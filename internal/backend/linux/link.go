//go:build linux

package linux

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"syscall"

	"github.com/TunnelHelper/TH/internal/core"
	"github.com/TunnelHelper/TH/internal/model"
	"github.com/vishvananda/netlink"
)

func ownershipAlias(id string) string {
	return "th:" + id
}

func (b *Backend) ensureLink(record model.Tunnel, desired netlink.Link, matches func(netlink.Link) bool) (netlink.Link, error) {
	existing, err := b.netlink.LinkByName(record.Interface)
	if err != nil && !isLinkNotFound(err) {
		return nil, fmt.Errorf("lookup link %s: %w", record.Interface, err)
	}
	if existing != nil {
		if existing.Attrs().Alias != ownershipAlias(record.ID) {
			return nil, fmt.Errorf("link %s exists with alias %q: %w", record.Interface, existing.Attrs().Alias, ErrOwnershipConflict)
		}
		if !matches(existing) {
			if err := b.netlink.LinkDel(existing); err != nil {
				return nil, fmt.Errorf("replace owned link %s: %w", record.Interface, err)
			}
			existing = nil
		}
	}
	if existing == nil {
		aliased, aliasErr := b.netlink.LinkByAlias(ownershipAlias(record.ID))
		if aliasErr == nil && aliased.Attrs().Name != record.Interface {
			return nil, fmt.Errorf("ownership alias is already attached to link %s: %w", aliased.Attrs().Name, ErrOwnershipConflict)
		}
		if aliasErr != nil && !isLinkNotFound(aliasErr) {
			return nil, fmt.Errorf("lookup ownership alias: %w", aliasErr)
		}
		if err := b.netlink.LinkAdd(desired); err != nil {
			return nil, fmt.Errorf("create link %s: %w", record.Interface, err)
		}
		existing, err = b.netlink.LinkByName(record.Interface)
		if err != nil {
			return nil, fmt.Errorf("reload created link %s: %w", record.Interface, err)
		}
	}
	if existing.Attrs().Alias != ownershipAlias(record.ID) {
		if err := b.netlink.LinkSetAlias(existing, ownershipAlias(record.ID)); err != nil {
			return nil, fmt.Errorf("set link ownership alias: %w", err)
		}
		existing, err = b.netlink.LinkByName(record.Interface)
		if err != nil {
			return nil, fmt.Errorf("reload link after setting ownership alias: %w", err)
		}
		if existing.Attrs().Alias != ownershipAlias(record.ID) {
			return nil, fmt.Errorf("link %s did not retain ownership alias: %w", record.Interface, ErrOwnershipConflict)
		}
	}
	return existing, nil
}

func (b *Backend) configureOwnedLink(record model.Tunnel, link netlink.Link, mtu int, addresses []netip.Prefix) error {
	if link.Attrs().Alias != ownershipAlias(record.ID) {
		return ErrOwnershipConflict
	}
	if link.Attrs().MTU != mtu {
		if err := b.netlink.LinkSetMTU(link, mtu); err != nil {
			return fmt.Errorf("set MTU on %s: %w", record.Interface, err)
		}
	}
	if err := b.reconcileAddresses(record, link, addresses); err != nil {
		return err
	}
	if link.Attrs().Flags&net.FlagUp == 0 {
		if err := b.netlink.LinkSetUp(link); err != nil {
			return fmt.Errorf("set link %s up: %w", record.Interface, err)
		}
	}
	return nil
}

func (b *Backend) reconcileAddresses(record model.Tunnel, link netlink.Link, desired []netip.Prefix) error {
	wanted := make(map[netip.Prefix]struct{}, len(desired)+1)
	for _, prefix := range desired {
		wanted[prefix] = struct{}{}
	}
	wanted[managedLinkLocalPrefix(record)] = struct{}{}
	current, err := b.netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("list addresses on %s: %w", link.Attrs().Name, err)
	}
	present := make(map[netip.Prefix]struct{}, len(current))
	for i := range current {
		prefix, ok := prefixFromIPNet(current[i].IPNet)
		if !ok {
			continue
		}
		if _, ok := wanted[prefix]; ok {
			present[prefix] = struct{}{}
			continue
		}
		if prefix.Addr().IsLinkLocalUnicast() {
			continue
		}
		if err := b.netlink.AddrDel(link, &current[i]); err != nil && !errors.Is(err, syscall.EADDRNOTAVAIL) {
			return fmt.Errorf("remove stale address %s from %s: %w", prefix, link.Attrs().Name, err)
		}
	}
	for prefix := range wanted {
		if _, ok := present[prefix]; ok {
			continue
		}
		addr := &netlink.Addr{IPNet: prefixToIPNet(prefix)}
		if err := b.netlink.AddrAdd(link, addr); err != nil && !errors.Is(err, syscall.EEXIST) {
			return fmt.Errorf("ensure address %s on %s: %w", prefix, link.Attrs().Name, err)
		}
	}
	return nil
}

func managedLinkLocalPrefix(record model.Tunnel) netip.Prefix {
	// WireGuard-style interfaces get their stable link-local address from
	// the tunnel's own public key. Every peer knows that public key, so it
	// can compute the address and form a unicast Babel adjacency without
	// any manual neighbour configuration.
	switch record.Kind {
	case model.KindWireGuard:
		if record.Spec.WireGuard != nil {
			if addr, ok := wgLinkLocal(record.Spec.WireGuard.PublicKey); ok {
				return netip.PrefixFrom(addr, 64)
			}
		}
	case model.KindAmneziaWG:
		if record.Spec.AmneziaWG != nil {
			if addr, ok := wgLinkLocal(record.Spec.AmneziaWG.PublicKey); ok {
				return netip.PrefixFrom(addr, 64)
			}
		}
	}
	digest := sha256.Sum256([]byte("th-link-local\x00" + record.ID))
	var address [16]byte
	address[0], address[1] = 0xfe, 0x80
	copy(address[8:], digest[:8])
	address[8] &^= 0x02
	return netip.PrefixFrom(netip.AddrFrom16(address), 64)
}

func (b *Backend) assertLinkOwnershipOrMissing(record model.Tunnel) error {
	if record.Interface == "" {
		return nil
	}
	link, err := b.netlink.LinkByName(record.Interface)
	if isLinkNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if link.Attrs().Alias != ownershipAlias(record.ID) {
		return fmt.Errorf("link %s has alias %q: %w", record.Interface, link.Attrs().Alias, ErrOwnershipConflict)
	}
	return nil
}

func (b *Backend) removeOwnedLink(record model.Tunnel) error {
	if record.Interface == "" {
		return nil
	}
	link, err := b.netlink.LinkByName(record.Interface)
	if isLinkNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("lookup link for removal: %w", err)
	}
	if link.Attrs().Alias != ownershipAlias(record.ID) {
		return fmt.Errorf("refuse to remove link %s with alias %q: %w", record.Interface, link.Attrs().Alias, ErrOwnershipConflict)
	}
	if err := b.netlink.LinkDel(link); err != nil && !isLinkNotFound(err) {
		return fmt.Errorf("remove link %s: %w", record.Interface, err)
	}
	return nil
}

func (b *Backend) observeLink(record model.Tunnel) (core.Observation, error) {
	link, err := b.netlink.LinkByName(record.Interface)
	if isLinkNotFound(err) {
		return core.Observation{}, nil
	}
	if err != nil {
		return core.Observation{}, err
	}
	if link.Attrs().Alias != ownershipAlias(record.ID) {
		return observationFromLink(link), ErrOwnershipConflict
	}
	observation := observationFromLink(link)
	managedLinkLocal := managedLinkLocalPrefix(record)
	addresses, err := b.netlink.AddrList(link, netlink.FAMILY_V6)
	if err != nil {
		return observation, fmt.Errorf("list IPv6 addresses on %s: %w", record.Interface, err)
	}
	for _, address := range addresses {
		prefix, ok := prefixFromIPNet(address.IPNet)
		if ok && prefix == managedLinkLocal {
			observation.Details["ipv6_link_local"] = managedLinkLocal.String()
			return observation, nil
		}
	}
	return observation, fmt.Errorf("managed IPv6 link-local address %s is missing from %s", managedLinkLocal, record.Interface)
}

func isLinkNotFound(err error) bool {
	if err == nil {
		return false
	}
	var notFound netlink.LinkNotFoundError
	return errors.As(err, &notFound) || errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENODEV)
}

func prefixToIPNet(prefix netip.Prefix) *net.IPNet {
	addr := prefix.Addr()
	bits := 128
	if addr.Is4() {
		bits = 32
	}
	return &net.IPNet{IP: net.IP(addr.AsSlice()), Mask: net.CIDRMask(prefix.Bits(), bits)}
}

func prefixFromIPNet(network *net.IPNet) (netip.Prefix, bool) {
	if network == nil {
		return netip.Prefix{}, false
	}
	addr, ok := netip.AddrFromSlice(network.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	ones, bits := network.Mask.Size()
	if ones < 0 || (bits != 32 && bits != 128) {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(addr.Unmap(), ones), true
}

func ipFromAddr(addr netip.Addr) net.IP {
	return net.IP(addr.AsSlice())
}
