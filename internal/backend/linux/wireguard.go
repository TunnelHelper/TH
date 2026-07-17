//go:build linux

package linux

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"time"

	"github.com/TunnelHelper/TH/internal/core"
	"github.com/TunnelHelper/TH/internal/model"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func (b *Backend) applyWireGuard(ctx context.Context, record model.Tunnel) (core.Observation, error) {
	if b.wgErr != nil {
		return core.Observation{}, fmt.Errorf("open WireGuard generic netlink: %w", b.wgErr)
	}
	if err := ctx.Err(); err != nil {
		return core.Observation{}, err
	}
	spec := record.Spec.WireGuard
	desired := &netlink.GenericLink{
		LinkAttrs: netlink.LinkAttrs{Name: record.Interface, MTU: spec.MTU, Alias: ownershipAlias(record.ID)},
		LinkType:  "wireguard",
	}
	link, err := b.ensureLink(record, desired, func(existing netlink.Link) bool {
		return existing.Type() == "wireguard"
	})
	if err != nil {
		return core.Observation{}, err
	}
	configuration, err := b.wireGuardConfiguration(ctx, record, spec)
	if err != nil {
		return observationFromLink(link), err
	}
	if err := b.wg.ConfigureDevice(record.Interface, configuration); err != nil {
		return observationFromLink(link), fmt.Errorf("configure WireGuard device: %w", err)
	}
	if err := b.configureOwnedLink(record, link, spec.MTU, spec.Addresses); err != nil {
		return observationFromLink(link), err
	}
	if err := b.reconcileWireGuardRoutes(record, spec, link); err != nil {
		return observationFromLink(link), err
	}
	return b.observeWireGuard(record)
}

func (b *Backend) wireGuardConfiguration(ctx context.Context, record model.Tunnel, spec *model.WireGuardSpec) (wgtypes.Config, error) {
	privateKey, err := wgtypes.ParseKey(spec.PrivateKey)
	if err != nil {
		return wgtypes.Config{}, err
	}
	listenPort := spec.ListenPort
	firewallMark := effectiveFirewallMark(record, spec)
	configuration := wgtypes.Config{
		PrivateKey:   &privateKey,
		ListenPort:   &listenPort,
		FirewallMark: &firewallMark,
		ReplacePeers: true,
		Peers:        make([]wgtypes.PeerConfig, 0, len(spec.Peers)),
	}
	for _, peer := range spec.Peers {
		publicKey, err := wgtypes.ParseKey(peer.PublicKey)
		if err != nil {
			return wgtypes.Config{}, err
		}
		keepalive := time.Duration(peer.Keepalive) * time.Second
		peerConfig := wgtypes.PeerConfig{
			PublicKey:                   publicKey,
			ReplaceAllowedIPs:           true,
			PersistentKeepaliveInterval: &keepalive,
			AllowedIPs:                  make([]net.IPNet, 0, len(peer.AllowedIPs)),
		}
		if peer.PresharedKey != "" {
			key, err := wgtypes.ParseKey(peer.PresharedKey)
			if err != nil {
				return wgtypes.Config{}, err
			}
			peerConfig.PresharedKey = &key
		}
		if peer.Endpoint != "" {
			endpoint, err := resolveEndpoint(ctx, peer.Endpoint)
			if err != nil {
				return wgtypes.Config{}, fmt.Errorf("resolve endpoint %q: %w", peer.Endpoint, err)
			}
			peerConfig.Endpoint = endpoint
		}
		for _, prefix := range peer.AllowedIPs {
			peerConfig.AllowedIPs = append(peerConfig.AllowedIPs, *prefixToIPNet(prefix.Masked()))
		}
		configuration.Peers = append(configuration.Peers, peerConfig)
	}
	return configuration, nil
}

func resolveEndpoint(ctx context.Context, endpoint string) (*net.UDPAddr, error) {
	host, portText, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return nil, err
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return &net.UDPAddr{IP: net.IP(addr.AsSlice()), Port: port, Zone: addr.Zone()}, nil
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	if len(addresses) == 0 {
		return nil, errors.New("hostname resolved without addresses")
	}
	return &net.UDPAddr{IP: net.IP(addresses[0].AsSlice()), Port: port}, nil
}

func (b *Backend) observeWireGuard(record model.Tunnel) (core.Observation, error) {
	observation, err := b.observeLink(record)
	if err != nil || !observation.InterfaceExists || b.wgErr != nil {
		return observation, err
	}
	device, err := b.wg.Device(record.Interface)
	if err != nil {
		return observation, fmt.Errorf("read WireGuard device: %w", err)
	}
	if observation.Details == nil {
		observation.Details = make(map[string]string)
	}
	observation.Details["public_key"] = device.PublicKey.String()
	observation.Details["listen_port"] = strconv.Itoa(device.ListenPort)
	observation.Details["peers"] = strconv.Itoa(len(device.Peers))
	var rx, tx int64
	var latest time.Time
	for _, peer := range device.Peers {
		rx += peer.ReceiveBytes
		tx += peer.TransmitBytes
		if peer.LastHandshakeTime.After(latest) {
			latest = peer.LastHandshakeTime
		}
	}
	observation.Details["receive_bytes"] = strconv.FormatInt(rx, 10)
	observation.Details["transmit_bytes"] = strconv.FormatInt(tx, 10)
	observation.Peers = wireGuardPeerStatuses(device.Peers)
	if !latest.IsZero() {
		observation.Details["latest_handshake"] = latest.UTC().Format(time.RFC3339)
	}
	return observation, nil
}

func wireGuardPeerStatuses(peers []wgtypes.Peer) []model.PeerStatus {
	statuses := make([]model.PeerStatus, 0, len(peers))
	for _, peer := range peers {
		status := model.PeerStatus{
			PublicKey:        peer.PublicKey.String(),
			KeepaliveSeconds: int(peer.PersistentKeepaliveInterval / time.Second),
			ReceiveBytes:     peer.ReceiveBytes,
			TransmitBytes:    peer.TransmitBytes,
			AllowedIPs:       make([]string, 0, len(peer.AllowedIPs)),
		}
		if peer.Endpoint != nil {
			status.Endpoint = peer.Endpoint.String()
		}
		if !peer.LastHandshakeTime.IsZero() {
			handshake := peer.LastHandshakeTime.UTC()
			status.LastHandshakeTime = &handshake
		}
		for _, prefix := range peer.AllowedIPs {
			status.AllowedIPs = append(status.AllowedIPs, prefix.String())
		}
		statuses = append(statuses, status)
	}
	return statuses
}

func effectiveRouteTable(record model.Tunnel, spec *model.WireGuardSpec) int {
	return model.WireGuardRouteTable(record, spec)
}

func effectiveFirewallMark(record model.Tunnel, spec *model.WireGuardSpec) int {
	if spec.FirewallMark != 0 {
		return spec.FirewallMark
	}
	if spec.RouteAllowedIPs && hasDefaultAllowedIP(spec) {
		return effectiveRouteTable(record, spec)
	}
	return 0
}

func hasDefaultAllowedIP(spec *model.WireGuardSpec) bool {
	for _, peer := range spec.Peers {
		for _, prefix := range peer.AllowedIPs {
			if prefix.Bits() == 0 {
				return true
			}
		}
	}
	return false
}

func (b *Backend) reconcileWireGuardRoutes(record model.Tunnel, spec *model.WireGuardSpec, link netlink.Link) error {
	if !spec.RouteAllowedIPs {
		return errors.Join(b.removeManagedRoutes(record, link), b.removeManagedRules(record))
	}
	table := effectiveRouteTable(record, spec)
	familiesWithDefault := make(map[int]bool)
	seen := make(map[netip.Prefix]struct{})
	desired := make(map[string]netlink.Route)
	for _, peer := range spec.Peers {
		for _, prefix := range peer.AllowedIPs {
			prefix = prefix.Masked()
			if _, ok := seen[prefix]; ok {
				continue
			}
			seen[prefix] = struct{}{}
			family := netlink.FAMILY_V6
			if prefix.Addr().Is4() {
				family = netlink.FAMILY_V4
			}
			if prefix.Bits() == 0 {
				familiesWithDefault[family] = true
			}
			route := netlink.Route{
				LinkIndex: link.Attrs().Index,
				Dst:       prefixToIPNet(prefix),
				Table:     table,
				Protocol:  managedRouteProtocol,
				Scope:     netlink.SCOPE_LINK,
			}
			desired[managedRouteKey(route)] = route
		}
	}
	if err := b.reconcileManagedRoutes(record, link, desired); err != nil {
		return err
	}
	return b.reconcileWireGuardRules(record, familiesWithDefault, table, uint32(effectiveFirewallMark(record, spec)))
}

func (b *Backend) removeWireGuardRoutes(record model.Tunnel) error {
	if record.Interface == "" {
		return nil
	}
	link, err := b.netlink.LinkByName(record.Interface)
	if isLinkNotFound(err) {
		return b.removeManagedRules(record)
	}
	if err != nil {
		return err
	}
	if link.Attrs().Alias != ownershipAlias(record.ID) {
		return ErrOwnershipConflict
	}
	return errors.Join(b.removeManagedRoutes(record, link), b.removeManagedRules(record))
}

func (b *Backend) removeManagedRoutes(record model.Tunnel, link netlink.Link) error {
	if link.Attrs().Alias != ownershipAlias(record.ID) {
		return ErrOwnershipConflict
	}
	table, err := managedWireGuardRouteTable(record)
	if err != nil {
		return err
	}
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		routes, err := b.listRoutesForLinkTable(link, family, table)
		if err != nil {
			return fmt.Errorf("list managed routes: %w", err)
		}
		for i := range routes {
			if routes[i].Protocol != managedRouteProtocol {
				continue
			}
			if err := b.netlink.RouteDel(&routes[i]); err != nil && !errors.Is(err, syscall.ESRCH) {
				return fmt.Errorf("remove managed route: %w", err)
			}
		}
	}
	return nil
}

func (b *Backend) reconcileManagedRoutes(record model.Tunnel, link netlink.Link, desired map[string]netlink.Route) error {
	if link.Attrs().Alias != ownershipAlias(record.ID) {
		return ErrOwnershipConflict
	}
	if err := b.assertManagedRouteClaimsAvailable(link, desired); err != nil {
		return err
	}
	present := make(map[string]struct{}, len(desired))
	table, err := managedWireGuardRouteTable(record)
	if err != nil {
		return err
	}
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		routes, err := b.listRoutesForLinkTable(link, family, table)
		if err != nil {
			return fmt.Errorf("list managed routes: %w", err)
		}
		for i := range routes {
			key := managedRouteKey(routes[i])
			want, expected := desired[key]
			if routes[i].Protocol != managedRouteProtocol {
				if expected {
					return fmt.Errorf("route %s is not owned by TH: %w", key, ErrOwnershipConflict)
				}
				continue
			}
			if expected && equalWireGuardRoute(routes[i], want) {
				present[key] = struct{}{}
				continue
			}
			if err := b.netlink.RouteDel(&routes[i]); err != nil && !errors.Is(err, syscall.ESRCH) {
				return fmt.Errorf("remove stale managed route: %w", err)
			}
		}
	}
	for key, route := range desired {
		if _, ok := present[key]; ok {
			continue
		}
		route := route
		if err := b.netlink.RouteAdd(&route); err != nil {
			if errors.Is(err, syscall.EEXIST) {
				return fmt.Errorf("route %s appeared during reconciliation: %w", key, ErrOwnershipConflict)
			}
			return fmt.Errorf("add WireGuard route %s: %w", key, err)
		}
	}
	return nil
}

func managedWireGuardRouteTable(record model.Tunnel) (int, error) {
	var spec *model.WireGuardSpec
	switch record.Kind {
	case model.KindWireGuard:
		spec = record.Spec.WireGuard
	case model.KindAmneziaWG:
		if record.Spec.AmneziaWG != nil {
			spec = &record.Spec.AmneziaWG.WireGuardSpec
		}
	}
	if spec == nil {
		return 0, fmt.Errorf("record %s has no WireGuard route specification", record.ID)
	}
	return effectiveRouteTable(record, spec), nil
}

func (b *Backend) listRoutesForLinkTable(link netlink.Link, family, table int) ([]netlink.Route, error) {
	filter := &netlink.Route{LinkIndex: link.Attrs().Index, Table: table}
	return b.netlink.RouteListFiltered(family, filter, netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE)
}

func (b *Backend) assertManagedRouteClaimsAvailable(link netlink.Link, desired map[string]netlink.Route) error {
	type tableFamily struct {
		table  int
		family int
	}
	cache := make(map[tableFamily][]netlink.Route)
	for key, route := range desired {
		family := netlink.FAMILY_V6
		if route.Dst != nil && route.Dst.IP.To4() != nil {
			family = netlink.FAMILY_V4
		}
		query := tableFamily{table: route.Table, family: family}
		routes, ok := cache[query]
		if !ok {
			var err error
			routes, err = b.netlink.RouteListFiltered(family, &netlink.Route{Table: route.Table}, netlink.RT_FILTER_TABLE)
			if err != nil {
				return fmt.Errorf("list route table %d: %w", route.Table, err)
			}
			cache[query] = routes
		}
		for _, existing := range routes {
			if managedRouteKey(existing) != key {
				continue
			}
			if existing.Protocol != managedRouteProtocol || existing.LinkIndex != link.Attrs().Index {
				return fmt.Errorf("route %s is already owned by another source: %w", key, ErrOwnershipConflict)
			}
		}
	}
	return nil
}

func managedRouteKey(route netlink.Route) string {
	return fmt.Sprintf("%d|%s", route.Table, routeDestinationKey(route))
}

func routeDestinationKey(route netlink.Route) string {
	if route.Dst != nil {
		return route.Dst.String()
	}
	if route.Family == netlink.FAMILY_V4 {
		return "0.0.0.0/0"
	}
	if route.Family == netlink.FAMILY_V6 {
		return "::/0"
	}
	return "default"
}

func equalWireGuardRoute(a, b netlink.Route) bool {
	return managedRouteKey(a) == managedRouteKey(b) && a.LinkIndex == b.LinkIndex && a.Protocol == b.Protocol &&
		a.Scope == b.Scope && a.Priority == b.Priority
}

func rulePriorities(record model.Tunnel) (int, int) {
	priorities := model.ManagedRulePriorities(record)
	if len(priorities) != 2 {
		return 0, 0
	}
	return priorities[0], priorities[1]
}

func desiredWireGuardRules(record model.Tunnel, family, table int, mark uint32) []*netlink.Rule {
	suppressPriority, markPriority := rulePriorities(record)
	suppress := netlink.NewRule()
	suppress.Family = family
	suppress.Priority = suppressPriority
	suppress.Table = unix.RT_TABLE_MAIN
	suppress.SuppressPrefixlen = 0
	suppress.Protocol = managedRouteProtocol
	mask := uint32(0xffffffff)
	marked := netlink.NewRule()
	marked.Family = family
	marked.Priority = markPriority
	marked.Table = table
	marked.Mark = mark
	marked.Mask = &mask
	marked.Invert = true
	marked.Protocol = managedRouteProtocol
	return []*netlink.Rule{suppress, marked}
}

func (b *Backend) reconcileWireGuardRules(record model.Tunnel, families map[int]bool, table int, mark uint32) error {
	suppressPriority, markPriority := rulePriorities(record)
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		expected := make(map[int]*netlink.Rule)
		if families[family] {
			for _, rule := range desiredWireGuardRules(record, family, table, mark) {
				expected[rule.Priority] = rule
			}
		}
		rules, err := b.netlink.RuleList(family)
		if err != nil {
			return fmt.Errorf("list policy rules: %w", err)
		}
		present := make(map[int]struct{}, len(expected))
		for i := range rules {
			if rules[i].Priority != suppressPriority && rules[i].Priority != markPriority {
				continue
			}
			want, needed := expected[rules[i].Priority]
			if rules[i].Protocol != managedRouteProtocol {
				return fmt.Errorf("policy-rule priority %d is not owned by TH: %w", rules[i].Priority, ErrOwnershipConflict)
			}
			if needed && equalManagedRule(&rules[i], want) {
				present[rules[i].Priority] = struct{}{}
				continue
			}
			if err := b.netlink.RuleDel(&rules[i]); err != nil && !errors.Is(err, syscall.ENOENT) {
				return fmt.Errorf("remove stale policy rule: %w", err)
			}
		}
		for priority, rule := range expected {
			if _, ok := present[priority]; ok {
				continue
			}
			if err := b.netlink.RuleAdd(rule); err != nil && !errors.Is(err, syscall.EEXIST) {
				return fmt.Errorf("ensure WireGuard policy rule: %w", err)
			}
		}
	}
	return nil
}

func equalManagedRule(a, b *netlink.Rule) bool {
	if a.Priority != b.Priority || a.Family != b.Family || a.Table != b.Table ||
		a.Mark != b.Mark || a.Invert != b.Invert || a.SuppressPrefixlen != b.SuppressPrefixlen ||
		a.Protocol != b.Protocol {
		return false
	}
	if a.Mask == nil || b.Mask == nil {
		return a.Mask == nil && b.Mask == nil
	}
	return *a.Mask == *b.Mask
}

func (b *Backend) removeManagedRules(record model.Tunnel) error {
	suppressPriority, markPriority := rulePriorities(record)
	if suppressPriority == 0 {
		return nil
	}
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		rules, err := b.netlink.RuleList(family)
		if err != nil {
			return fmt.Errorf("list policy rules: %w", err)
		}
		for i := range rules {
			if rules[i].Protocol != managedRouteProtocol || (rules[i].Priority != suppressPriority && rules[i].Priority != markPriority) {
				continue
			}
			if err := b.netlink.RuleDel(&rules[i]); err != nil && !errors.Is(err, syscall.ENOENT) {
				return fmt.Errorf("remove managed policy rule: %w", err)
			}
		}
	}
	return nil
}
