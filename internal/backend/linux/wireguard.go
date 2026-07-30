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
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func (b *Backend) applyWireGuard(ctx context.Context, record model.Tunnel) (core.Observation, error) {
	if err := ctx.Err(); err != nil {
		return core.Observation{}, err
	}
	client, err := b.wg.kernelClient(ctx)
	if err != nil {
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
	configuration, err := b.wireGuardConfiguration(ctx, client, record, spec)
	if err != nil {
		return observationFromLink(link), err
	}
	if wireGuardConfigurationChanges(configuration) {
		if err := client.ConfigureDevice(record.Interface, configuration); err != nil {
			return observationFromLink(link), fmt.Errorf("configure WireGuard device: %w", err)
		}
	}
	if err := b.configureOwnedLink(record, link, spec.MTU, spec.Addresses); err != nil {
		return observationFromLink(link), err
	}
	if err := b.reconcileWireGuardRoutes(record, spec, link); err != nil {
		return observationFromLink(link), err
	}
	return b.observeWireGuardWithClient(record, client)
}

func (b *Backend) wireGuardConfiguration(ctx context.Context, client *wgctrl.Client, record model.Tunnel, spec *model.WireGuardSpec) (wgtypes.Config, error) {
	current, err := client.Device(record.Interface)
	if err != nil {
		return wgtypes.Config{}, fmt.Errorf("read WireGuard device before configuration: %w", err)
	}
	return buildWireGuardConfiguration(ctx, record, spec, current)
}

func buildWireGuardConfiguration(ctx context.Context, record model.Tunnel, spec *model.WireGuardSpec, current *wgtypes.Device) (wgtypes.Config, error) {
	privateKey, err := wgtypes.ParseKey(spec.PrivateKey)
	if err != nil {
		return wgtypes.Config{}, err
	}
	firewallMark := effectiveFirewallMark(record, spec)
	configuration := wgtypes.Config{Peers: make([]wgtypes.PeerConfig, 0, len(spec.Peers)+len(current.Peers))}
	if current.PrivateKey != privateKey {
		configuration.PrivateKey = &privateKey
	}
	if spec.ListenPort != 0 {
		if current.ListenPort != spec.ListenPort {
			listenPort := spec.ListenPort
			configuration.ListenPort = &listenPort
		}
	} else if current.ListenPort == 0 {
		listenPort := 0
		configuration.ListenPort = &listenPort
	}
	if current.FirewallMark != firewallMark {
		configuration.FirewallMark = &firewallMark
	}

	currentPeers := make(map[wgtypes.Key]wgtypes.Peer, len(current.Peers))
	for _, peer := range current.Peers {
		currentPeers[peer.PublicKey] = peer
	}
	for _, peer := range spec.Peers {
		peerConfig, err := buildWireGuardPeerConfiguration(ctx, peer)
		if err != nil {
			return wgtypes.Config{}, err
		}
		currentPeer, exists := currentPeers[peerConfig.PublicKey]
		if !exists || !wireGuardPeerConfigurationMatches(currentPeer, peerConfig) {
			peerConfig.UpdateOnly = exists
			configuration.Peers = append(configuration.Peers, peerConfig)
		}
		delete(currentPeers, peerConfig.PublicKey)
	}
	for publicKey := range currentPeers {
		configuration.Peers = append(configuration.Peers, wgtypes.PeerConfig{PublicKey: publicKey, Remove: true})
	}
	return configuration, nil
}

func buildWireGuardPeerConfiguration(ctx context.Context, peer model.WireGuardPeer) (wgtypes.PeerConfig, error) {
	publicKey, err := wgtypes.ParseKey(peer.PublicKey)
	if err != nil {
		return wgtypes.PeerConfig{}, err
	}
	keepalive := time.Duration(peer.Keepalive) * time.Second
	presharedKey := wgtypes.Key{}
	if peer.PresharedKey != "" {
		presharedKey, err = wgtypes.ParseKey(peer.PresharedKey)
		if err != nil {
			return wgtypes.PeerConfig{}, err
		}
	}
	configuration := wgtypes.PeerConfig{
		PublicKey:                   publicKey,
		PresharedKey:                &presharedKey,
		ReplaceAllowedIPs:           true,
		PersistentKeepaliveInterval: &keepalive,
		AllowedIPs:                  make([]net.IPNet, 0, len(peer.AllowedIPs)),
	}
	if peer.Endpoint != "" {
		endpoint, err := resolveEndpoint(ctx, peer.Endpoint)
		if err != nil {
			return wgtypes.PeerConfig{}, fmt.Errorf("resolve endpoint %q: %w", peer.Endpoint, err)
		}
		configuration.Endpoint = endpoint
	}
	for _, prefix := range peer.AllowedIPs {
		configuration.AllowedIPs = append(configuration.AllowedIPs, *prefixToIPNet(prefix.Masked()))
	}
	return configuration, nil
}

func wireGuardConfigurationChanges(configuration wgtypes.Config) bool {
	return configuration.PrivateKey != nil || configuration.ListenPort != nil || configuration.FirewallMark != nil || len(configuration.Peers) != 0
}

func wireGuardPeerConfigurationMatches(current wgtypes.Peer, desired wgtypes.PeerConfig) bool {
	if desired.PresharedKey == nil || current.PresharedKey != *desired.PresharedKey {
		return false
	}
	if desired.PersistentKeepaliveInterval == nil || current.PersistentKeepaliveInterval != *desired.PersistentKeepaliveInterval {
		return false
	}
	if desired.Endpoint != nil && !equalUDPEndpoint(current.Endpoint, desired.Endpoint) {
		return false
	}
	return equalIPNetworks(current.AllowedIPs, desired.AllowedIPs)
}

func equalUDPEndpoint(a, b *net.UDPAddr) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Port == b.Port && a.Zone == b.Zone && a.IP.Equal(b.IP)
}

func equalIPNetworks(a, b []net.IPNet) bool {
	if len(a) != len(b) {
		return false
	}
	values := make(map[string]int, len(a))
	for _, prefix := range a {
		values[prefix.String()]++
	}
	for _, prefix := range b {
		key := prefix.String()
		if values[key] == 0 {
			return false
		}
		values[key]--
	}
	return true
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

func (b *Backend) observeWireGuard(ctx context.Context, record model.Tunnel) (core.Observation, error) {
	observation, err := b.observeLink(record)
	if err != nil || !observation.InterfaceExists {
		return observation, err
	}
	if observation.Details["link_type"] != "wireguard" {
		return observation, fmt.Errorf("link %s has type %q, not kernel WireGuard", record.Interface, observation.Details["link_type"])
	}
	client, err := b.wg.kernelClient(ctx)
	if err != nil {
		return observation, err
	}
	return b.observeWireGuardDevice(observation, record, client)
}

func (b *Backend) observeWireGuardWithClient(record model.Tunnel, client *wgctrl.Client) (core.Observation, error) {
	observation, err := b.observeLink(record)
	if err != nil || !observation.InterfaceExists {
		return observation, err
	}
	if observation.Details["link_type"] != "wireguard" {
		return observation, fmt.Errorf("link %s has type %q, not kernel WireGuard", record.Interface, observation.Details["link_type"])
	}
	return b.observeWireGuardDevice(observation, record, client)
}

func (b *Backend) observeWireGuardDevice(observation core.Observation, record model.Tunnel, client *wgctrl.Client) (core.Observation, error) {
	device, err := client.Device(record.Interface)
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
	observation.Details["counter_source"] = "wireguard"
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
				Realm:     model.ManagedRouteRealm(record),
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
	expected := make(map[string]netlink.Route)
	for _, claim := range model.ManagedRouteClaims(record) {
		route := netlink.Route{Table: claim.Table, Dst: prefixToIPNet(claim.Prefix)}
		expected[managedRouteKey(route)] = route
	}
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		routes, err := b.listRoutesForLinkTable(link, family, table)
		if err != nil {
			return fmt.Errorf("list managed routes: %w", err)
		}
		for i := range routes {
			if !routeOwnedByRecord(record, routes[i]) && !legacyExpectedRoute(routes[i], expected) {
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
	if err := b.assertManagedRouteClaimsAvailable(record, link, desired); err != nil {
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
			owned := routeOwnedByRecord(record, routes[i])
			legacy := expected && legacyExpectedRoute(routes[i], desired)
			if !owned && !legacy {
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

func (b *Backend) assertManagedRouteClaimsAvailable(record model.Tunnel, link netlink.Link, desired map[string]netlink.Route) error {
	type tableFamily struct {
		table  int
		family int
	}
	cache := make(map[tableFamily]map[string][]netlink.Route)
	for key, route := range desired {
		family := netlink.FAMILY_V6
		if route.Dst != nil && route.Dst.IP.To4() != nil {
			family = netlink.FAMILY_V4
		}
		query := tableFamily{table: route.Table, family: family}
		routesByKey, ok := cache[query]
		if !ok {
			routes, err := b.netlink.RouteListFiltered(family, &netlink.Route{Table: route.Table}, netlink.RT_FILTER_TABLE)
			if err != nil {
				return fmt.Errorf("list route table %d: %w", route.Table, err)
			}
			routesByKey = make(map[string][]netlink.Route, len(routes))
			for _, existing := range routes {
				existingKey := managedRouteKey(existing)
				routesByKey[existingKey] = append(routesByKey[existingKey], existing)
			}
			cache[query] = routesByKey
		}
		for _, existing := range routesByKey[key] {
			legacy := existing.Protocol == managedRouteProtocol && existing.Realm == 0
			if existing.LinkIndex != link.Attrs().Index || (!routeOwnedByRecord(record, existing) && !legacy) {
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
		a.Realm == b.Realm && a.Scope == b.Scope && a.Priority == b.Priority
}
