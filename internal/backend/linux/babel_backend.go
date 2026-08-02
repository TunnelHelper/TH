//go:build linux

package linux

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/TunnelHelper/TH/internal/babel"
	"github.com/TunnelHelper/TH/internal/core"
	"github.com/TunnelHelper/TH/internal/model"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const babelRoutePriority = 1

type babelInstance struct {
	record     model.Tunnel
	speaker    *babel.Speaker
	table      int
	generation uint64
}

type babelRegistry struct {
	mu        sync.Mutex
	instances map[string]*babelInstance
}

func newBabelRegistry() *babelRegistry {
	return &babelRegistry{instances: make(map[string]*babelInstance)}
}

// babelHandler receives protocol events from the Babel speaker and turns
// them into backend events that drive reconciliation.
type babelHandler struct {
	backend  *Backend
	recordID string
	table    int
}

// babelMultipathWeight maps route metrics to kernel next-hop weights.
// Equal-cost candidates get equal weights; a cheaper (lower-metric)
// candidate gets proportionally more of the traffic.
func babelMultipathWeight(primary, candidate uint16) int {
	if primary == 0 || candidate <= primary {
		return 256
	}
	weight := 256 * int(primary) / int(candidate)
	if weight < 1 {
		return 1
	}
	return weight
}

func (h babelHandler) RoutesChanged() {
	h.emit(core.BackendEventRoute)
}

func (h babelHandler) NeighbourAdded(*babel.Neighbour) {
	h.emit(core.BackendEventLink)
}

func (h babelHandler) NeighbourRemoved(*babel.Neighbour) {
	h.emit(core.BackendEventLink)
}

func (h babelHandler) emit(eventType core.BackendEventType) {
	select {
	case h.backend.events <- core.BackendEvent{Type: eventType, RecordID: h.recordID, RouteTable: h.table}:
	default:
	}
}

func (b *Backend) applyBabel(ctx context.Context, record model.Tunnel) (core.Observation, error) {
	if err := ctx.Err(); err != nil {
		return core.Observation{}, err
	}
	spec := record.Spec.Babel
	if spec == nil {
		return core.Observation{}, errors.New("babel spec is required")
	}

	routerID, err := parseBabelRouterID(spec.RouterID)
	if err != nil {
		return core.Observation{}, err
	}
	table := model.BabelRouteTable(record)

	b.babel.mu.Lock()
	instance, exists := b.babel.instances[record.ID]
	if exists && instance.generation != record.Generation {
		instance.speaker.Close()
		delete(b.babel.instances, record.ID)
		exists = false
	}
	if !exists {
		instance, err = b.startBabel(record, routerID, table)
		if err != nil {
			b.babel.mu.Unlock()
			return core.Observation{}, err
		}
		b.babel.instances[record.ID] = instance
	}
	speaker := instance.speaker
	b.babel.mu.Unlock()

	for _, pfx := range spec.AdvertisedPrefixes {
		if err := speaker.Advertise(pfx, babel.LocalRouteMetric); err != nil {
			return core.Observation{}, fmt.Errorf("advertise %s: %w", pfx, err)
		}
	}
	if err := b.reconcileBabelRoutes(record, speaker.SelectedRoutes()); err != nil {
		return core.Observation{}, err
	}
	return b.observeBabel(record)
}

func (b *Backend) startBabel(record model.Tunnel, routerID [8]byte, table int) (*babelInstance, error) {
	spec := record.Spec.Babel
	params := babel.DefaultParameters
	params.UnicastHelloInterval = time.Duration(spec.UnicastHelloSeconds) * time.Second
	params.MaxPaths = spec.MaxPaths
	params.MultipathSlack = uint16(spec.MultipathSlack)
	params.SplitHorizon = spec.SplitHorizon == nil || *spec.SplitHorizon

	wanted := make(map[string]struct{}, len(spec.Interfaces))
	for _, name := range spec.Interfaces {
		wanted[name] = struct{}{}
	}

	static := make(map[string][]netip.Addr, len(spec.StaticNeighbours))
	for name, addrs := range spec.StaticNeighbours {
		normalised := make([]netip.Addr, 0, len(addrs))
		for _, addr := range addrs {
			normalised = append(normalised, normalizeBabelAddress(addr))
		}
		static[name] = normalised
	}

	handler := babelHandler{backend: b, recordID: record.ID, table: table}
	cfg := &babel.SpeakerConfig{
		Parameters: &params,
		RouterID:   routerID,
		InterfaceFilter: func(name string) bool {
			_, ok := wanted[name]
			return ok
		},
		StaticNeighbours: static,
		StrictNeighbours: spec.StrictNeighbours,
		Multicast:        spec.Multicast,
		Handler:          handler,
		Logger:           slog.Default(),
	}

	speaker, err := babel.NewSpeaker(cfg)
	if err != nil {
		return nil, fmt.Errorf("start Babel speaker: %w", err)
	}
	return &babelInstance{
		record:     record,
		speaker:    speaker,
		table:      table,
		generation: record.Generation,
	}, nil
}

func (b *Backend) removeBabel(record model.Tunnel) (core.Observation, error) {
	b.babel.mu.Lock()
	if instance, ok := b.babel.instances[record.ID]; ok {
		instance.speaker.Close()
		delete(b.babel.instances, record.ID)
	}
	b.babel.mu.Unlock()

	if err := b.removeOwnedBabelRoutes(record); err != nil {
		return core.Observation{}, err
	}
	return core.Observation{}, nil
}

func (b *Backend) observeBabel(record model.Tunnel) (core.Observation, error) {
	b.babel.mu.Lock()
	instance, ok := b.babel.instances[record.ID]
	b.babel.mu.Unlock()
	if !ok {
		return core.Observation{}, nil
	}

	speaker := instance.speaker
	selected := speaker.SelectedRoutes()
	details := map[string]string{
		"router_id":       record.Spec.Babel.RouterID,
		"selected_routes": strconv.Itoa(len(selected)),
		"route_table":     strconv.Itoa(instance.table),
	}
	peers := make([]model.PeerStatus, 0)
	_ = speaker.Interfaces.Foreach(func(_ int, iface *babel.Interface) error {
		count := 0
		_ = iface.Neighbours.Foreach(func(n *babel.Neighbour) error {
			count++
			peers = append(peers, model.PeerStatus{
				PublicKey: n.Address.String(),
				Endpoint:  iface.Name,
			})
			return nil
		})
		details["neighbours_"+iface.Name] = strconv.Itoa(count)
		return nil
	})
	return core.Observation{
		InterfaceExists: true,
		InterfaceUp:     true,
		Details:         details,
		Peers:           peers,
	}, nil
}

// babelRoutesToNetlink converts the speaker's selected routes into netlink
// routes, grouping multipath candidates per destination prefix. Weights are
// derived from the route metrics so faster (lower-cost) links carry more
// of the traffic.
type babelLinkResolver func(name string) (int, error)

func (b *Backend) resolveBabelLink(name string) (int, error) {
	link, err := b.netlink.LinkByName(name)
	if err != nil {
		return 0, fmt.Errorf("lookup Babel next-hop interface %s: %w", name, err)
	}
	return link.Attrs().Index, nil
}

func babelRoutesToNetlink(record model.Tunnel, table int, selected []babel.SelectedRoute, resolve babelLinkResolver) ([]netlink.Route, error) {
	byPrefix := make(map[netip.Prefix][]babel.SelectedRoute)
	for _, route := range selected {
		if route.Local {
			continue
		}
		prefix := route.Prefix.Masked()
		byPrefix[prefix] = append(byPrefix[prefix], route)
	}

	realm := model.ManagedRouteRealm(record)
	result := make([]netlink.Route, 0, len(byPrefix))
	for prefix, candidates := range byPrefix {
		sort.SliceStable(candidates, func(i, j int) bool {
			if candidates[i].Metric != candidates[j].Metric {
				return candidates[i].Metric < candidates[j].Metric
			}
			return candidates[i].NextHop.Compare(candidates[j].NextHop) < 0
		})
		base := netlink.Route{
			Dst:      prefixToIPNet(prefix),
			Table:    table,
			Protocol: managedRouteProtocol,
			Realm:    realm,
			Scope:    netlink.SCOPE_UNIVERSE,
			Priority: babelRoutePriority,
		}
		if len(candidates) == 1 {
			linkIndex, gw, err := babelNextHop(resolve, candidates[0])
			if err != nil {
				return nil, err
			}
			base.LinkIndex = linkIndex
			base.Gw = gw
			result = append(result, base)
			continue
		}
		for _, candidate := range candidates {
			linkIndex, gw, err := babelNextHop(resolve, candidate)
			if err != nil {
				return nil, err
			}
			weight := babelMultipathWeight(candidates[0].Metric, candidate.Metric)
			base.MultiPath = append(base.MultiPath, &netlink.NexthopInfo{
				LinkIndex: linkIndex,
				Hops:      weight - 1,
				Gw:        gw,
			})
		}
		result = append(result, base)
	}
	return result, nil
}

func babelNextHop(resolve babelLinkResolver, route babel.SelectedRoute) (int, net.IP, error) {
	if route.Interface == "" {
		return 0, nil, errors.New("Babel route has no interface")
	}
	linkIndex, err := resolve(route.Interface)
	if err != nil {
		return 0, nil, err
	}
	return linkIndex, net.IP(route.NextHop.Unmap().AsSlice()), nil
}

func (b *Backend) reconcileBabelRoutes(record model.Tunnel, selected []babel.SelectedRoute) error {
	table := model.BabelRouteTable(record)
	desired, err := babelRoutesToNetlink(record, table, selected, b.resolveBabelLink)
	if err != nil {
		return err
	}
	current, err := b.netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return fmt.Errorf("list Babel route table %d: %w", table, err)
	}

	replace, remove, err := babelRouteDiff(current, desired, model.ManagedRouteRealm(record))
	if err != nil {
		return err
	}
	for i := range replace {
		if err := b.netlink.RouteReplace(&replace[i]); err != nil {
			return fmt.Errorf("ensure Babel route %s: %w", routeKey(replace[i]), err)
		}
	}
	for i := range remove {
		route := remove[i]
		if err := b.netlink.RouteDel(&route); err != nil && !errors.Is(err, unix.ESRCH) {
			return fmt.Errorf("remove stale Babel route: %w", err)
		}
	}
	return nil
}

// babelRouteDiff compares the routes currently present in a table against
// the desired Babel routes. It returns the routes to replace, the owned
// routes to remove, or an ownership error when a desired prefix is already
// claimed by a route TH does not own. Babel must never overwrite a route
// another owner installed.
func babelRouteDiff(current, desired []netlink.Route, realm int) (replace, remove []netlink.Route, err error) {
	wanted := make(map[string]netlink.Route, len(desired))
	for _, route := range desired {
		wanted[routeKey(route)] = route
	}
	currentByKey := make(map[string][]netlink.Route, len(current))
	for _, route := range current {
		key := routeKey(route)
		currentByKey[key] = append(currentByKey[key], route)
	}

	for key, route := range wanted {
		matched := false
		for _, existing := range currentByKey[key] {
			if existing.Protocol != managedRouteProtocol || existing.Realm != realm {
				return nil, nil, fmt.Errorf("route %s in table %d is not owned by TH: %w",
					key, route.Table, ErrOwnershipConflict)
			}
			if equalBabelManagedRoute(existing, route) {
				matched = true
			}
		}
		if !matched {
			replace = append(replace, route)
		}
	}

	for key, routes := range currentByKey {
		if _, ok := wanted[key]; ok {
			continue
		}
		for _, route := range routes {
			if route.Protocol == managedRouteProtocol && route.Realm == realm {
				remove = append(remove, route)
			}
		}
	}
	return replace, remove, nil
}

func equalBabelManagedRoute(current, desired netlink.Route) bool {
	if current.Table != desired.Table || current.Priority != desired.Priority ||
		current.Scope != desired.Scope || current.Protocol != desired.Protocol ||
		current.Realm != desired.Realm {
		return false
	}
	if !ipEqual(current.Gw, desired.Gw) || current.LinkIndex != desired.LinkIndex {
		return false
	}
	if len(current.MultiPath) != len(desired.MultiPath) {
		return false
	}
	for i := range current.MultiPath {
		if current.MultiPath[i].LinkIndex != desired.MultiPath[i].LinkIndex ||
			current.MultiPath[i].Hops != desired.MultiPath[i].Hops ||
			!ipEqual(current.MultiPath[i].Gw, desired.MultiPath[i].Gw) {
			return false
		}
	}
	return true
}

func ipEqual(a, b net.IP) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(b)
}

func (b *Backend) removeOwnedBabelRoutes(record model.Tunnel) error {
	table := model.BabelRouteTable(record)
	realm := model.ManagedRouteRealm(record)
	current, err := b.netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return fmt.Errorf("list Babel route table %d: %w", table, err)
	}
	for i := range current {
		route := current[i]
		if route.Protocol != managedRouteProtocol || route.Realm != realm {
			continue
		}
		if err := b.netlink.RouteDel(&route); err != nil && !errors.Is(err, unix.ESRCH) {
			return fmt.Errorf("remove Babel route: %w", err)
		}
	}
	return nil
}

func parseBabelRouterID(value string) ([8]byte, error) {
	var id [8]byte
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 8 {
		return id, errors.New("invalid Babel router_id")
	}
	copy(id[:], decoded)
	if id == ([8]byte{}) || id == [8]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff} {
		return id, errors.New("invalid Babel router_id: all-zero and all-one router IDs are reserved")
	}
	return id, nil
}

func normalizeBabelAddress(addr netip.Addr) netip.Addr {
	if addr.Is4() {
		return netip.AddrFrom16(addr.As16())
	}
	return addr
}

func (b *Backend) closeBabelInstances() {
	b.babel.mu.Lock()
	defer b.babel.mu.Unlock()
	for id, instance := range b.babel.instances {
		instance.speaker.Close()
		delete(b.babel.instances, id)
	}
}
