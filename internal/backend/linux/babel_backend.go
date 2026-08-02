//go:build linux

package linux

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/TunnelHelper/TH/internal/babel"
	"github.com/TunnelHelper/TH/internal/config"
	"github.com/TunnelHelper/TH/internal/core"
	"github.com/TunnelHelper/TH/internal/model"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const babelRoutePriority = 1

// babelWeightCooldown is the minimum interval between weight-only route
// updates. Kernel multipath rehashing disturbs in-flight flows, so weight
// changes must be slow and deliberate.
const babelWeightCooldown = 60 * time.Second

// babelTunnel is the engine's view of one participating tunnel.
type babelTunnel struct {
	recordID      string
	kind          model.Kind
	interfaceName string
	bandwidthMbps int
	neighbours    []netip.Addr
	multicast     bool
}

func (t babelTunnel) fingerprint() string {
	parts := make([]string, 0, len(t.neighbours)+3)
	parts = append(parts, t.recordID, t.interfaceName, strconv.Itoa(t.bandwidthMbps), strconv.FormatBool(t.multicast))
	for _, addr := range t.neighbours {
		parts = append(parts, addr.String())
	}
	sort.Strings(parts)
	return fmt.Sprint(parts)
}

// babelEngine runs the single daemon-wide Babel speaker. Every tunnel with
// Babel enabled feeds this engine; the engine decides per-interface whether
// multicast auto-discovery or unicast + static neighbours applies.
type babelEngine struct {
	backend  *Backend
	settings config.BabelSettings
	table    int
	realm    int

	mu               sync.Mutex
	speaker          *babel.Speaker
	tunnels          map[string]babelTunnel
	built            string // fingerprint of the tunnels the current speaker was built from
	routerID         [8]byte
	lastWeightChange time.Time
	lastWeights      map[string]string

	advertised map[netip.Prefix]struct{}
}

func newBabelEngine(backend *Backend) (*babelEngine, error) {
	settings := backend.settings.Babel
	routerID, err := loadBabelRouterID(settings.RouterID, backend.settings.StateDir)
	if err != nil {
		return nil, err
	}
	table := settings.RouteTable
	if table == 0 {
		table = unix.RT_TABLE_MAIN
	}
	return &babelEngine{
		backend:     backend,
		settings:    settings,
		table:       table,
		realm:       model.BabelManagedRealm(),
		tunnels:     make(map[string]babelTunnel),
		routerID:    routerID,
		advertised:  make(map[netip.Prefix]struct{}),
		lastWeights: make(map[string]string),
	}, nil
}

// loadBabelRouterID returns the configured router ID or a persisted random
// one so the protocol identity survives daemon restarts.
func loadBabelRouterID(configured, stateDir string) ([8]byte, error) {
	if configured != "" {
		return parseBabelRouterID(configured)
	}
	path := filepath.Join(stateDir, "babel-router-id")
	if data, err := os.ReadFile(path); err == nil {
		id, parseErr := parseBabelRouterID(string(data))
		if parseErr == nil {
			return id, nil
		}
	}
	generated, err := randomBabelRouterIDBytes()
	if err != nil {
		return [8]byte{}, fmt.Errorf("generate Babel router id: %w", err)
	}
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return generated, fmt.Errorf("create state dir for Babel router id: %w", err)
	}
	if err := writeCacheAtomic(path, []byte(hex.EncodeToString(generated[:]))); err != nil {
		return generated, fmt.Errorf("persist Babel router id: %w", err)
	}
	return generated, nil
}

func randomBabelRouterIDBytes() ([8]byte, error) {
	var id [8]byte
	if _, err := rand.Read(id[:]); err != nil {
		return id, err
	}
	return id, nil
}

// upsertTunnel records (or updates) a tunnel's participation. It marks the
// engine dirty only when the derived configuration actually changed.
func (e *babelEngine) upsertTunnel(record model.Tunnel) {
	t := babelTunnel{
		recordID:      record.ID,
		kind:          record.Kind,
		interfaceName: record.Interface,
		bandwidthMbps: 0,
		multicast:     tunnelMulticastMode(record),
	}
	if record.Spec.Babel != nil {
		t.bandwidthMbps = record.Spec.Babel.BandwidthMbps
		t.neighbours = deriveBabelNeighbours(record)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if existing, ok := e.tunnels[record.ID]; ok && existing.fingerprint() == t.fingerprint() {
		return
	}
	e.tunnels[record.ID] = t
}

func (e *babelEngine) removeTunnel(recordID string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.tunnels[recordID]; ok {
		delete(e.tunnels, recordID)
	}
}

// reconcile rebuilds the speaker when the tunnel set changed, refreshes the
// advertised prefixes and installs the current forwarding set.
func (e *babelEngine) reconcile() error {
	e.mu.Lock()
	fingerprint := e.fingerprintLocked()
	needBuild := e.speaker == nil || e.built != fingerprint
	if needBuild {
		if e.speaker != nil {
			old := e.speaker
			e.speaker = nil
			e.mu.Unlock()
			old.Close()
			e.mu.Lock()
		}
		if len(e.tunnels) == 0 && len(e.settings.Interfaces) == 0 {
			e.built = fingerprint
			e.mu.Unlock()
			return e.removeOwnedRoutes()
		}
		speaker, err := e.buildSpeakerLocked()
		if err != nil {
			e.mu.Unlock()
			return err
		}
		e.speaker = speaker
		e.built = fingerprint
		e.advertised = make(map[netip.Prefix]struct{})
	}
	speaker := e.speaker
	e.mu.Unlock()

	if err := e.refreshAdvertised(speaker); err != nil {
		return err
	}
	return e.installRoutes(speaker)
}

func (e *babelEngine) fingerprintLocked() string {
	keys := make([]string, 0, len(e.tunnels))
	for id, t := range e.tunnels {
		keys = append(keys, id+"="+t.fingerprint())
	}
	sort.Strings(keys)
	return fmt.Sprintf("%s|%x|%v|%d|%s", fmt.Sprint(keys), e.routerID,
		e.settings.DelayMetricEnabled(), e.settings.UnicastHelloSeconds, e.externalFingerprintLocked())
}

func (e *babelEngine) externalFingerprintLocked() string {
	names := make([]string, 0, len(e.settings.Interfaces))
	for name, external := range e.settings.Interfaces {
		names = append(names, fmt.Sprintf("%s=%d/%v/%v", name, external.BandwidthMbps, external.Multicast, external.Neighbours))
	}
	sort.Strings(names)
	return fmt.Sprint(names)
}

// refreshSettings applies a new Babel settings snapshot at runtime and
// rebuilds the speaker (and thus the advertised prefix set) when needed.
func (e *babelEngine) refreshSettings(settings config.BabelSettings) error {
	e.mu.Lock()
	previousFingerprint := e.fingerprintLocked()
	oldTable := e.table
	e.settings = settings
	e.table = settings.RouteTable
	if e.table == 0 {
		e.table = unix.RT_TABLE_MAIN
	}
	speakerFingerprintChanged := e.fingerprintLocked() != previousFingerprint
	speaker := e.speaker
	maxPaths := settings.MultipathMaxPaths
	if maxPaths == 0 {
		maxPaths = 4
	}
	tableChanged := e.table != oldTable
	e.mu.Unlock()

	// Route-table changes move the routes to a new table; remove the old
	// table's owned routes first so nothing is orphaned.
	if tableChanged {
		if err := e.removeOwnedRoutesFrom(oldTable); err != nil {
			return err
		}
	}
	// Non-protocol settings (ECMP parameters) apply to the running speaker
	// without rebuilding it, so adjacencies stay up.
	if !speakerFingerprintChanged && speaker != nil {
		speaker.UpdateECMPParams(maxPaths, uint16(settings.MultipathSlack), settings.WeightBottleneckPenalty)
	}
	return e.reconcile()
}

func (e *babelEngine) buildSpeakerLocked() (*babel.Speaker, error) {
	interfaces := make(map[string]bool, len(e.tunnels))
	static := make(map[string][]netip.Addr)
	multicast := make(map[string]bool)
	bandwidth := make(map[string]int)
	for _, t := range e.tunnels {
		interfaces[t.interfaceName] = true
		bandwidth[t.interfaceName] = t.bandwidthMbps
		if t.multicast {
			multicast[t.interfaceName] = true
		} else {
			static[t.interfaceName] = t.neighbours
		}
	}
	for name, external := range e.settings.Interfaces {
		if interfaces[name] {
			return nil, fmt.Errorf("external Babel interface %q conflicts with a TH tunnel interface", name)
		}
		interfaces[name] = true
		bandwidth[name] = external.BandwidthMbps
		if external.Multicast {
			multicast[name] = true
		} else {
			neighbours := make([]netip.Addr, 0, len(external.Neighbours))
			for _, addr := range external.Neighbours {
				neighbours = append(neighbours, normalizeBabelAddress(addr))
			}
			static[name] = neighbours
		}
	}

	params := babel.DefaultParameters
	helloSeconds := e.settings.UnicastHelloSeconds
	if helloSeconds == 0 {
		helloSeconds = 4
	}
	params.UnicastHelloInterval = time.Duration(helloSeconds) * time.Second
	maxPaths := e.settings.MultipathMaxPaths
	if maxPaths == 0 {
		maxPaths = 4
	}
	params.MaxPaths = maxPaths
	params.MultipathSlack = uint16(e.settings.MultipathSlack)
	params.DelayMetric = e.settings.DelayMetricEnabled()
	params.BottleneckPenalty = e.settings.WeightBottleneckPenalty

	cfg := &babel.SpeakerConfig{
		Parameters:          &params,
		RouterID:            e.routerID,
		InterfaceFilter:     func(name string) bool { return interfaces[name] },
		StaticNeighbours:    static,
		MulticastInterfaces: multicast,
		InterfaceBandwidth:  bandwidth,
		Handler:             babelEngineHandler{engine: e},
		Logger:              slog.Default(),
	}
	return babel.NewSpeaker(cfg)
}

// tunnelMulticastMode chooses the Babel link mode for a tunnel: single-peer
// WireGuard and point-to-point GRE/VXLAN/XFRM use multicast auto-discovery
// (like BIRD ptp), multi-peer WireGuard meshes use unicast + static
// neighbours (like BIRD ptmp/nbma). An explicit Multicast override wins.
func tunnelMulticastMode(record model.Tunnel) bool {
	if record.Spec.Babel != nil && record.Spec.Babel.Multicast != nil {
		return *record.Spec.Babel.Multicast
	}
	switch record.Kind {
	case model.KindWireGuard, model.KindAmneziaWG:
		peers := 0
		if record.Spec.WireGuard != nil {
			peers = len(record.Spec.WireGuard.Peers)
		} else if record.Spec.AmneziaWG != nil {
			peers = len(record.Spec.AmneziaWG.Peers)
		}
		return peers <= 1
	default:
		return true
	}
}

// refreshAdvertised injects (or withdraws) the locally originated prefixes.
func (e *babelEngine) refreshAdvertised(speaker *babel.Speaker) error {
	if speaker == nil {
		return nil
	}
	desired := e.discoverAdvertisedPrefixes()
	for prefix := range desired {
		if err := speaker.Advertise(prefix, babel.LocalRouteMetric); err != nil {
			return fmt.Errorf("advertise %s: %w", prefix, err)
		}
	}
	for prefix := range e.advertised {
		if _, keep := desired[prefix]; keep {
			continue
		}
		if err := speaker.Withdraw(prefix); err != nil {
			return fmt.Errorf("withdraw %s: %w", prefix, err)
		}
	}
	e.advertised = desired
	return nil
}

// discoverAdvertisedPrefixes returns the filtered prefix set to originate.
func (e *babelEngine) discoverAdvertisedPrefixes() map[netip.Prefix]struct{} {
	advertise := e.settings.Advertise
	var discovered []netip.Prefix
	if len(advertise.AdvertisedPrefixes) > 0 {
		discovered = append(discovered, advertise.AdvertisedPrefixes...)
	} else {
		sources := advertise.SourceInterfaces
		if len(sources) == 0 {
			sources = []string{"lo"}
		}
		for _, name := range sources {
			link, err := e.backend.netlink.LinkByName(name)
			if err != nil {
				continue
			}
			addresses, err := e.backend.netlink.AddrList(link, netlink.FAMILY_ALL)
			if err != nil {
				continue
			}
			for _, addr := range addresses {
				ones, _ := addr.IPNet.Mask.Size()
				if ones < 0 {
					continue
				}
				if parsed, ok := netip.AddrFromSlice(addr.IPNet.IP); ok {
					discovered = append(discovered, netip.PrefixFrom(parsed.Unmap(), ones))
				}
			}
		}
	}

	out := make(map[netip.Prefix]struct{})
	for _, prefix := range discovered {
		prefix = prefix.Masked()
		if !filterAdvertisedPrefix(prefix, advertise.Include, advertise.Exclude) {
			continue
		}
		out[prefix] = struct{}{}
	}
	return out
}

// filterAdvertisedPrefix applies the include/exclude filters plus built-in
// exclusions for link-local, multicast, loopback and unspecified prefixes.
func filterAdvertisedPrefix(prefix netip.Prefix, include, exclude []netip.Prefix) bool {
	addr := prefix.Addr()
	if !addr.IsValid() || addr.IsUnspecified() || addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsLoopback() {
		return false
	}
	if prefix == netip.MustParsePrefix("127.0.0.0/8") || prefix == netip.MustParsePrefix("::1/128") {
		return false
	}
	for _, excluded := range exclude {
		if excluded.Contains(addr) {
			return false
		}
	}
	if len(include) > 0 {
		for _, allowed := range include {
			if allowed.Contains(addr) {
				return true
			}
		}
		return false
	}
	return true
}

func (e *babelEngine) installRoutes(speaker *babel.Speaker) error {
	if speaker == nil {
		return e.removeOwnedRoutes()
	}
	selected := speaker.SelectedRoutes()
	desired, err := babelRoutesToNetlink(e.table, selected, e.backend.resolveBabelLink, e.pathScore, e.realm)
	if err != nil {
		return err
	}
	current, err := e.backend.netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: e.table}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return fmt.Errorf("list Babel route table %d: %w", e.table, err)
	}
	replace, remove, err := babelRouteDiff(current, desired, e.realm)
	if err != nil {
		return err
	}
	weightApplied := false
	for i := range replace {
		route := replace[i]
		key := routeKey(route)
		if babelWeightOnlyChange(current, route) {
			fingerprint := multipathWeightFingerprint(route)
			if previous, ok := e.lastWeights[key]; ok && weightsWithinTolerance(previous, fingerprint) {
				// Small weight changes do not rehash in-flight flows.
				continue
			}
			if time.Since(e.lastWeightChange) < babelWeightCooldown {
				continue
			}
			weightApplied = true
			e.lastWeights[key] = fingerprint
		} else {
			delete(e.lastWeights, key)
		}
		if err := e.backend.netlink.RouteReplace(&route); err != nil {
			return fmt.Errorf("ensure Babel route %s: %w", routeKey(route), err)
		}
	}
	if weightApplied {
		e.lastWeightChange = time.Now()
	}
	for i := range remove {
		route := remove[i]
		delete(e.lastWeights, routeKey(route))
		if err := e.backend.netlink.RouteDel(&route); err != nil && !errors.Is(err, unix.ESRCH) {
			return fmt.Errorf("remove stale Babel route: %w", err)
		}
	}
	return nil
}

func (e *babelEngine) bandwidthOf(interfaceName string) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, t := range e.tunnels {
		if t.interfaceName == interfaceName {
			return t.bandwidthMbps
		}
	}
	return 0
}

// pathScore is the raw per-path signal used for weighted ECMP:
// bandwidth^alpha / rtt^beta. Bandwidth is the operator-declared value;
// RTT is the smoothed measurement from RFC 9616. Before an RTT sample
// exists the bandwidth term alone is used.
// pathScore is the raw per-path signal used for weighted ECMP:
// bottleneck^alpha / path_rtt^beta, computed from the end-to-end values
// carried by the route. When a peer does not announce the extension, the
// local first-hop declared bandwidth and measured neighbour RTT are used.
func (e *babelEngine) pathScore(route babel.SelectedRoute) float64 {
	e.mu.Lock()
	alpha, beta := e.settings.WeightBandwidthExponent, e.settings.WeightRTTExponent
	speaker := e.speaker
	e.mu.Unlock()

	bw := float64(route.BottleneckMbps)
	if bw <= 0 {
		bw = float64(e.bandwidthOf(route.Interface))
		if bw <= 0 {
			bw = 1
		}
	}
	var localRTT time.Duration
	var hasRTT bool
	if speaker != nil {
		localRTT, hasRTT = speaker.NeighbourRTT(route.Interface, route.NextHop)
	}
	return babelPathScore(bw, route.PathRTTMicros, localRTT, hasRTT, alpha, beta)
}

// babelPathScore computes bottleneck^alpha / rtt^beta from end-to-end path
// values, falling back to the local first-hop measurement when the path RTT
// is unknown. A zero-latency path gets full weight.
func babelPathScore(bottleneck float64, pathRTT int64, localRTT time.Duration, hasLocalRTT bool, alpha, beta float64) float64 {
	if bottleneck <= 0 {
		bottleneck = 1
	}
	if pathRTT > 0 {
		return math.Pow(bottleneck, alpha) / math.Pow(float64(pathRTT), beta)
	}
	if hasLocalRTT && localRTT > 0 {
		return math.Pow(bottleneck, alpha) / math.Pow(float64(localRTT.Microseconds()), beta)
	}
	return math.Pow(bottleneck, alpha)
}

func (e *babelEngine) removeOwnedRoutes() error {
	return e.removeOwnedRoutesFrom(e.table)
}

func (e *babelEngine) removeOwnedRoutesFrom(table int) error {
	current, err := e.backend.netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return fmt.Errorf("list Babel route table %d: %w", table, err)
	}
	for i := range current {
		route := current[i]
		if route.Protocol != managedRouteProtocol || route.Realm != e.realm {
			continue
		}
		if err := e.backend.netlink.RouteDel(&route); err != nil && !errors.Is(err, unix.ESRCH) {
			return fmt.Errorf("remove Babel route: %w", err)
		}
	}
	return nil
}

func (e *babelEngine) observe(record model.Tunnel) core.Observation {
	if record.Spec.Babel == nil || !record.Spec.Babel.Enabled {
		return core.Observation{}
	}
	e.mu.Lock()
	speaker := e.speaker
	e.mu.Unlock()
	if speaker == nil {
		return core.Observation{}
	}

	selected := speaker.SelectedRoutes()
	details := map[string]string{
		"babel":           "enabled",
		"router_id":       hex.EncodeToString(e.routerID[:]),
		"selected_routes": strconv.Itoa(len(selected)),
		"route_table":     strconv.Itoa(e.table),
	}
	peers := make([]model.PeerStatus, 0)
	_ = speaker.Interfaces.Foreach(func(_ int, iface *babel.Interface) error {
		if iface.Name != record.Interface {
			return nil
		}
		count := 0
		_ = iface.Neighbours.Foreach(func(n *babel.Neighbour) error {
			count++
			peers = append(peers, model.PeerStatus{PublicKey: n.Address.String(), Endpoint: iface.Name})
			return nil
		})
		details["neighbours"] = strconv.Itoa(count)
		return nil
	})
	return core.Observation{
		InterfaceExists: true,
		InterfaceUp:     true,
		Details:         details,
		Peers:           peers,
	}
}

func (e *babelEngine) close() {
	e.mu.Lock()
	speaker := e.speaker
	e.speaker = nil
	e.mu.Unlock()
	if speaker != nil {
		_ = speaker.Close()
	}
}

// deriveBabelNeighbours returns the Babel neighbours of a tunnel: explicit
// entries plus, for WireGuard-style tunnels, the deterministic link-local
// address of every peer derived from its public key.
func deriveBabelNeighbours(record model.Tunnel) []netip.Addr {
	out := make([]netip.Addr, 0)
	if record.Spec.Babel != nil {
		for _, addr := range record.Spec.Babel.Neighbours {
			out = append(out, normalizeBabelAddress(addr))
		}
	}
	switch record.Kind {
	case model.KindWireGuard:
		if record.Spec.WireGuard != nil {
			for _, peer := range record.Spec.WireGuard.Peers {
				if addr, ok := wgLinkLocal(peer.PublicKey); ok {
					out = append(out, addr)
				}
			}
		}
	case model.KindAmneziaWG:
		if record.Spec.AmneziaWG != nil {
			for _, peer := range record.Spec.AmneziaWG.Peers {
				if addr, ok := wgLinkLocal(peer.PublicKey); ok {
					out = append(out, addr)
				}
			}
		}
	}
	seen := make(map[netip.Addr]struct{}, len(out))
	result := out[:0]
	for _, addr := range out {
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		result = append(result, addr)
	}
	return result
}

// wgLinkLocal derives the stable IPv6 link-local address a WireGuard
// interface gets from its public key. Both ends of a tunnel can compute the
// peer's address, which is what makes unicast Babel over LLA-only links
// work without manual neighbour configuration.
func wgLinkLocal(publicKey string) (netip.Addr, bool) {
	key, err := wgtypes.ParseKey(publicKey)
	if err != nil {
		return netip.Addr{}, false
	}
	digest := sha256.Sum256(append([]byte("th-wg-lla\x00"), key[:]...))
	var address [16]byte
	address[0], address[1] = 0xfe, 0x80
	copy(address[8:], digest[:8])
	address[8] &^= 0x02
	return netip.AddrFrom16(address), true
}

// babelEngineHandler forwards protocol events to the reconciler.
type babelEngineHandler struct {
	engine *babelEngine
}

func (h babelEngineHandler) RoutesChanged() {
	h.emit(core.BackendEventRoute)
}

func (h babelEngineHandler) NeighbourAdded(*babel.Neighbour) {
	h.emit(core.BackendEventLink)
}

func (h babelEngineHandler) NeighbourRemoved(*babel.Neighbour) {
	h.emit(core.BackendEventLink)
}

func (h babelEngineHandler) emit(eventType core.BackendEventType) {
	select {
	case h.engine.backend.events <- core.BackendEvent{Type: eventType, RouteTable: h.engine.table}:
	default:
	}
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

// babelMultipathWeight maps a candidate bandwidth to a kernel next-hop
// weight relative to the best (fastest) candidate: 256 * bw_i / bw_best.
// babelWeightFromScores maps per-path scores to kernel next-hop weights:
// 256 * score_i / score_best, clamped to [1, 256]. A missing signal yields
// the default weight, so no path is ever starved completely.
func babelWeightFromScores(scoreBest, candidate float64) int {
	if scoreBest <= 0 || candidate <= 0 {
		return 256
	}
	weight := int(math.Round(256 * candidate / scoreBest))
	if weight < 1 {
		return 1
	}
	if weight > 256 {
		return 256
	}
	return weight
}

type babelLinkResolver func(name string) (int, error)

func (b *Backend) resolveBabelLink(name string) (int, error) {
	link, err := b.netlink.LinkByName(name)
	if err != nil {
		return 0, fmt.Errorf("lookup Babel next-hop interface %s: %w", name, err)
	}
	return link.Attrs().Index, nil
}

func babelRoutesToNetlink(table int, selected []babel.SelectedRoute, resolve babelLinkResolver, score func(babel.SelectedRoute) float64, realm int) ([]netlink.Route, error) {
	byPrefix := make(map[netip.Prefix][]babel.SelectedRoute)
	for _, route := range selected {
		if route.Local {
			continue
		}
		prefix := route.Prefix.Masked()
		byPrefix[prefix] = append(byPrefix[prefix], route)
	}

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
		scoreBest := 0.0
		for _, candidate := range candidates {
			if current := score(candidate); current > scoreBest {
				scoreBest = current
			}
		}
		for _, candidate := range candidates {
			linkIndex, gw, err := babelNextHop(resolve, candidate)
			if err != nil {
				return nil, err
			}
			weight := babelWeightFromScores(scoreBest, score(candidate))
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

// babelRouteDiff compares the routes currently present in a table against
// the desired Babel routes. It returns the routes to replace, the owned
// routes to remove, or an ownership error when a desired prefix is already
// claimed by a route TH does not own.
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

// babelWeightEqual treats next-hop weights as equal when they differ by at
// most 10% (or a single unit). Small weight changes must not trigger kernel
// route replacements: each one rehashes in-flight flows.
func babelWeightEqual(current, desired int) bool {
	if current == desired {
		return true
	}
	larger := max(current, desired)
	if larger == 0 {
		return true
	}
	delta := current - desired
	if delta < 0 {
		delta = -delta
	}
	return float64(delta)/float64(larger) <= 0.10 || delta <= 1
}

// multipathWeightFingerprint serialises the installed weights of a
// multipath route so weight-only changes can be compared across reconciles.
func multipathWeightFingerprint(route netlink.Route) string {
	parts := make([]string, 0, len(route.MultiPath))
	for _, nextHop := range route.MultiPath {
		parts = append(parts, strconv.Itoa(nextHop.Hops))
	}
	return strings.Join(parts, ",")
}

// weightsWithinTolerance reports whether every weight in the new fingerprint
// is within the 10% tolerance of the previously installed one.
func weightsWithinTolerance(previous, current string) bool {
	oldParts := strings.Split(previous, ",")
	newParts := strings.Split(current, ",")
	if len(oldParts) != len(newParts) {
		return false
	}
	for i := range oldParts {
		oldWeight, oldErr := strconv.Atoi(oldParts[i])
		newWeight, newErr := strconv.Atoi(newParts[i])
		if oldErr != nil || newErr != nil {
			return false
		}
		if !babelWeightEqual(oldWeight, newWeight) {
			return false
		}
	}
	return true
}

// babelWeightOnlyChange reports whether a replacement differs from the
// currently installed route only in its multipath weights (same next hops,
// same structure). Such updates are candidates for cooldown gating.
func babelWeightOnlyChange(current []netlink.Route, desired netlink.Route) bool {
	for _, existing := range current {
		if routeKey(existing) != routeKey(desired) {
			continue
		}
		if existing.Protocol != desired.Protocol || existing.Realm != desired.Realm ||
			existing.Priority != desired.Priority || existing.Scope != desired.Scope {
			return false
		}
		if len(existing.MultiPath) != len(desired.MultiPath) {
			return false
		}
		if !ipEqual(existing.Gw, desired.Gw) || existing.LinkIndex != desired.LinkIndex {
			return false
		}
		for i := range existing.MultiPath {
			if existing.MultiPath[i].LinkIndex != desired.MultiPath[i].LinkIndex ||
				!ipEqual(existing.MultiPath[i].Gw, desired.MultiPath[i].Gw) {
				return false
			}
		}
		return true
	}
	return false
}

func ipEqual(a, b net.IP) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(b)
}
