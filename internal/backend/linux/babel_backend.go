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
	"math/bits"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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

const (
	babelReferenceBandwidthMbps = 100.0
	babelReferenceRTTMicros     = 10_000.0
	babelReferenceJitterMicros  = 5_000.0
	babelUnknownRTTMicros       = 120_000.0
	babelUnknownJitterMicros    = 20_000.0
	babelMinimumConfidence      = 0.10
)

// babelTunnel is the engine's view of one participating tunnel.
type babelTunnel struct {
	recordID      string
	kind          model.Kind
	interfaceName string
	bandwidthMbps int
	balance       *float64
	neighbours    []netip.Addr
	multicast     bool
}

type babelWeightState struct {
	installed           string
	lastChange          time.Time
	pending             string
	pendingObservations int
}

func (s *babelWeightState) shouldApply(desired string, now time.Time) bool {
	if s.installed != "" && weightsWithinTolerance(s.installed, desired) {
		s.pending = ""
		s.pendingObservations = 0
		return false
	}
	if s.pending == "" || !weightsWithinTolerance(s.pending, desired) {
		s.pending = desired
		s.pendingObservations = 1
		return false
	}
	s.pendingObservations++
	return s.pendingObservations >= 2 && (s.lastChange.IsZero() || now.Sub(s.lastChange) >= babelWeightCooldown)
}

func (s *babelWeightState) applied(fingerprint string, now time.Time) {
	s.installed = fingerprint
	s.lastChange = now
	s.pending = ""
	s.pendingObservations = 0
}

func (t babelTunnel) fingerprint() string {
	parts := make([]string, 0, len(t.neighbours)+3)
	parts = append(parts, t.recordID, t.interfaceName, strconv.Itoa(t.bandwidthMbps), strconv.FormatBool(t.multicast))
	if t.balance != nil {
		parts = append(parts, strconv.FormatFloat(*t.balance, 'g', -1, 64))
	}
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

	reconcileMu  sync.Mutex
	mu           sync.Mutex
	eventTable   atomic.Int64
	speaker      *babel.Speaker
	tunnels      map[string]babelTunnel
	built        string // fingerprint of the tunnels the current speaker was built from
	routerID     [8]byte
	weightStates map[string]*babelWeightState

	advertised map[netip.Prefix]struct{}

	// forceWeightRefresh bypasses measurement-noise damping for an explicit
	// operator change to the global weighting policy. It is protected by
	// reconcileMu and remains set after a failed netlink update for retry.
	forceWeightRefresh bool
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
	engine := &babelEngine{
		backend:      backend,
		settings:     settings,
		table:        table,
		tunnels:      make(map[string]babelTunnel),
		routerID:     routerID,
		advertised:   make(map[netip.Prefix]struct{}),
		weightStates: make(map[string]*babelWeightState),
	}
	engine.eventTable.Store(int64(table))
	return engine, nil
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

// health reports the router ID the running speaker actually uses, which is
// the persisted auto-generated value when the configuration is empty.
func (e *babelEngine) health() core.BabelHealth {
	e.reconcileMu.Lock()
	defer e.reconcileMu.Unlock()
	e.mu.Lock()
	routerID := hex.EncodeToString(e.routerID[:])
	speaker := e.speaker
	table := e.table
	maxAge := e.settings.DelaySampleMaxAge()
	e.mu.Unlock()
	health := core.BabelHealth{RouterID: routerID}
	if speaker == nil {
		return health
	}
	for prefix := range e.advertised {
		health.OriginatedPrefixes = append(health.OriginatedPrefixes, prefix.String())
	}
	sort.Strings(health.OriginatedPrefixes)
	now := time.Now()
	_ = speaker.Interfaces.Foreach(func(_ int, iface *babel.Interface) error {
		return iface.Neighbours.Foreach(func(n *babel.Neighbour) error {
			stats := n.DelayStats()
			health.Neighbours = append(health.Neighbours, core.BabelNeighbourHealth{
				Interface: iface.Name, Address: n.Address.String(),
				RTTMicros: stats.Mean.Microseconds(), JitterMicros: stats.Jitter().Microseconds(),
				MinRTTMicros: stats.Min.Microseconds(), AgeMillis: stats.Age(now).Milliseconds(),
				Samples: stats.Samples, Outliers: stats.OutlierSamples,
				Confidence: stats.Confidence(now, babel.DefaultDelayWarmupSamples, maxAge),
				Fresh:      stats.Fresh(now, babel.DefaultDelayWarmupSamples, maxAge),
			})
			return nil
		})
	})
	sort.Slice(health.Neighbours, func(i, j int) bool {
		if health.Neighbours[i].Interface != health.Neighbours[j].Interface {
			return health.Neighbours[i].Interface < health.Neighbours[j].Interface
		}
		return health.Neighbours[i].Address < health.Neighbours[j].Address
	})
	sources := e.localOriginAddresses()
	health.Routes = e.routeHealthLocked(speaker.SelectedRoutes(), table, sources)
	return health
}

func (e *babelEngine) routeHealthLocked(selected []babel.SelectedRoute, table int, sources []netip.Addr) []core.BabelRouteHealth {
	byPrefix := make(map[netip.Prefix][]babel.SelectedRoute)
	for _, route := range selected {
		if !route.Local {
			byPrefix[route.Prefix.Masked()] = append(byPrefix[route.Prefix.Masked()], route)
		}
	}
	prefixes := make([]netip.Prefix, 0, len(byPrefix))
	for prefix := range byPrefix {
		prefixes = append(prefixes, prefix)
	}
	sort.Slice(prefixes, func(i, j int) bool { return prefixes[i].String() < prefixes[j].String() })
	out := make([]core.BabelRouteHealth, 0, len(selected))
	for _, prefix := range prefixes {
		preferredSource := selectBabelPreferredSource(prefix, sources)
		candidates := byPrefix[prefix]
		sort.SliceStable(candidates, func(i, j int) bool {
			if candidates[i].Metric != candidates[j].Metric {
				return candidates[i].Metric < candidates[j].Metric
			}
			return candidates[i].NextHop.Compare(candidates[j].NextHop) < 0
		})
		scores := make([]float64, len(candidates))
		best := 0.0
		for i, candidate := range candidates {
			scores[i] = e.pathScore(candidate)
			if scores[i] > best && !math.IsInf(scores[i], 0) && !math.IsNaN(scores[i]) {
				best = scores[i]
			}
		}
		key := routeKey(netlink.Route{Table: table, Dst: prefixToIPNet(prefix)})
		installed := []int(nil)
		if state := e.weightStates[key]; state != nil {
			installed, _, _ = parseWeightFingerprint(state.installed)
		}
		for i, candidate := range candidates {
			confidence := float64(candidate.PathMetricConfidence) / float64(math.MaxUint16)
			item := core.BabelRouteHealth{
				Prefix: prefix.String(), Interface: candidate.Interface, NextHop: candidate.NextHop.String(),
				PreferredSource: ipString(preferredSource),
				Metric:          candidate.Metric, BottleneckMbps: candidate.BottleneckMbps,
				RTTMicros: candidate.PathRTTMicros, JitterMicros: candidate.PathJitterMicros,
				AgeMillis: candidate.PathMetricAgeMillis, Confidence: confidence,
				Score: scores[i], DesiredWeight: babelWeightFromScores(best, scores[i]),
			}
			if i < len(installed) {
				item.InstalledWeight = installed[i]
			}
			out = append(out, item)
		}
	}
	return out
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
		t.balance = record.Spec.Babel.Balance
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
	e.reconcileMu.Lock()
	defer e.reconcileMu.Unlock()
	return e.reconcileSerialized()
}

func (e *babelEngine) reconcileSerialized() error {
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
		e.warnMissingInterfaces(speaker)
	}
	speaker := e.speaker
	e.mu.Unlock()

	if err := e.refreshAdvertised(speaker); err != nil {
		return err
	}
	return e.installRoutes(speaker)
}

// warnMissingInterfaces logs every interface that was configured for Babel
// (a tunnel with Babel enabled or an external settings entry) but is not
// present in the kernel, so a missing link is visible instead of being
// silently ignored. The caller must hold e.mu.
func (e *babelEngine) warnMissingInterfaces(speaker *babel.Speaker) {
	configured := e.configuredBabelInterfaces()
	_ = speaker.Interfaces.Foreach(func(_ int, iface *babel.Interface) error {
		delete(configured, iface.Name)
		return nil
	})
	for name, source := range configured {
		slog.Warn("Configured Babel interface is not present in the kernel; Babel is inactive on it",
			slog.String("interface", name), slog.String("source", source))
	}
}

// configuredBabelInterfaces maps every interface expected to run Babel to
// the source that configured it ("tunnel" or "external").
func (e *babelEngine) configuredBabelInterfaces() map[string]string {
	configured := make(map[string]string, len(e.tunnels)+len(e.settings.Interfaces))
	for _, t := range e.tunnels {
		configured[t.interfaceName] = "tunnel"
	}
	for name := range e.settings.Interfaces {
		configured[name] = "external"
	}
	return configured
}

func (e *babelEngine) fingerprintLocked() string {
	keys := make([]string, 0, len(e.tunnels))
	for id, t := range e.tunnels {
		keys = append(keys, id+"="+t.fingerprint())
	}
	sort.Strings(keys)
	return fmt.Sprintf("%s|%x|%v|%d|%d|%d|%d|%s", fmt.Sprint(keys), e.routerID,
		e.settings.DelayMetricEnabled(), e.settings.UnicastHelloSeconds,
		e.settings.DelayProbeIntervalMillis, e.settings.DelaySampleMaxAgeMillis,
		e.settings.DelaySmoothingTimeConstantMillis, e.externalFingerprintLocked())
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
	e.reconcileMu.Lock()
	defer e.reconcileMu.Unlock()
	e.mu.Lock()
	previousFingerprint := e.fingerprintLocked()
	oldTable := e.table
	weightPolicyChanged := e.settings.WeightBandwidthExponent != settings.WeightBandwidthExponent ||
		e.settings.WeightRTTExponent != settings.WeightRTTExponent ||
		e.settings.WeightJitterExponent != settings.WeightJitterExponent
	if err := e.refreshRouterIDLocked(settings); err != nil {
		e.mu.Unlock()
		return err
	}
	e.settings = settings
	e.table = settings.RouteTable
	if e.table == 0 {
		e.table = unix.RT_TABLE_MAIN
	}
	e.eventTable.Store(int64(e.table))
	speakerFingerprintChanged := e.fingerprintLocked() != previousFingerprint
	speaker := e.speaker
	maxPaths := settings.MultipathMaxPaths
	if maxPaths == 0 {
		maxPaths = 4
	}
	tableChanged := e.table != oldTable
	e.mu.Unlock()
	if weightPolicyChanged {
		e.forceWeightRefresh = true
	}

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
	return e.reconcileSerialized()
}

// refreshRouterIDLocked resolves the effective router ID for a settings
// snapshot: the configured value, or the persisted auto-generated one when
// the configuration leaves it empty. The caller must hold e.mu.
func (e *babelEngine) refreshRouterIDLocked(settings config.BabelSettings) error {
	routerID, err := loadBabelRouterID(settings.RouterID, e.backend.settings.StateDir)
	if err != nil {
		return err
	}
	e.routerID = routerID
	return nil
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
	params.DelayProbeInterval = e.settings.DelayProbeInterval()
	params.DelaySampleMaxAge = e.settings.DelaySampleMaxAge()
	params.DelaySmoothingTimeConstant = e.settings.DelaySmoothingTimeConstant()
	params.BottleneckPenalty = e.settings.WeightBottleneckPenalty

	cfg := &babel.SpeakerConfig{
		Parameters:          &params,
		RouterID:            e.routerID,
		InterfaceFilter:     func(name string) bool { return interfaces[name] },
		StaticNeighbours:    static,
		StrictNeighbours:    true,
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
	// A tunnel whose auto-selected multicast mode cannot carry Babel
	// traffic falls back to unicast even when the stored record was not
	// normalized yet.
	if model.BabelNeedsUnicastFallback(&record) {
		return false
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
	sources := e.localOriginAddresses()
	desired, err := babelRoutesToNetlink(e.table, selected, e.backend.resolveBabelLink, e.pathScore,
		func(prefix netip.Prefix) net.IP { return selectBabelPreferredSource(prefix, sources) })
	if err != nil {
		return err
	}
	current, err := e.backend.netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: e.table}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return fmt.Errorf("list Babel route table %d: %w", e.table, err)
	}
	replace, remove, err := babelRouteDiff(current, desired, e.table)
	if err != nil {
		slog.Error("Babel route diff failed", "error", err)
		return err
	}
	now := time.Now()
	for i := range replace {
		route := replace[i]
		key := routeKey(route)
		if shouldDampBabelWeightChange(e.forceWeightRefresh, current, route) {
			desiredFingerprint := multipathWeightFingerprint(route)
			currentFingerprint := currentMultipathWeightFingerprint(current, key)
			state := e.weightStates[key]
			if state == nil {
				state = &babelWeightState{installed: currentFingerprint}
				e.weightStates[key] = state
			} else if state.installed != currentFingerprint {
				// Netlink is authoritative if an external actor changed the route.
				state.installed = currentFingerprint
				state.pending = ""
				state.pendingObservations = 0
			}
			if !state.shouldApply(desiredFingerprint, now) {
				continue
			}
		}
		if err := e.backend.netlink.RouteReplace(&route); err != nil {
			slog.Error("Babel route replace failed", "route", routeKey(route), "error", err)
			return fmt.Errorf("ensure Babel route %s: %w", routeKey(route), err)
		}
		if len(route.MultiPath) > 0 {
			state := e.weightStates[key]
			if state == nil {
				state = &babelWeightState{}
				e.weightStates[key] = state
			}
			state.applied(multipathWeightFingerprint(route), now)
		} else {
			delete(e.weightStates, key)
		}
	}
	for i := range remove {
		route := remove[i]
		delete(e.weightStates, routeKey(route))
		if err := e.backend.netlink.RouteDel(&route); err != nil && !errors.Is(err, unix.ESRCH) {
			slog.Error("Babel route delete failed", "route", routeKey(route), "error", err)
			return fmt.Errorf("remove stale Babel route: %w", err)
		}
	}
	e.forceWeightRefresh = false
	return nil
}

func shouldDampBabelWeightChange(forceRefresh bool, current []netlink.Route, desired netlink.Route) bool {
	return !forceRefresh && babelWeightOnlyChange(current, desired)
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
// (bottleneck/B0)^alpha / (path_rtt/R0)^beta /
// (1 + path_jitter/J0)^gamma * confidence. Fixed references make the score
// dimensionless, so per-interface exponent overrides cannot change path
// ordering merely because a measurement is expressed in other units.
func (e *babelEngine) pathScore(route babel.SelectedRoute) float64 {
	e.mu.Lock()
	alpha, beta := e.exponentsFor(route.Interface)
	gamma := e.settings.WeightJitterExponent
	speaker := e.speaker
	maxAge := e.settings.DelaySampleMaxAge()
	e.mu.Unlock()

	bw := float64(route.BottleneckMbps)
	if bw <= 0 {
		bw = float64(e.bandwidthOf(route.Interface))
		if bw <= 0 {
			bw = 1
		}
	}
	var local babel.DelayStats
	if speaker != nil {
		local, _ = speaker.NeighbourDelayStats(route.Interface, route.NextHop)
	}
	return babelPathScore(bw, route, local, maxAge, alpha, beta, gamma)
}

// exponentsFor returns the weight exponents of a tunnel. An explicit
// per-tunnel balance wins; tunnels without one use the daemon-global
// defaults (the balance mapping alpha = 1 + bias, beta = 1 - bias clamped
// to [0, 4]).
func (e *babelEngine) exponentsFor(interfaceName string) (float64, float64) {
	for _, tunnel := range e.tunnels {
		if tunnel.interfaceName == interfaceName && tunnel.balance != nil {
			bias := *tunnel.balance
			return clampWeightExponent(1 + bias), clampWeightExponent(1 - bias)
		}
	}
	return e.settings.WeightBandwidthExponent, e.settings.WeightRTTExponent
}

func clampWeightExponent(value float64) float64 {
	if value < 0 {
		return 0
	}
	if value > 4 {
		return 4
	}
	return value
}

// babelPathScore computes a dimensionless bandwidth/latency utility. Missing
// path RTT falls back to the local first-hop measurement, then to a common
// conservative value. Omitting the RTT denominator for only some candidates
// would make known and unknown paths incomparable.
func babelPathScore(bottleneck float64, route babel.SelectedRoute, local babel.DelayStats, maxAge time.Duration, alpha, beta, gamma float64) float64 {
	if bottleneck <= 0 {
		bottleneck = 1
	}
	rttMicros := babelUnknownRTTMicros
	jitterMicros := babelUnknownJitterMicros
	confidence := babelMinimumConfidence
	pathKnown := route.PathRTTMicros > 0
	pathFresh := pathKnown && route.PathMetricAgeMillis >= 0 && maxAge > 0 &&
		time.Duration(route.PathMetricAgeMillis)*time.Millisecond < maxAge
	if pathFresh {
		rttMicros = float64(route.PathRTTMicros)
		if route.PathJitterMicros >= 0 {
			jitterMicros = float64(route.PathJitterMicros)
		}
		confidence = max(float64(route.PathMetricConfidence)/float64(math.MaxUint16), babelMinimumConfidence)
	} else if !pathKnown {
		now := time.Now()
		if local.Samples > 0 && local.Age(now) < maxAge {
			rttMicros = float64(max(local.Mean.Microseconds(), 1))
			jitterMicros = float64(max(local.Jitter().Microseconds(), 0))
			confidence = max(local.Confidence(now, babel.DefaultDelayWarmupSamples, maxAge), babelMinimumConfidence)
		}
	}
	return math.Pow(bottleneck/babelReferenceBandwidthMbps, alpha) /
		math.Pow(rttMicros/babelReferenceRTTMicros, beta) /
		math.Pow(1+jitterMicros/babelReferenceJitterMicros, gamma) * confidence
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
		if !babelRouteOwned(route, table) {
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
	e.reconcileMu.Lock()
	defer e.reconcileMu.Unlock()
	e.mu.Lock()
	speaker := e.speaker
	routerID := e.routerID
	table := e.table
	e.mu.Unlock()
	if speaker == nil {
		return core.Observation{}
	}

	selected := speaker.SelectedRoutes()
	details := map[string]string{
		"babel":           "enabled",
		"router_id":       hex.EncodeToString(routerID[:]),
		"selected_routes": strconv.Itoa(len(selected)),
		"route_table":     strconv.Itoa(table),
	}
	peers := make([]model.PeerStatus, 0)
	_ = speaker.Interfaces.Foreach(func(_ int, iface *babel.Interface) error {
		if iface.Name != record.Interface {
			return nil
		}
		count := 0
		_ = iface.Neighbours.Foreach(func(n *babel.Neighbour) error {
			count++
			stats := n.DelayStats()
			now := time.Now()
			rtt := stats.Mean.Microseconds()
			jitter := stats.Jitter().Microseconds()
			age := stats.Age(now).Milliseconds()
			confidence := stats.Confidence(now, babel.DefaultDelayWarmupSamples, e.settings.DelaySampleMaxAge())
			fresh := stats.Fresh(now, babel.DefaultDelayWarmupSamples, e.settings.DelaySampleMaxAge())
			peers = append(peers, model.PeerStatus{
				Protocol: "babel", PublicKey: n.Address.String(), Endpoint: iface.Name,
				RTTMicros: &rtt, JitterMicros: &jitter, MetricAgeMillis: &age,
				MetricConfidence: &confidence, MetricFresh: &fresh,
			})
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
	e.reconcileMu.Lock()
	defer e.reconcileMu.Unlock()
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
	table := int(h.engine.eventTable.Load())
	select {
	case h.engine.backend.events <- core.BackendEvent{Type: eventType, RouteTable: table}:
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
	if scoreBest <= 0 || math.IsNaN(scoreBest) || math.IsInf(scoreBest, 0) {
		return 256
	}
	if candidate <= 0 || math.IsNaN(candidate) || math.IsInf(candidate, 0) {
		return 1
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
type babelSourceSelector func(prefix netip.Prefix) net.IP

func (b *Backend) resolveBabelLink(name string) (int, error) {
	link, err := b.linkByName(name)
	if err != nil {
		return 0, fmt.Errorf("lookup Babel next-hop interface %s: %w", name, err)
	}
	return link.Attrs().Index, nil
}

func babelRoutesToNetlink(table int, selected []babel.SelectedRoute, resolve babelLinkResolver, score func(babel.SelectedRoute) float64, source babelSourceSelector) ([]netlink.Route, error) {
	byPrefix := make(map[netip.Prefix][]babel.SelectedRoute)
	type forwardingPath struct {
		interfaceName string
		nextHop       netip.Addr
	}
	seen := make(map[netip.Prefix]map[forwardingPath]struct{})
	for _, route := range selected {
		if route.Local {
			continue
		}
		prefix := route.Prefix.Masked()
		key := forwardingPath{interfaceName: route.Interface, nextHop: route.NextHop.Unmap()}
		if seen[prefix] == nil {
			seen[prefix] = make(map[forwardingPath]struct{})
		}
		if _, duplicate := seen[prefix][key]; duplicate {
			continue
		}
		seen[prefix][key] = struct{}{}
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
			Scope:    netlink.SCOPE_UNIVERSE,
			Priority: babelRoutePriority,
		}
		if source != nil {
			base.Src = source(prefix)
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

// babelRouteOwned reports whether a route in the Babel table belongs to
// this engine. The kernel does not persist realms for IPv6 routes and
// rejects them outright on IPv4 multipath routes, so realm is not a
// reliable Babel ownership tag. Babel routes are therefore identified by
// the TH protocol plus the Babel route priority (other TH backends use
// priority 0 or 1024).
func babelRouteOwned(route netlink.Route, table int) bool {
	return route.Protocol == managedRouteProtocol && route.Priority == babelRoutePriority && route.Table == table
}

// babelRouteDiff compares the routes currently present in a table against
// the desired Babel routes. It returns the routes to replace, the owned
// routes to remove, or an ownership error when a desired prefix is already
// claimed by a route TH does not own.
func babelRouteDiff(current, desired []netlink.Route, table int) (replace, remove []netlink.Route, err error) {
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
			if !babelRouteOwned(existing, table) {
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
			if babelRouteOwned(route, table) {
				remove = append(remove, route)
			}
		}
	}
	return replace, remove, nil
}

func equalBabelManagedRoute(current, desired netlink.Route) bool {
	if current.Table != desired.Table || current.Priority != desired.Priority ||
		current.Scope != desired.Scope || current.Protocol != desired.Protocol {
		return false
	}
	if !ipEqual(current.Gw, desired.Gw) || !ipEqual(current.Src, desired.Src) || current.LinkIndex != desired.LinkIndex {
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

// multipathWeightFingerprint serialises the installed weights of a
// multipath route so weight-only changes can be compared across reconciles.
func multipathWeightFingerprint(route netlink.Route) string {
	parts := make([]string, 0, len(route.MultiPath))
	for _, nextHop := range route.MultiPath {
		parts = append(parts, strconv.Itoa(nextHop.Hops+1))
	}
	return strings.Join(parts, ",")
}

func currentMultipathWeightFingerprint(current []netlink.Route, key string) string {
	for _, route := range current {
		if routeKey(route) == key && len(route.MultiPath) > 0 {
			return multipathWeightFingerprint(route)
		}
	}
	return ""
}

// weightsWithinTolerance reports whether every weight in the new fingerprint
// is within the 10% tolerance of the previously installed one.
func weightsWithinTolerance(previous, current string) bool {
	oldWeights, oldTotal, ok := parseWeightFingerprint(previous)
	if !ok {
		return false
	}
	newWeights, newTotal, ok := parseWeightFingerprint(current)
	if !ok || len(oldWeights) != len(newWeights) {
		return false
	}
	for i := range oldWeights {
		oldShare := float64(oldWeights[i]) / float64(oldTotal)
		newShare := float64(newWeights[i]) / float64(newTotal)
		larger := max(oldShare, newShare)
		if larger > 0 && math.Abs(oldShare-newShare)/larger > 0.10 {
			return false
		}
	}
	return true
}

func parseWeightFingerprint(fingerprint string) ([]int, int, bool) {
	if fingerprint == "" {
		return nil, 0, false
	}
	parts := strings.Split(fingerprint, ",")
	weights := make([]int, len(parts))
	total := 0
	for i, part := range parts {
		weight, err := strconv.Atoi(part)
		if err != nil || weight < 1 || weight > 256 {
			return nil, 0, false
		}
		weights[i] = weight
		total += weight
	}
	return weights, total, total > 0
}

// babelWeightOnlyChange reports whether a replacement differs from the
// currently installed route only in its multipath weights (same next hops,
// same structure). Such updates are candidates for cooldown gating.
func babelWeightOnlyChange(current []netlink.Route, desired netlink.Route) bool {
	for _, existing := range current {
		if routeKey(existing) != routeKey(desired) {
			continue
		}
		if existing.Protocol != desired.Protocol ||
			existing.Priority != desired.Priority || existing.Scope != desired.Scope {
			return false
		}
		if len(existing.MultiPath) != len(desired.MultiPath) {
			return false
		}
		if !ipEqual(existing.Gw, desired.Gw) || !ipEqual(existing.Src, desired.Src) || existing.LinkIndex != desired.LinkIndex {
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

// localOriginAddresses returns usable local addresses covered by a prefix
// currently originated by this speaker. Explicit aggregate advertisements are
// allowed, but they only influence source selection when a matching address
// actually exists on the node.
func (e *babelEngine) localOriginAddresses() []netip.Addr {
	if len(e.advertised) == 0 {
		return nil
	}
	links, err := e.backend.netlink.LinkList()
	if err != nil {
		slog.Warn("Cannot enumerate local addresses for Babel preferred source", "error", err)
		return nil
	}
	seen := make(map[netip.Addr]struct{})
	for _, link := range links {
		addresses, err := e.backend.netlink.AddrList(link, netlink.FAMILY_ALL)
		if err != nil {
			continue
		}
		for _, address := range addresses {
			if address.IPNet == nil || address.Flags&(unix.IFA_F_TENTATIVE|unix.IFA_F_DADFAILED|unix.IFA_F_DEPRECATED) != 0 {
				continue
			}
			candidate, ok := netip.AddrFromSlice(address.IPNet.IP)
			if !ok {
				continue
			}
			candidate = candidate.Unmap()
			if !candidate.IsGlobalUnicast() || candidate.IsLoopback() {
				continue
			}
			for prefix := range e.advertised {
				if prefix.Contains(candidate) {
					seen[candidate] = struct{}{}
					break
				}
			}
		}
	}
	result := make([]netip.Addr, 0, len(seen))
	for address := range seen {
		result = append(result, address)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Compare(result[j]) < 0 })
	return result
}

func selectBabelPreferredSource(destination netip.Prefix, candidates []netip.Addr) net.IP {
	target := destination.Addr().Unmap()
	bestBits := -1
	var best netip.Addr
	for _, candidate := range candidates {
		candidate = candidate.Unmap()
		if !candidate.IsValid() || !candidate.IsGlobalUnicast() || candidate.IsLoopback() || candidate.BitLen() != target.BitLen() {
			continue
		}
		matched := commonAddressPrefixBits(candidate, target)
		if matched > bestBits || matched == bestBits && (!best.IsValid() || candidate.Compare(best) < 0) {
			best, bestBits = candidate, matched
		}
	}
	if !best.IsValid() {
		return nil
	}
	return net.IP(best.AsSlice())
}

func commonAddressPrefixBits(a, b netip.Addr) int {
	if a.BitLen() != b.BitLen() {
		return -1
	}
	left, right := a.AsSlice(), b.AsSlice()
	matched := 0
	for i := range left {
		if left[i] == right[i] {
			matched += 8
			continue
		}
		return matched + bits.LeadingZeros8(left[i]^right[i])
	}
	return matched
}

func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}
