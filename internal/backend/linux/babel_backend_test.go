//go:build linux

package linux

import (
	"encoding/hex"
	"errors"
	"math"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TunnelHelper/TH/internal/babel"
	"github.com/TunnelHelper/TH/internal/config"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestBabelWeightFromScores(t *testing.T) {
	cases := []struct {
		best, candidate float64
		want            int
	}{
		{1000, 1000, 256}, // equal scores -> equal weight
		{1000, 100, 26},   // 10:1 -> weight 26
		{1000, 1, 1},      // extremely bad path keeps a minimal weight
		{0, 1000, 256},    // missing best signal -> default weight
		{1000, 0, 1},      // invalid candidate signal -> minimum safe weight
	}
	for _, tc := range cases {
		if got := babelWeightFromScores(tc.best, tc.candidate); got != tc.want {
			t.Errorf("babelWeightFromScores(%g, %g) = %d, want %d", tc.best, tc.candidate, got, tc.want)
		}
	}
}

func TestBabelWeightFromScoresBandwidthLatencyExample(t *testing.T) {
	// 1 Mbps / 1 ms vs 1000 Mbps / 1000 ms: bandwidth/RTT scores are equal,
	// so the weights must be equal under the default exponents (1, 1).
	scoreFast := 1.0 / 0.001 // 1000
	scoreWide := 1000.0 / 1.0
	if scoreFast != scoreWide {
		t.Fatalf("scores must be equal for the asymmetric example: %g vs %g", scoreFast, scoreWide)
	}
	if got := babelWeightFromScores(scoreWide, scoreFast); got != 256 {
		t.Fatalf("equal scores must yield equal weights, got %d", got)
	}
}

func TestBabelPathScoreEndToEnd(t *testing.T) {
	maxAge := 10 * time.Second
	// End-to-end values win: bottleneck 10, path RTT 1000 us.
	route := babel.SelectedRoute{PathRTTMicros: 1000, PathJitterMicros: 0, PathMetricAgeMillis: 0, PathMetricConfidence: math.MaxUint16}
	score := babelPathScore(10, route, babel.DelayStats{}, maxAge, 1, 1, 0)
	if score != (10.0/babelReferenceBandwidthMbps)/(1000.0/babelReferenceRTTMicros) {
		t.Fatalf("unexpected dimensionless end-to-end score %g", score)
	}

	// Missing path RTT falls back to the local first-hop RTT.
	local := babel.DelayStats{Mean: 500 * time.Microsecond, Samples: 4, LastSample: time.Now()}
	fallback := babelPathScore(1000, babel.SelectedRoute{PathRTTMicros: -1}, local, maxAge, 1, 1, 0)
	if fallback != (1000.0/babelReferenceBandwidthMbps)/(500.0/babelReferenceRTTMicros) {
		t.Fatalf("unexpected dimensionless fallback score %g", fallback)
	}

	// Unknown RTT entirely uses the same conservative denominator as every
	// other unknown candidate instead of receiving a unit-dependent boost.
	noRTT := babelPathScore(1000, babel.SelectedRoute{PathRTTMicros: -1}, babel.DelayStats{}, maxAge, 2, 1, 0)
	wantNoRTT := math.Pow(1000.0/babelReferenceBandwidthMbps, 2) /
		(babelUnknownRTTMicros / babelReferenceRTTMicros) * babelMinimumConfidence
	if noRTT != wantNoRTT {
		t.Fatalf("unknown-RTT score = %g, want %g", noRTT, wantNoRTT)
	}
}

func TestBabelPathScorePenalisesJitterAndStaleMetrics(t *testing.T) {
	maxAge := 10 * time.Second
	stable := babel.SelectedRoute{PathRTTMicros: 10_000, PathJitterMicros: 0, PathMetricAgeMillis: 0, PathMetricConfidence: math.MaxUint16}
	shaky := stable
	shaky.PathJitterMicros = 5_000
	stableScore := babelPathScore(100, stable, babel.DelayStats{}, maxAge, 1, 1, 1)
	shakyScore := babelPathScore(100, shaky, babel.DelayStats{}, maxAge, 1, 1, 1)
	if shakyScore != stableScore/2 {
		t.Fatalf("one reference jitter must halve score: stable=%g shaky=%g", stableScore, shakyScore)
	}
	stale := stable
	stale.PathMetricAgeMillis = maxAge.Milliseconds()
	local := babel.DelayStats{Mean: time.Millisecond, Samples: 4, LastSample: time.Now()}
	staleScore := babelPathScore(100, stale, local, maxAge, 1, 1, 1)
	if staleScore >= stableScore {
		t.Fatalf("stale metrics must receive a lower conservative score: stale=%g stable=%g", staleScore, stableScore)
	}
	if want := babelPathScore(100, babel.SelectedRoute{PathRTTMicros: -1}, babel.DelayStats{}, maxAge, 1, 1, 1); staleScore != want {
		t.Fatalf("known stale path used first-hop fallback: stale=%g conservative=%g", staleScore, want)
	}
}

func TestBabelEnginePerTunnelBalance(t *testing.T) {
	bandwidthBias := 1.0
	engine := &babelEngine{
		settings: config.BabelSettings{WeightBandwidthExponent: 2, WeightRTTExponent: 2},
		tunnels: map[string]babelTunnel{
			"bandwidth-tunnel": {interfaceName: "wg0", balance: &bandwidthBias},
			"default-tunnel":   {interfaceName: "wg1"},
		},
	}

	alpha, beta := engine.exponentsFor("wg0")
	if alpha != 2 || beta != 0 {
		t.Fatalf("per-tunnel balance exponents = (%v, %v), want (2, 0)", alpha, beta)
	}
	alpha, beta = engine.exponentsFor("wg1")
	if alpha != 2 || beta != 2 {
		t.Fatalf("default exponents = (%v, %v), want the daemon defaults (2, 2)", alpha, beta)
	}

	if balance := engine.tunnels["bandwidth-tunnel"].balance; balance == nil || *balance != 1 {
		t.Fatalf("fixture balance was not stored: %v", balance)
	}
}

func TestWeightsWithinTolerance(t *testing.T) {
	if !weightsWithinTolerance("256,26", "240,25") {
		t.Fatal("small weight changes must be within tolerance")
	}
	if weightsWithinTolerance("256,26", "200,26") {
		t.Fatal("a 22% weight change must exceed tolerance")
	}
	if weightsWithinTolerance("256,26", "256") {
		t.Fatal("fingerprints with different sizes must differ")
	}
}

func TestBabelSettingsFingerprint(t *testing.T) {
	engine := &babelEngine{
		settings: config.Defaults().Babel,
		tunnels:  map[string]babelTunnel{},
		routerID: [8]byte{1},
	}
	base := engine.fingerprintLocked()

	// Data-plane settings (advertisement filters, weight exponents, the
	// bottleneck penalty) must NOT trigger a speaker rebuild.
	engine.settings.Advertise.Include = []netip.Prefix{netip.MustParsePrefix("8.0.0.0/8")}
	engine.settings.WeightBandwidthExponent = 2
	engine.settings.WeightRTTExponent = 0.5
	engine.settings.WeightBottleneckPenalty = 5
	if got := engine.fingerprintLocked(); got != base {
		t.Fatalf("data-plane settings changed the speaker fingerprint: %s != %s", got, base)
	}

	// Protocol-affecting settings must trigger a rebuild.
	engine.routerID = [8]byte{2}
	if got := engine.fingerprintLocked(); got == base {
		t.Fatal("router id change must trigger a speaker rebuild")
	}
}

func TestExplicitWeightPolicyChangeBypassesNoiseCooldown(t *testing.T) {
	engine := &babelEngine{forceWeightRefresh: true}
	current := netlink.Route{
		Dst: prefixToIPNet(netip.MustParsePrefix("10.8.0.0/24")), Table: 254,
		Protocol: managedRouteProtocol, Priority: babelRoutePriority, Scope: netlink.SCOPE_UNIVERSE,
		MultiPath: []*netlink.NexthopInfo{
			{LinkIndex: 1, Hops: 255, Gw: net.ParseIP("fe80::1")},
			{LinkIndex: 2, Hops: 127, Gw: net.ParseIP("fe80::2")},
		},
	}
	desired := current
	desired.MultiPath = []*netlink.NexthopInfo{
		{LinkIndex: 1, Hops: 255, Gw: net.ParseIP("fe80::1")},
		{LinkIndex: 2, Hops: 31, Gw: net.ParseIP("fe80::2")},
	}
	if !babelWeightOnlyChange([]netlink.Route{current}, desired) {
		t.Fatal("fixture must differ only in weights")
	}
	if shouldDampBabelWeightChange(engine.forceWeightRefresh, []netlink.Route{current}, desired) {
		t.Fatal("explicit policy refresh must bypass automatic weight damping")
	}
	if !shouldDampBabelWeightChange(false, []netlink.Route{current}, desired) {
		t.Fatal("automatic quality-only change must retain weight damping")
	}
}

func TestConfiguredBabelInterfaces(t *testing.T) {
	engine := &babelEngine{
		tunnels: map[string]babelTunnel{
			"t1": {interfaceName: "wg-prod1"},
			"t2": {interfaceName: "wg-prod2"},
		},
		settings: config.BabelSettings{
			Interfaces: map[string]config.BabelExternalInterface{
				"gre-ext0": {},
			},
		},
	}
	got := engine.configuredBabelInterfaces()
	want := map[string]string{
		"wg-prod1": "tunnel",
		"wg-prod2": "tunnel",
		"gre-ext0": "external",
	}
	if len(got) != len(want) {
		t.Fatalf("configured interfaces = %v, want %v", got, want)
	}
	for name, source := range want {
		if got[name] != source {
			t.Fatalf("interface %s source = %q, want %q", name, got[name], source)
		}
	}
}

func TestBabelWeightStateRequiresConfirmationAndPerPrefixCooldown(t *testing.T) {
	now := time.Now()
	state := babelWeightState{installed: "256,128"}
	if state.shouldApply("256,64", now) {
		t.Fatal("first significant observation must not apply")
	}
	if !state.shouldApply("256,64", now.Add(time.Second)) {
		t.Fatal("second consistent observation must apply when no cooldown exists")
	}
	state.applied("256,64", now.Add(time.Second))
	if state.shouldApply("256,32", now.Add(2*time.Second)) {
		t.Fatal("first post-install observation must not apply")
	}
	if state.shouldApply("256,32", now.Add(3*time.Second)) {
		t.Fatal("per-prefix cooldown must suppress confirmed changes")
	}
	if !state.shouldApply("256,32", now.Add(babelWeightCooldown+time.Second)) {
		t.Fatal("pending confirmed change must apply when its prefix cooldown expires")
	}
}

func TestBabelWeightOnlyChange(t *testing.T) {
	realm := 0x40000001
	key := netip.MustParsePrefix("10.7.0.0/24")
	base := netlink.Route{
		Dst: prefixToIPNet(key), Table: 254, Protocol: managedRouteProtocol, Realm: realm,
		Priority: 1, Scope: netlink.SCOPE_UNIVERSE,
		MultiPath: []*netlink.NexthopInfo{
			{LinkIndex: 1, Hops: 255, Gw: net.ParseIP("fe80::1")},
			{LinkIndex: 2, Hops: 25, Gw: net.ParseIP("fe80::2")},
		},
	}
	weightOnly := base
	weightOnly.MultiPath[1].Hops = 50
	if !babelWeightOnlyChange([]netlink.Route{base}, weightOnly) {
		t.Fatal("weight-only change must be detected")
	}

	structural := base
	structural.MultiPath = []*netlink.NexthopInfo{
		{LinkIndex: 1, Hops: 255, Gw: net.ParseIP("fe80::1")},
		{LinkIndex: 2, Hops: 25, Gw: net.ParseIP("fe80::3")},
	}
	if babelWeightOnlyChange([]netlink.Route{base}, structural) {
		t.Fatal("structural change must not be treated as weight-only")
	}
}

func TestBabelRoutesToNetlink(t *testing.T) {
	resolve := func(name string) (int, error) {
		if name == "wg0" {
			return 42, nil
		}
		return 0, nil
	}
	score := func(route babel.SelectedRoute) float64 {
		if route.Interface == "wg0" {
			return 1000.0
		}
		return 0
	}
	selected := []babel.SelectedRoute{
		{Prefix: netip.MustParsePrefix("10.1.0.0/24"), NextHop: netip.MustParseAddr("fe80::1"), Interface: "wg0", Metric: 512},
		{Prefix: netip.MustParsePrefix("10.1.0.0/24"), NextHop: netip.MustParseAddr("fe80::2"), Interface: "wg0", Metric: 2816},
		{Prefix: netip.MustParsePrefix("10.2.0.0/24"), NextHop: netip.MustParseAddr("fe80::3"), Interface: "wg0", Metric: 512},
		{Prefix: netip.MustParsePrefix("10.3.0.0/24"), NextHop: netip.Addr{}, Interface: "", Metric: 0, Local: true},
	}

	routes, err := babelRoutesToNetlink(254, selected, resolve, score)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 2 {
		t.Fatalf("local routes must be skipped, got %d routes", len(routes))
	}

	var multi netlink.Route
	for _, route := range routes {
		if len(route.MultiPath) == 2 {
			multi = route
			break
		}
	}
	if len(multi.MultiPath) == 0 {
		t.Fatal("multipath route not found")
	}
	if multi.MultiPath[0].LinkIndex != 42 || multi.MultiPath[1].LinkIndex != 42 {
		t.Error("nexthop link index must come from the resolver")
	}
	if multi.MultiPath[0].Hops != 255 { // weight 256
		t.Errorf("primary hop weight = %d, want 256", multi.MultiPath[0].Hops+1)
	}
	if multi.MultiPath[1].Hops != 255 { // equal bandwidth -> equal weight
		t.Errorf("candidate hop weight = %d, want 256", multi.MultiPath[1].Hops+1)
	}
	if multi.Protocol != managedRouteProtocol || multi.Priority != babelRoutePriority {
		t.Error("routes must carry TH ownership tags")
	}
	if multi.Realm != 0 {
		t.Error("Babel routes must not set realm: the kernel rejects it on IPv4 multipath routes")
	}
}

func TestRouteHealthReportsDesiredAndInstalledWeights(t *testing.T) {
	settings := config.Defaults().Babel
	engine := &babelEngine{
		settings: settings,
		tunnels: map[string]babelTunnel{
			"a": {interfaceName: "wg0", bandwidthMbps: 100},
			"b": {interfaceName: "wg1", bandwidthMbps: 100},
		},
		weightStates: make(map[string]*babelWeightState),
	}
	prefix := netip.MustParsePrefix("10.9.0.0/24")
	selected := []babel.SelectedRoute{
		{Prefix: prefix, NextHop: netip.MustParseAddr("fe80::1"), Interface: "wg0", Metric: 100, BottleneckMbps: 100, PathRTTMicros: 10_000, PathJitterMicros: 0, PathMetricAgeMillis: 0, PathMetricConfidence: math.MaxUint16},
		{Prefix: prefix, NextHop: netip.MustParseAddr("fe80::2"), Interface: "wg1", Metric: 100, BottleneckMbps: 100, PathRTTMicros: 20_000, PathJitterMicros: 0, PathMetricAgeMillis: 0, PathMetricConfidence: math.MaxUint16},
	}
	key := routeKey(netlink.Route{Table: 254, Dst: prefixToIPNet(prefix)})
	engine.weightStates[key] = &babelWeightState{installed: "256,100"}
	health := engine.routeHealthLocked(selected, 254)
	if len(health) != 2 || health[0].InstalledWeight != 256 || health[1].InstalledWeight != 100 {
		t.Fatalf("installed weights missing from health: %+v", health)
	}
	if health[0].DesiredWeight != 256 || health[1].DesiredWeight >= health[0].DesiredWeight {
		t.Fatalf("desired weights do not reflect RTT score: %+v", health)
	}
}

func TestParseBabelRouterID(t *testing.T) {
	id, err := parseBabelRouterID("0011223344556677")
	if err != nil {
		t.Fatal(err)
	}
	if id[0] != 0x00 || id[7] != 0x77 {
		t.Errorf("unexpected router id: %x", id)
	}
	if _, err := parseBabelRouterID("zz"); err == nil {
		t.Error("non-hex router id must fail")
	}
	if _, err := parseBabelRouterID("00112233"); err == nil {
		t.Error("short router id must fail")
	}
	for _, reserved := range []string{"0000000000000000", "ffffffffffffffff"} {
		if _, err := parseBabelRouterID(reserved); err == nil {
			t.Errorf("reserved router id %s must fail", reserved)
		}
	}
}

func TestLoadBabelRouterIDGeneratesStableIDWhenUnconfigured(t *testing.T) {
	stateDir := t.TempDir()
	first, err := loadBabelRouterID("", stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if first == [8]byte{} {
		t.Fatal("empty configuration must auto-generate a router id")
	}
	second, err := loadBabelRouterID("", stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if second != first {
		t.Fatalf("generated router id is not stable across loads: %x vs %x", first, second)
	}
	persisted, err := os.ReadFile(filepath.Join(stateDir, "babel-router-id"))
	if err != nil {
		t.Fatalf("generated router id was not persisted: %v", err)
	}
	if got := hex.EncodeToString(first[:]); string(persisted) != got {
		t.Fatalf("persisted router id = %q, want %q", persisted, got)
	}

	configured, err := loadBabelRouterID("aabbccddeeff0011", stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if configured[0] != 0xaa || configured[7] != 0x11 {
		t.Fatalf("explicit configuration must win over the generated id: %x", configured)
	}
}

func TestRefreshRouterIDAppliesConfiguredAndPersistedID(t *testing.T) {
	stateDir := t.TempDir()
	engine := &babelEngine{
		backend: &Backend{settings: config.Settings{StateDir: stateDir}},
	}
	persisted, err := loadBabelRouterID("", stateDir)
	if err != nil {
		t.Fatal(err)
	}
	engine.routerID = persisted

	next := config.Defaults().Babel
	next.RouterID = "aabbccddeeff0011"
	if err := engine.refreshRouterIDLocked(next); err != nil {
		t.Fatal(err)
	}
	if got := engine.health().RouterID; got != "aabbccddeeff0011" {
		t.Fatalf("configured router id was not applied, got %q", got)
	}

	// Clearing the field returns to the persisted auto-generated ID.
	next.RouterID = ""
	if err := engine.refreshRouterIDLocked(next); err != nil {
		t.Fatal(err)
	}
	if got := engine.health().RouterID; got != hex.EncodeToString(persisted[:]) {
		t.Fatalf("clearing router id must restore the persisted id, got %q", got)
	}
}

func TestNormalizeBabelAddress(t *testing.T) {
	v4 := netip.MustParseAddr("192.168.1.1")
	normalised := normalizeBabelAddress(v4)
	if !normalised.Is4In6() {
		t.Errorf("IPv4 neighbour must be normalised to 4-in-6, got %s", normalised)
	}
	v6 := netip.MustParseAddr("fe80::1")
	if got := normalizeBabelAddress(v6); got != v6 {
		t.Errorf("IPv6 neighbour must stay unchanged, got %s", got)
	}
}

func TestBabelRouteDiffOwnership(t *testing.T) {
	key := netip.MustParsePrefix("10.5.0.0/24")
	owned := netlink.Route{Dst: prefixToIPNet(key), Table: 254, Protocol: managedRouteProtocol, Priority: 1, Scope: netlink.SCOPE_UNIVERSE}
	foreign := netlink.Route{Dst: prefixToIPNet(key), Table: 254, Protocol: 4, Realm: 0, Priority: 0}

	replace, remove, err := babelRouteDiff([]netlink.Route{foreign}, []netlink.Route{owned}, 254)
	if !errors.Is(err, ErrOwnershipConflict) {
		t.Fatalf("expected ownership conflict, got %v (replace=%d remove=%d)", err, len(replace), len(remove))
	}

	// A TH-protocol route with a different priority (WireGuard/SRv6 use 0
	// or 1024) is not Babel-owned and must conflict.
	otherBackend := owned
	otherBackend.Priority = 0
	_, _, err = babelRouteDiff([]netlink.Route{otherBackend}, []netlink.Route{owned}, 254)
	if !errors.Is(err, ErrOwnershipConflict) {
		t.Fatalf("TH route with a foreign priority must conflict, got %v", err)
	}

	replace, remove, err = babelRouteDiff([]netlink.Route{owned}, []netlink.Route{owned}, 254)
	if err != nil || len(replace) != 0 || len(remove) != 0 {
		t.Fatalf("unchanged owned route must be a no-op: replace=%d remove=%d err=%v", len(replace), len(remove), err)
	}

	changed := owned
	changed.Priority = 2
	replace, _, err = babelRouteDiff([]netlink.Route{owned}, []netlink.Route{changed}, 254)
	if err != nil || len(replace) != 1 {
		t.Fatalf("changed owned route must be replaced: replace=%d err=%v", len(replace), err)
	}

	stale := owned
	stale.Dst = prefixToIPNet(netip.MustParsePrefix("10.6.0.0/24"))
	foreignStale := foreign
	foreignStale.Dst = stale.Dst
	_, remove, err = babelRouteDiff([]netlink.Route{stale, foreignStale}, []netlink.Route{owned}, 254)
	if err != nil || len(remove) != 1 {
		t.Fatalf("only owned stale routes must be removed: remove=%d err=%v", len(remove), err)
	}
}

func TestBabelRouteOwnedIPv6ToleratesDroppedRealm(t *testing.T) {
	route := netlink.Route{
		Dst: prefixToIPNet(netip.MustParsePrefix("2001:db8::/48")), Table: 100,
		Protocol: managedRouteProtocol, Priority: babelRoutePriority,
	}
	if !babelRouteOwned(route, 100) {
		t.Fatal("IPv6 Babel route with kernel-dropped realm must be owned")
	}
	route.Priority = 0
	if babelRouteOwned(route, 100) {
		t.Fatal("route with a non-Babel priority must not be owned")
	}
	route = netlink.Route{Table: 100, Protocol: managedRouteProtocol, Priority: babelRoutePriority}
	if !babelRouteOwned(route, 100) {
		t.Fatal("IPv4 multipath Babel route without realm must be owned")
	}
	if babelRouteOwned(netlink.Route{Table: 200, Protocol: managedRouteProtocol, Priority: babelRoutePriority}, 100) {
		t.Fatal("route in another table must not be owned")
	}
}

func TestWgLinkLocalIsDeterministic(t *testing.T) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub := key.PublicKey().String()
	first, ok := wgLinkLocal(pub)
	if !ok {
		t.Fatal("valid public key must produce a link-local address")
	}
	second, _ := wgLinkLocal(pub)
	if first != second {
		t.Fatalf("link-local address must be deterministic: %s != %s", first, second)
	}
	if !first.IsLinkLocalUnicast() {
		t.Fatalf("derived address %s must be link-local unicast", first)
	}
	if _, ok := wgLinkLocal("not-a-key"); ok {
		t.Fatal("invalid public key must not produce an address")
	}
}

func TestFilterAdvertisedPrefix(t *testing.T) {
	include := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	exclude := []netip.Prefix{netip.MustParsePrefix("10.64.0.0/10")}
	cases := []struct {
		prefix string
		want   bool
	}{
		{"10.1.2.0/24", true},
		{"10.64.0.0/10", false},
		{"172.16.0.0/12", false},
		{"fe80::1/128", false},
		{"127.0.0.0/8", false},
		{"::1/128", false},
		{"2001:db8::/32", false},
	}
	for _, tc := range cases {
		if got := filterAdvertisedPrefix(netip.MustParsePrefix(tc.prefix), include, exclude); got != tc.want {
			t.Errorf("filter(%s) = %v, want %v", tc.prefix, got, tc.want)
		}
	}
}
