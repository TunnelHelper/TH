//go:build linux

package linux

import (
	"errors"
	"net"
	"net/netip"
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
		{1000, 0, 256},    // missing candidate signal -> default weight
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
	// End-to-end values win: bottleneck 10, path RTT 1000 us.
	score := babelPathScore(10, 1000, 0, false, 1, 1)
	if score != 10.0/1000.0 {
		t.Fatalf("end-to-end score = %g, want %g", score, 10.0/1000.0)
	}

	// Missing path RTT falls back to the local first-hop RTT.
	fallback := babelPathScore(1000, -1, 500*time.Microsecond, true, 1, 1)
	if fallback != 1000.0/500.0 {
		t.Fatalf("fallback score = %g, want %g", fallback, 1000.0/500.0)
	}

	// Unknown RTT entirely: bandwidth term alone.
	noRTT := babelPathScore(1000, -1, 0, false, 2, 1)
	if noRTT != 1000*1000 {
		t.Fatalf("bandwidth-only score = %g, want %g", noRTT, float64(1000*1000))
	}
}

func TestWeightsWithinTolerance(t *testing.T) {
	if !weightsWithinTolerance("255,25", "240,27") {
		t.Fatal("small weight changes must be within tolerance")
	}
	if weightsWithinTolerance("255,25", "200,25") {
		t.Fatal("a 22% weight change must exceed tolerance")
	}
	if weightsWithinTolerance("255,25", "255") {
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

func TestBabelWeightEqualTolerance(t *testing.T) {
	cases := []struct {
		current, desired int
		equal            bool
	}{
		{255, 255, true},
		{255, 240, true},  // 6% difference within tolerance
		{255, 200, false}, // 22% difference must differ
		{3, 4, true},      // single-unit difference always tolerated
		{0, 1, true},
	}
	for _, tc := range cases {
		if got := babelWeightEqual(tc.current, tc.desired); got != tc.equal {
			t.Errorf("babelWeightEqual(%d, %d) = %v, want %v", tc.current, tc.desired, got, tc.equal)
		}
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

	realm := 0x40000001
	routes, err := babelRoutesToNetlink(254, selected, resolve, score, realm)
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
	if multi.Protocol != managedRouteProtocol || multi.Realm != realm {
		t.Error("routes must carry TH ownership tags")
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
	realm := 0x40000001
	key := netip.MustParsePrefix("10.5.0.0/24")
	owned := netlink.Route{Dst: prefixToIPNet(key), Table: 254, Protocol: managedRouteProtocol, Realm: realm, Priority: 1, Scope: netlink.SCOPE_UNIVERSE}
	foreign := netlink.Route{Dst: prefixToIPNet(key), Table: 254, Protocol: 4, Realm: 0, Priority: 0}

	replace, remove, err := babelRouteDiff([]netlink.Route{foreign}, []netlink.Route{owned}, realm)
	if !errors.Is(err, ErrOwnershipConflict) {
		t.Fatalf("expected ownership conflict, got %v (replace=%d remove=%d)", err, len(replace), len(remove))
	}

	replace, remove, err = babelRouteDiff([]netlink.Route{owned}, []netlink.Route{owned}, realm)
	if err != nil || len(replace) != 0 || len(remove) != 0 {
		t.Fatalf("unchanged owned route must be a no-op: replace=%d remove=%d err=%v", len(replace), len(remove), err)
	}

	changed := owned
	changed.Priority = 2
	replace, _, err = babelRouteDiff([]netlink.Route{owned}, []netlink.Route{changed}, realm)
	if err != nil || len(replace) != 1 {
		t.Fatalf("changed owned route must be replaced: replace=%d err=%v", len(replace), err)
	}

	stale := owned
	stale.Dst = prefixToIPNet(netip.MustParsePrefix("10.6.0.0/24"))
	foreignStale := foreign
	foreignStale.Dst = stale.Dst
	_, remove, err = babelRouteDiff([]netlink.Route{stale, foreignStale}, []netlink.Route{owned}, realm)
	if err != nil || len(remove) != 1 {
		t.Fatalf("only owned stale routes must be removed: remove=%d err=%v", len(remove), err)
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
