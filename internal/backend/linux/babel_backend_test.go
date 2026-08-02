//go:build linux

package linux

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/TunnelHelper/TH/internal/babel"
	"github.com/TunnelHelper/TH/internal/model"
	"github.com/vishvananda/netlink"
)

func TestBabelMultipathWeight(t *testing.T) {
	cases := []struct {
		primary, candidate uint16
		want               int
	}{
		{512, 512, 256}, // equal cost -> equal weight
		{512, 2816, 46}, // 1 Gbps vs 100 Mbps
		{512, 65534, 2}, // extremely slow link keeps a minimal weight
		{0, 512, 256},   // degenerate primary -> equal
		{512, 100, 256}, // candidate cannot be cheaper than primary
	}
	for _, tc := range cases {
		if got := babelMultipathWeight(tc.primary, tc.candidate); got != tc.want {
			t.Errorf("babelMultipathWeight(%d, %d) = %d, want %d", tc.primary, tc.candidate, got, tc.want)
		}
	}
}

func TestBabelRoutesToNetlink(t *testing.T) {
	record := model.Tunnel{
		ID:   "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
		Kind: model.KindBabel,
		Spec: model.Spec{Babel: &model.BabelSpec{}},
	}
	resolve := func(name string) (int, error) {
		if name == "wg0" {
			return 42, nil
		}
		return 0, nil
	}
	selected := []babel.SelectedRoute{
		{Prefix: netip.MustParsePrefix("10.1.0.0/24"), NextHop: netip.MustParseAddr("fe80::1"), Interface: "wg0", Metric: 512},
		{Prefix: netip.MustParsePrefix("10.1.0.0/24"), NextHop: netip.MustParseAddr("fe80::2"), Interface: "wg0", Metric: 2816},
		{Prefix: netip.MustParsePrefix("10.2.0.0/24"), NextHop: netip.MustParseAddr("fe80::3"), Interface: "wg0", Metric: 512},
		{Prefix: netip.MustParsePrefix("10.3.0.0/24"), NextHop: netip.Addr{}, Interface: "", Metric: 0, Local: true},
	}

	routes, err := babelRoutesToNetlink(record, 254, selected, resolve)
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
	if len(multi.MultiPath) != 2 {
		t.Fatalf("equal-prefix routes must be grouped into multipath, got %d nexthops", len(multi.MultiPath))
	}
	if multi.MultiPath[0].LinkIndex != 42 || multi.MultiPath[1].LinkIndex != 42 {
		t.Error("nexthop link index must come from the resolver")
	}
	if multi.MultiPath[0].Hops != 255 { // weight 256
		t.Errorf("primary hop weight = %d, want 256", multi.MultiPath[0].Hops+1)
	}
	if multi.MultiPath[1].Hops != 45 { // weight 46
		t.Errorf("candidate hop weight = %d, want 46", multi.MultiPath[1].Hops+1)
	}
	if multi.Protocol != managedRouteProtocol || multi.Realm != model.ManagedRouteRealm(record) {
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

func TestBabelRouteDiffOwnership(t *testing.T) {
	realm := 0x40000001
	key := netip.MustParsePrefix("10.5.0.0/24")
	owned := netlink.Route{Dst: prefixToIPNet(key), Table: 254, Protocol: managedRouteProtocol, Realm: realm, Priority: 1, Scope: netlink.SCOPE_UNIVERSE}
	foreign := netlink.Route{Dst: prefixToIPNet(key), Table: 254, Protocol: 4, Realm: 0, Priority: 0}

	// A foreign route at a wanted key must never be replaced.
	replace, remove, err := babelRouteDiff([]netlink.Route{foreign}, []netlink.Route{owned}, realm)
	if !errors.Is(err, ErrOwnershipConflict) {
		t.Fatalf("expected ownership conflict, got %v (replace=%d remove=%d)", err, len(replace), len(remove))
	}

	// An identical owned route needs no replacement.
	replace, remove, err = babelRouteDiff([]netlink.Route{owned}, []netlink.Route{owned}, realm)
	if err != nil || len(replace) != 0 || len(remove) != 0 {
		t.Fatalf("unchanged owned route must be a no-op: replace=%d remove=%d err=%v", len(replace), len(remove), err)
	}

	// A changed owned route is replaced.
	changed := owned
	changed.Priority = 2
	replace, _, err = babelRouteDiff([]netlink.Route{owned}, []netlink.Route{changed}, realm)
	if err != nil || len(replace) != 1 {
		t.Fatalf("changed owned route must be replaced: replace=%d err=%v", len(replace), err)
	}

	// Stale owned routes are removed; foreign stale routes are preserved.
	stale := owned
	stale.Dst = prefixToIPNet(netip.MustParsePrefix("10.6.0.0/24"))
	foreignStale := foreign
	foreignStale.Dst = stale.Dst
	_, remove, err = babelRouteDiff([]netlink.Route{stale, foreignStale}, []netlink.Route{owned}, realm)
	if err != nil || len(remove) != 1 {
		t.Fatalf("only owned stale routes must be removed: remove=%d err=%v", len(remove), err)
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
