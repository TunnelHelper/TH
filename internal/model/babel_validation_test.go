package model

import (
	"net/netip"
	"testing"
	"time"
)

func newBabelTunnel() *Tunnel {
	now := time.Now().UTC()
	return &Tunnel{
		SchemaVersion: SchemaVersion,
		ID:            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		Generation:    1,
		Name:          "mesh1",
		Kind:          KindBabel,
		Enabled:       true,
		CreatedAt:     now,
		UpdatedAt:     now,
		Spec: Spec{Babel: &BabelSpec{
			Interfaces: []string{"wg0"},
			StaticNeighbours: map[string][]netip.Addr{
				"wg0": {netip.MustParseAddr("fe80::1"), netip.MustParseAddr("192.168.1.1")},
			},
			StrictNeighbours:    true,
			UnicastHelloSeconds: 4,
			AdvertisedPrefixes:  []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
			MaxPaths:            4,
			SplitHorizon:        boolPtr(true),
			RouterID:            "0011223344556677",
		}},
	}
}

func boolPtr(v bool) *bool { return &v }

func TestValidateBabelValid(t *testing.T) {
	if err := Validate(newBabelTunnel()); err != nil {
		t.Fatal(err)
	}
}

func TestValidateBabelRejectsMissingInterfaces(t *testing.T) {
	record := newBabelTunnel()
	record.Spec.Babel.Interfaces = nil
	if err := Validate(record); err == nil {
		t.Fatal("babel record without interfaces must fail")
	}
}

func TestValidateBabelRejectsBadRouterID(t *testing.T) {
	record := newBabelTunnel()
	record.Spec.Babel.RouterID = "zz"
	if err := Validate(record); err == nil {
		t.Fatal("invalid router_id must fail")
	}
	for _, reserved := range []string{"0000000000000000", "ffffffffffffffff"} {
		record.Spec.Babel.RouterID = reserved
		if err := Validate(record); err == nil {
			t.Fatalf("reserved router_id %s must fail", reserved)
		}
	}
}

func TestValidateBabelRejectsStrictWithoutNeighbours(t *testing.T) {
	record := newBabelTunnel()
	record.Spec.Babel.StaticNeighbours = nil
	if err := Validate(record); err == nil {
		t.Fatal("strict_neighbours without static neighbours must fail")
	}
}

func TestValidateBabelRejectsStrictWithMulticast(t *testing.T) {
	record := newBabelTunnel()
	record.Spec.Babel.Multicast = true
	if err := Validate(record); err == nil {
		t.Fatal("strict_neighbours with multicast must fail")
	}
}

func TestValidateBabelRejectsUnknownStaticInterface(t *testing.T) {
	record := newBabelTunnel()
	record.Spec.Babel.StaticNeighbours = map[string][]netip.Addr{
		"eth0": {netip.MustParseAddr("fe80::1")},
	}
	if err := Validate(record); err == nil {
		t.Fatal("static neighbour on an unlisted interface must fail")
	}
}

func TestBabelDefaults(t *testing.T) {
	record := newBabelTunnel()
	record.Spec.Babel.RouterID = ""
	record.Spec.Babel.MaxPaths = 0
	record.Spec.Babel.SplitHorizon = nil
	record.Spec.Babel.UnicastHelloSeconds = 0
	record.Spec.Babel.Multicast = false

	if err := PrepareNew(record, time.Now()); err != nil {
		t.Fatal(err)
	}
	spec := record.Spec.Babel
	if len(spec.RouterID) != 16 {
		t.Errorf("router_id must be generated, got %q", spec.RouterID)
	}
	if spec.MaxPaths != 4 {
		t.Errorf("max_paths default = %d, want 4", spec.MaxPaths)
	}
	if spec.SplitHorizon == nil || !*spec.SplitHorizon {
		t.Error("split_horizon must default to enabled")
	}
	if spec.UnicastHelloSeconds != 4 {
		t.Errorf("non-multicast unicast_hello_seconds default = %d, want 4", spec.UnicastHelloSeconds)
	}
	if BabelRouteTable(*record) != mainRouteTable {
		t.Error("default Babel route table must be the main table")
	}
}

func TestBabelRouteTableOverride(t *testing.T) {
	record := newBabelTunnel()
	record.Spec.Babel.RouteTable = 100
	if BabelRouteTable(*record) != 100 {
		t.Error("route_table override must be honoured")
	}
}
