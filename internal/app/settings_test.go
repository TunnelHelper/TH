package app

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/TunnelHelper/TH/internal/config"
)

func TestValidateNonNegativeFloatInput(t *testing.T) {
	for _, ok := range []string{"0", "0.5", "1234.75"} {
		if err := validateNonNegativeFloatInput(ok); err != nil {
			t.Errorf("%q must be accepted, got %v", ok, err)
		}
	}
	for _, bad := range []string{"-1", "abc", "", "NaN", "Inf", "+Inf"} {
		if err := validateNonNegativeFloatInput(bad); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
}

func TestValidateNeighbourListInput(t *testing.T) {
	if err := validateNeighbourListInput(""); err == nil {
		t.Fatal("empty neighbour list must be rejected")
	}
	if err := validateNeighbourListInput("fe80::1,2001:db8::2"); err != nil {
		t.Fatalf("valid addresses rejected: %v", err)
	}
	if err := validateNeighbourListInput("not-an-address"); err == nil {
		t.Fatal("garbage must be rejected")
	}
	if err := validateNeighbourListInput("::"); err == nil {
		t.Fatal("unspecified address must be rejected")
	}
}

func TestNeighbourListRoundTrip(t *testing.T) {
	addrs := parseNeighbourList("fe80::1, 192.0.2.1 ,2001:db8::5")
	addrs = append(addrs, netip.MustParseAddr("::ffff:10.44.0.2"))
	if len(addrs) != 4 {
		t.Fatalf("parsed %d addresses, want 4: %v", len(addrs), addrs)
	}
	if got := formatNeighbourList(addrs); got != "fe80::1,192.0.2.1,2001:db8::5,10.44.0.2" {
		t.Fatalf("formatted = %q", got)
	}
}

func TestExternalInterfacesSummary(t *testing.T) {
	interfaces := map[string]config.BabelExternalInterface{
		"tun-ext1": {
			BandwidthMbps: 10,
			Neighbours:    []netip.Addr{netip.MustParseAddr("fe80::1")},
		},
		"gre-ext0": {BandwidthMbps: 100, Multicast: true},
	}
	summary := externalInterfacesSummary(interfaces)
	if !strings.Contains(summary, "gre-ext0: multicast, 100 Mbps") ||
		!strings.Contains(summary, "tun-ext1: unicast (fe80::1), 10 Mbps") {
		t.Fatalf("summary = %q", summary)
	}
	if got := externalInterfacesSummary(nil); got != "none" {
		t.Fatalf("empty summary = %q, want none", got)
	}
}
