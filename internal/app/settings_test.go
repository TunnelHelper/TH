package app

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/TunnelHelper/TH/internal/config"
)

func TestBalanceBiasRoundTrip(t *testing.T) {
	cases := []struct {
		name  string
		alpha float64
		beta  float64
		bias  float64
	}{
		{"default", 1, 1, 0},
		{"bandwidth dominant", 2, 0, 1},
		{"latency dominant", 0, 2, -1},
		{"clamped high", 4, 0, 2},
		{"clamped low", 0, 4, -2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bias := balanceBias(tc.alpha, tc.beta)
			if bias != tc.bias {
				t.Fatalf("balanceBias(%v, %v) = %v, want %v", tc.alpha, tc.beta, bias, tc.bias)
			}
			// The write-back used by the settings editor must restore the
			// stored exponents for representable pairs (alpha + beta = 2).
			alpha := clampExponent(1 + bias)
			beta := clampExponent(1 - bias)
			if tc.alpha+tc.beta == 2 && (alpha != tc.alpha || beta != tc.beta) {
				t.Fatalf("round trip (%v, %v) -> bias %v -> (%v, %v)", tc.alpha, tc.beta, bias, alpha, beta)
			}
		})
	}
}

func TestBalanceExponentsPreserveUnrepresentable(t *testing.T) {
	// A pair off the alpha + beta = 2 line must survive an untouched save.
	alpha, beta := balanceExponents(false, 0, 2, 2)
	if alpha != 2 || beta != 2 {
		t.Fatalf("untouched slider rewrote stored exponents to (%v, %v), want (2, 2)", alpha, beta)
	}
	alpha, beta = balanceExponents(false, 0.25, 1.5, 1.0)
	if alpha != 1.5 || beta != 1.0 {
		t.Fatalf("untouched slider rewrote stored exponents to (%v, %v), want (1.5, 1.0)", alpha, beta)
	}
	// Moving the knob still applies the bias mapping.
	alpha, beta = balanceExponents(true, 1, 2, 2)
	if alpha != 2 || beta != 0 {
		t.Fatalf("moved slider must apply the bias mapping, got (%v, %v)", alpha, beta)
	}
}

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
	if len(addrs) != 3 {
		t.Fatalf("parsed %d addresses, want 3: %v", len(addrs), addrs)
	}
	if got := formatNeighbourList(addrs); got != "fe80::1,192.0.2.1,2001:db8::5" {
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
