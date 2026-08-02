package app

import (
	"net"
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
			// The write-back used by editBabelSettings must restore the
			// stored exponents for representable pairs (alpha + beta = 2).
			alpha := clampExponent(1 + bias)
			beta := clampExponent(1 - bias)
			if tc.alpha+tc.beta == 2 && (alpha != tc.alpha || beta != tc.beta) {
				t.Fatalf("round trip (%v, %v) -> bias %v -> (%v, %v)", tc.alpha, tc.beta, bias, alpha, beta)
			}
		})
	}
}

func TestRenderBalanceSliderMatchesMapping(t *testing.T) {
	// The readout must show the same exponents that the write-back stores:
	// right (positive bias) is bandwidth-dominant, left is latency-dominant.
	right := renderBalanceSlider(1, 1, 1)
	if !strings.Contains(right, "α=2.0 β=0.0") {
		t.Errorf("positive bias must render bandwidth-dominant, got %q", right)
	}
	left := renderBalanceSlider(-1, 1, 1)
	if !strings.Contains(left, "α=0.0 β=2.0") {
		t.Errorf("negative bias must render latency-dominant, got %q", left)
	}
	if strings.ContainsAny(right, "延迟带宽") {
		t.Errorf("slider must render in English, got %q", right)
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

func TestRenderBalanceSliderShowsStoredOffLine(t *testing.T) {
	// At the stored position of an unrepresentable pair the readout shows
	// the stored values, not the derived approximation.
	got := renderBalanceSlider(balanceBias(1.5, 1.0), 1.5, 1.0)
	if !strings.Contains(got, "α=1.50 β=1.00 (stored)") {
		t.Fatalf("stored readout missing, got %q", got)
	}
	// Once the knob moves away, the derived readout is shown again.
	moved := renderBalanceSlider(1, 1.5, 1.0)
	if !strings.Contains(moved, "α=2.0 β=0.0") || strings.Contains(moved, "(stored)") {
		t.Fatalf("moved readout must be derived, got %q", moved)
	}
	// A representable pair never shows the stored marker.
	representable := renderBalanceSlider(0, 1, 1)
	if strings.Contains(representable, "(stored)") {
		t.Fatalf("representable pair must not show the stored marker, got %q", representable)
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

func TestSystemInterfaceOptionsFilter(t *testing.T) {
	intfs := []net.Interface{
		{Name: "lo", Flags: net.FlagLoopback | net.FlagUp},
		{Name: "eth0", Flags: net.FlagUp},
		{Name: "gre-ext0", Flags: net.FlagUp},
		{Name: "wg-prod1", Flags: net.FlagUp},
		{Name: "tap-down", Flags: 0},
	}

	t.Run("excludes loopback and configured external interfaces", func(t *testing.T) {
		options := systemInterfaceOptions(intfs, "", map[string]bool{"gre-ext0": true}, nil)
		want := []string{"eth0", "tap-down", "wg-prod1"}
		if len(options) != len(want) {
			t.Fatalf("options = %d, want %d: %+v", len(options), len(want), options)
		}
		for i := range want {
			if options[i].Value != want[i] {
				t.Fatalf("option %d = %q, want %q", i, options[i].Value, want[i])
			}
		}
		if !strings.Contains(options[1].Label, "(down)") {
			t.Fatalf("down interface must be marked, got %q", options[1].Label)
		}
	})

	t.Run("keyword filter is case-insensitive", func(t *testing.T) {
		options := systemInterfaceOptions(intfs, "PROD", nil, map[string]bool{"wg-prod1": true})
		if len(options) != 1 || options[0].Value != "wg-prod1" {
			t.Fatalf("keyword filter = %+v, want only wg-prod1", options)
		}
		if !strings.Contains(options[0].Label, "(TH tunnel interface)") {
			t.Fatalf("TH tunnel interface must be marked, got %q", options[0].Label)
		}
	})

	t.Run("no match yields no options", func(t *testing.T) {
		options := systemInterfaceOptions(intfs, "zzz", nil, nil)
		if len(options) != 0 {
			t.Fatalf("expected no options, got %+v", options)
		}
	})
}

func TestCollectExternalInterfaceUnicast(t *testing.T) {
	prompts, _ := transcriptPrompts("100\n2\nfe80::1, fe80::2\n")
	external, err := collectExternalInterface(prompts, "tun-ext1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if external.BandwidthMbps != 100 || external.Multicast {
		t.Fatalf("external = %+v, want 100 Mbps unicast", external)
	}
	if len(external.Neighbours) != 2 || external.Neighbours[0] != netip.MustParseAddr("fe80::1") ||
		external.Neighbours[1] != netip.MustParseAddr("fe80::2") {
		t.Fatalf("neighbours = %v, want fe80::1 and fe80::2", external.Neighbours)
	}
}

func TestCollectExternalInterfaceMulticastClearsNeighbours(t *testing.T) {
	existing := config.BabelExternalInterface{
		BandwidthMbps: 10,
		Multicast:     false,
		Neighbours:    []netip.Addr{netip.MustParseAddr("fe80::1")},
	}
	prompts, _ := transcriptPrompts("0\n1\n")
	external, err := collectExternalInterface(prompts, "gre-ext0", &existing)
	if err != nil {
		t.Fatal(err)
	}
	if !external.Multicast || external.BandwidthMbps != 0 || len(external.Neighbours) != 0 {
		t.Fatalf("multicast edit must clear neighbours, got %+v", external)
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
