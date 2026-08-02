package app

import (
	"strings"
	"testing"
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
