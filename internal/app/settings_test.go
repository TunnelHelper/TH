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
	right := renderBalanceSlider(1)
	if !strings.Contains(right, "α=2.0 β=0.0") {
		t.Errorf("positive bias must render bandwidth-dominant, got %q", right)
	}
	left := renderBalanceSlider(-1)
	if !strings.Contains(left, "α=0.0 β=2.0") {
		t.Errorf("negative bias must render latency-dominant, got %q", left)
	}
}
