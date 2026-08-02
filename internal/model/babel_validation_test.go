package model

import (
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func newBabelTunnel() *Tunnel {
	now := time.Now().UTC()
	private, _ := wgtypes.GeneratePrivateKey()
	peer, _ := wgtypes.GeneratePrivateKey()
	return &Tunnel{
		SchemaVersion: SchemaVersion,
		ID:            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		Generation:    1,
		Name:          "mesh1",
		Kind:          KindWireGuard,
		Interface:     "wg0",
		Enabled:       true,
		CreatedAt:     now,
		UpdatedAt:     now,
		Spec: Spec{
			WireGuard: &WireGuardSpec{
				PrivateKey: private.String(),
				PublicKey:  private.PublicKey().String(),
				Addresses:  []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")},
				MTU:        1420,
				Peers: []WireGuardPeer{{
					PublicKey:  peer.PublicKey().String(),
					AllowedIPs: []netip.Prefix{netip.MustParsePrefix("::/0")},
				}},
			},
			Babel: &BabelTunnelConfig{
				Enabled:       true,
				BandwidthMbps: 1000,
			},
		},
	}
}

func TestValidateBabelTunnelValid(t *testing.T) {
	if err := Validate(newBabelTunnel()); err != nil {
		t.Fatal(err)
	}
}

func TestValidateBabelTunnelBandwidthRange(t *testing.T) {
	record := newBabelTunnel()
	record.Spec.Babel.BandwidthMbps = -1
	if err := Validate(record); err == nil {
		t.Fatal("negative bandwidth must fail")
	}
	record.Spec.Babel.BandwidthMbps = MaxBabelBandwidthMbps + 1
	if err := Validate(record); err == nil {
		t.Fatal("oversized bandwidth must fail")
	}
}

func TestValidateBabelTunnelBalanceRange(t *testing.T) {
	record := newBabelTunnel()
	for _, balance := range []float64{-2, 0, 2} {
		record.Spec.Babel.Balance = &balance
		if err := Validate(record); err != nil {
			t.Errorf("balance %v must validate: %v", balance, err)
		}
	}
	for _, balance := range []float64{-2.1, 2.5} {
		record.Spec.Babel.Balance = &balance
		if err := Validate(record); err == nil {
			t.Errorf("balance %v must be rejected", balance)
		}
	}
	record.Spec.Babel.Balance = nil
	if err := Validate(record); err != nil {
		t.Fatalf("nil balance must validate: %v", err)
	}
}

func TestValidateBabelTunnelRejectsSRv6(t *testing.T) {
	record := newBabelTunnel()
	record.Kind = KindSRv6
	record.Interface = ""
	record.Spec = Spec{
		SRv6:  &SRv6Spec{UnderlayInterface: "lo", Table: 100},
		Babel: &BabelTunnelConfig{Enabled: true},
	}
	if err := Validate(record); err == nil {
		t.Fatal("Babel on an SRv6 record must fail")
	}
}

func TestValidateBabelTunnelNeighbours(t *testing.T) {
	record := newBabelTunnel()
	record.Spec.Babel.Multicast = boolPtr(false)
	record.Spec.Babel.Neighbours = []netip.Addr{netip.MustParseAddr("fe80::1"), netip.MustParseAddr("fe80::1")}
	if err := Validate(record); err == nil {
		t.Fatal("duplicate neighbours must fail")
	}
	record.Spec.Babel.Neighbours = []netip.Addr{{}}
	if err := Validate(record); err == nil {
		t.Fatal("invalid neighbour must fail")
	}
}

func TestValidateBabelTunnelMulticastCoverage(t *testing.T) {
	// Single peer, multicast auto-selected: narrow AllowedIPs fall back to
	// unicast mode, so the tunnel stays valid.
	record := newBabelTunnel()
	record.Spec.WireGuard.Peers[0].AllowedIPs = []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32")}
	if !BabelNeedsUnicastFallback(record) {
		t.Fatal("narrow AllowedIPs must trigger the unicast fallback")
	}
	if err := Validate(record); err != nil {
		t.Fatalf("auto-selected unicast fallback must validate: %v", err)
	}

	// Explicit unicast mode skips the multicast requirement as well.
	record.Spec.Babel.Multicast = boolPtr(false)
	if err := Validate(record); err != nil {
		t.Fatalf("explicit unicast mode must be allowed: %v", err)
	}

	// Explicit multicast mode without coverage must still fail.
	record.Spec.Babel.Multicast = boolPtr(true)
	if err := Validate(record); err == nil {
		t.Fatal("explicit multicast mode without ff02::1:6 coverage must fail")
	}

	// ::/0 covers the group.
	record.Spec.Babel.Multicast = nil
	record.Spec.WireGuard.Peers[0].AllowedIPs = []netip.Prefix{netip.MustParsePrefix("::/0")}
	if err := Validate(record); err != nil {
		t.Fatalf("::/0 must cover the Babel multicast group: %v", err)
	}
	if BabelNeedsUnicastFallback(record) {
		t.Fatal("::/0 coverage must not trigger the unicast fallback")
	}
}

func TestApplyDefaultsBabelMulticastFallback(t *testing.T) {
	// A single-peer WireGuard tunnel with narrow AllowedIPs is normalized to
	// explicit unicast mode so the engine uses auto-derived neighbours.
	record := newBabelTunnel()
	record.Spec.WireGuard.Peers[0].AllowedIPs = []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32")}
	applyDefaults(record)
	if record.Spec.Babel.Multicast == nil || *record.Spec.Babel.Multicast {
		t.Fatalf("narrow AllowedIPs must normalize multicast to false, got %v", record.Spec.Babel.Multicast)
	}
	if err := Validate(record); err != nil {
		t.Fatalf("normalized record must validate: %v", err)
	}

	// Wide AllowedIPs keep auto multicast; an explicit choice is untouched.
	record = newBabelTunnel()
	record.Spec.Babel.Multicast = boolPtr(true)
	record.Spec.WireGuard.Peers[0].AllowedIPs = []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32")}
	applyDefaults(record)
	if record.Spec.Babel.Multicast == nil || !*record.Spec.Babel.Multicast {
		t.Fatal("an explicit multicast choice must never be overridden")
	}
	if err := Validate(record); err == nil {
		t.Fatal("explicit multicast without coverage must still fail after defaults")
	}
}

func TestBabelManagedRealmStable(t *testing.T) {
	if BabelManagedRealm() != BabelManagedRealm() {
		t.Fatal("Babel realm must be stable")
	}
	if !IsManagedRouteRealm(BabelManagedRealm()) {
		t.Fatal("Babel realm must carry the TH managed-realm prefix")
	}
}
