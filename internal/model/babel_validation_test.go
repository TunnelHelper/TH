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

func boolPtr(value bool) *bool { return &value }

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
	// Single peer, multicast auto-selected, AllowedIPs does not cover the
	// Babel multicast group.
	record := newBabelTunnel()
	record.Spec.WireGuard.Peers[0].AllowedIPs = []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32")}
	if err := Validate(record); err == nil {
		t.Fatal("multicast mode without ff02::1:6 coverage must fail")
	}

	// Explicit unicast mode skips the multicast requirement.
	record.Spec.Babel.Multicast = boolPtr(false)
	if err := Validate(record); err != nil {
		t.Fatalf("explicit unicast mode must be allowed: %v", err)
	}

	// ::/0 covers the group.
	record.Spec.Babel.Multicast = nil
	record.Spec.WireGuard.Peers[0].AllowedIPs = []netip.Prefix{netip.MustParsePrefix("::/0")}
	if err := Validate(record); err != nil {
		t.Fatalf("::/0 must cover the Babel multicast group: %v", err)
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
