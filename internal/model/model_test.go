package model

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestPrepareNewDefaultsAndValidation(t *testing.T) {
	now := time.Date(2026, 7, 17, 1, 2, 3, 0, time.FixedZone("test", 8*60*60))
	peerKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	records := []Tunnel{
		{Name: "gre", Kind: KindGRE, Interface: "gre0", Spec: Spec{GRE: &GRESpec{Local: netip.MustParseAddr("192.0.2.1"), Remote: netip.MustParseAddr("192.0.2.2")}}},
		{Name: "vxlan", Kind: KindVXLAN, Interface: "vx0", Spec: Spec{VXLAN: &VXLANSpec{VNI: 100, UnderlayInterface: "eth0", Local: netip.MustParseAddr("192.0.2.1"), Remote: netip.MustParseAddr("192.0.2.2")}}},
		{Name: "wg", Kind: KindWireGuard, Interface: "wg0", Spec: Spec{WireGuard: &WireGuardSpec{Peers: []WireGuardPeer{{PublicKey: peerKey.PublicKey().String(), AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}}}}}},
		{Name: "awg", Kind: KindAmneziaWG, Interface: "awg0", Spec: Spec{AmneziaWG: &AmneziaWGSpec{WireGuardSpec: WireGuardSpec{Peers: []WireGuardPeer{{PublicKey: peerKey.PublicKey().String()}}}}}},
		{Name: "static", Kind: KindXFRMStatic, Interface: "xfrm0", Spec: Spec{XFRMStatic: &XFRMStaticSpec{UnderlayInterface: "eth0", Local: netip.MustParseAddr("192.0.2.1"), Remote: netip.MustParseAddr("192.0.2.2")}}},
		{Name: "ike", Kind: KindXFRMIKEv2, Interface: "ipsec0", Spec: Spec{XFRMIKEv2: &XFRMIKEv2Spec{UnderlayInterface: "eth0", LocalAddress: "192.0.2.1", RemoteAddress: "192.0.2.2", LocalID: "left", RemoteID: "right", AuthMethod: IKEAuthPSK}}},
		{Name: "srv6", Kind: KindSRv6, Spec: Spec{SRv6: &SRv6Spec{BaseURL: "https://routes.example/", UnderlayInterface: "eth0", Table: 100, Sources: []SRv6Source{{Name: "carrier", SIDv4: addrPointer("2001:db8::1"), MTU: 1500}}}}},
	}

	for i := range records {
		record := &records[i]
		t.Run(string(record.Kind), func(t *testing.T) {
			if err := PrepareNew(record, now); err != nil {
				t.Fatalf("PrepareNew: %v", err)
			}
			if record.SchemaVersion != SchemaVersion || record.Generation != 1 || !ValidID(record.ID) {
				t.Fatalf("unexpected metadata: %+v", record)
			}
			if record.CreatedAt.Location() != time.UTC || !record.CreatedAt.Equal(now) {
				t.Fatalf("timestamp was not normalized: %s", record.CreatedAt)
			}
			if err := Validate(record); err != nil {
				t.Fatalf("Validate after preparation: %v", err)
			}
		})
	}
}

func TestRedactAndMergeWireGuardSecrets(t *testing.T) {
	peerPrivate, _ := wgtypes.GeneratePrivateKey()
	psk, _ := wgtypes.GenerateKey()
	record := Tunnel{
		Name: "wg", Kind: KindWireGuard, Interface: "wg0",
		Spec: Spec{WireGuard: &WireGuardSpec{Peers: []WireGuardPeer{{PublicKey: peerPrivate.PublicKey().String(), PresharedKey: psk.String()}}}},
	}
	if err := PrepareNew(&record, time.Now()); err != nil {
		t.Fatal(err)
	}
	private := record.Spec.WireGuard.PrivateKey
	redacted, fields := Redact(record)
	if redacted.Spec.WireGuard.PrivateKey != "" || redacted.Spec.WireGuard.Peers[0].PresharedKey != "" {
		t.Fatal("redacted view contains WireGuard secrets")
	}
	for _, field := range []string{"spec.wireguard.private_key", "spec.wireguard.peers[0].preshared_key"} {
		if !slices.Contains(fields, field) {
			t.Fatalf("missing redacted field %q in %v", field, fields)
		}
	}
	redacted.Name = "renamed"
	if err := PrepareUpdate(&redacted, &record, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if redacted.Spec.WireGuard.PrivateKey != private || redacted.Spec.WireGuard.Peers[0].PresharedKey != psk.String() {
		t.Fatal("redacted update did not merge stored secrets")
	}
	if redacted.Generation != 2 || redacted.Name != "renamed" {
		t.Fatalf("unexpected update metadata: %+v", redacted)
	}
}

func TestRPKPreparationAndKeyConsistency(t *testing.T) {
	remote := XFRMIKEv2Spec{AuthMethod: IKEAuthRPK}
	if err := ensureIKECredentials(&remote, true); err != nil {
		t.Fatal(err)
	}
	record := Tunnel{
		Name: "ike-rpk", Kind: KindXFRMIKEv2, Interface: "xfrm1",
		Spec: Spec{XFRMIKEv2: &XFRMIKEv2Spec{
			UnderlayInterface: "eth0", LocalAddress: "%any", RemoteAddress: "192.0.2.2",
			LocalID: "left", RemoteID: "right", AuthMethod: IKEAuthRPK, RemotePublicKey: remote.LocalPublicKey,
		}},
	}
	if err := PrepareNew(&record, time.Now()); err != nil {
		t.Fatal(err)
	}
	view, fields := Redact(record)
	if view.Spec.XFRMIKEv2.LocalPrivateKey != "" || !slices.Contains(fields, "spec.xfrm_ikev2.local_private_key") {
		t.Fatal("RPK private key was not redacted")
	}
	record.Spec.XFRMIKEv2.LocalPublicKey = remote.LocalPublicKey
	if err := Validate(&record); err == nil {
		t.Fatal("mismatched RPK public/private keys were accepted")
	}
}

func TestIKECredentialModeSwitchDropsOldSecrets(t *testing.T) {
	record := Tunnel{
		Name: "ike", Kind: KindXFRMIKEv2, Interface: "xfrm0",
		Spec: Spec{XFRMIKEv2: &XFRMIKEv2Spec{
			UnderlayInterface: "eth0", LocalAddress: "%any", RemoteAddress: "192.0.2.2",
			LocalID: "left", RemoteID: "right", AuthMethod: IKEAuthPSK,
		}},
	}
	if err := PrepareNew(&record, time.Now()); err != nil {
		t.Fatal(err)
	}
	remote := XFRMIKEv2Spec{AuthMethod: IKEAuthRPK}
	if err := ensureIKECredentials(&remote, true); err != nil {
		t.Fatal(err)
	}
	next, err := Clone(record)
	if err != nil {
		t.Fatal(err)
	}
	next.Spec.XFRMIKEv2.AuthMethod = IKEAuthRPK
	next.Spec.XFRMIKEv2.RemotePublicKey = remote.LocalPublicKey
	withoutGenerated, err := Clone(next)
	if err != nil {
		t.Fatal(err)
	}
	if err := PrepareUpdate(&withoutGenerated, &record, time.Now().Add(time.Minute)); err == nil {
		t.Fatal("ordinary update silently generated replacement RPK credentials")
	}
	if err := PrepareUpdateWithGeneratedSecrets(&next, &record, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if next.Spec.XFRMIKEv2.PSK != "" || next.Spec.XFRMIKEv2.LocalPrivateKey == "" {
		t.Fatal("PSK to RPK switch retained the PSK or failed to generate RPK material")
	}
	back, err := Clone(next)
	if err != nil {
		t.Fatal(err)
	}
	back.Spec.XFRMIKEv2.AuthMethod = IKEAuthPSK
	back.Spec.XFRMIKEv2.PSK = ""
	if err := PrepareUpdateWithGeneratedSecrets(&back, &next, time.Now().Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if back.Spec.XFRMIKEv2.PSK == "" || back.Spec.XFRMIKEv2.LocalPrivateKey != "" || back.Spec.XFRMIKEv2.LocalPublicKey != "" || back.Spec.XFRMIKEv2.RemotePublicKey != "" {
		t.Fatal("RPK to PSK switch retained RPK material or failed to generate a PSK")
	}
}

func TestManagedRulePrioritiesAreStableAndSeparated(t *testing.T) {
	id := "11111111-2222-4333-8444-555555555555"
	wg := Tunnel{ID: id, Kind: KindWireGuard}
	srv6 := Tunnel{ID: id, Kind: KindSRv6}
	first := ManagedRulePriorities(wg)
	second := ManagedRulePriorities(wg)
	if !slices.Equal(first, second) || len(first) != 2 || first[1] != first[0]+1 {
		t.Fatalf("unexpected WireGuard priorities: %v / %v", first, second)
	}
	if slices.Contains(first, ManagedRulePriorities(srv6)[0]) {
		t.Fatal("WireGuard and SRv6 priority ranges overlap")
	}
}

func TestPrepareRejectsMismatchedSpecWithoutPanicking(t *testing.T) {
	record := Tunnel{
		Name: "wrong", Kind: KindWireGuard, Interface: "wg0",
		Spec: Spec{GRE: &GRESpec{Local: netip.MustParseAddr("192.0.2.1"), Remote: netip.MustParseAddr("192.0.2.2")}},
	}
	if err := PrepareNew(&record, time.Now()); err == nil {
		t.Fatal("mismatched spec was accepted")
	}
}

func TestInterfaceAddressesPreserveHostBits(t *testing.T) {
	addresses := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.1/24"),
		netip.MustParsePrefix("10.0.0.2/24"),
	}
	if err := validateInterfaceAddresses(addresses); err != nil {
		t.Fatalf("valid interface addresses were rejected: %v", err)
	}
	if err := validateNetworks(addresses); err == nil {
		t.Fatal("duplicate masked networks were accepted")
	}
}

func addrPointer(value string) *netip.Addr {
	addr := netip.MustParseAddr(value)
	return &addr
}
