//go:build linux

package linux

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TunnelHelper/TH/internal/model"
	"github.com/mdlayher/genetlink"
	mdnetlink "github.com/mdlayher/netlink"
	"github.com/strongswan/govici/vici"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestBuildVICIConnectionUsesBinaryRPKValues(t *testing.T) {
	remotePublic := generatedPublicDER(t)
	record := model.Tunnel{
		Name: "ike", Kind: model.KindXFRMIKEv2, Interface: "xfrm0",
		Spec: model.Spec{XFRMIKEv2: &model.XFRMIKEv2Spec{
			UnderlayInterface: "eth0", LocalAddress: "192.0.2.1", RemoteAddress: "192.0.2.2",
			LocalID: "left", RemoteID: "right", AuthMethod: model.IKEAuthRPK,
			RemotePublicKey: base64.StdEncoding.EncodeToString(remotePublic),
		}},
	}
	if err := model.PrepareNew(&record, time.Now()); err != nil {
		t.Fatal(err)
	}
	message, err := buildVICIConnection(record)
	if err != nil {
		t.Fatal(err)
	}
	inner, ok := message.Get(connectionName(record)).(*vici.Message)
	if !ok {
		t.Fatalf("connection section has type %T", message.Get(connectionName(record)))
	}
	var decoded viciConnection
	if err := vici.UnmarshalMessage(inner, &decoded); err != nil {
		t.Fatal(err)
	}
	localDER, _ := base64.StdEncoding.DecodeString(record.Spec.XFRMIKEv2.LocalPublicKey)
	if len(decoded.Local.Pubkeys) != 1 || decoded.Local.Pubkeys[0] != string(localDER) {
		t.Fatal("local RPK was not encoded as binary DER")
	}
	if len(decoded.Remote.Pubkeys) != 1 || decoded.Remote.Pubkeys[0] != string(remotePublic) {
		t.Fatal("remote RPK was not encoded as binary DER")
	}
	child, ok := decoded.Children[childName(record)]
	if !ok || child.IfIDIn != record.Spec.XFRMIKEv2.IfID || child.ReqID != record.Spec.XFRMIKEv2.ReqID {
		t.Fatalf("unexpected VICI child: %+v", decoded.Children)
	}
	if id, err := privateKeyID(record); err != nil || len(id) != 40 {
		t.Fatalf("private key id = %q, %v", id, err)
	}
}

func TestAmneziaHeaderEncodingByFamilyVersion(t *testing.T) {
	for _, test := range []struct {
		name    string
		version uint8
		value   string
	}{
		{name: "numeric-v1", version: 1, value: "12345"},
		{name: "string-v2", version: 2, value: "header-value"},
	} {
		t.Run(test.name, func(t *testing.T) {
			encoder := mdnetlink.NewAttributeEncoder()
			if err := encodeAmneziaHeader(encoder, awgDeviceH1, test.value, test.version); err != nil {
				t.Fatal(err)
			}
			data, err := encoder.Encode()
			if err != nil {
				t.Fatal(err)
			}
			decoder, err := mdnetlink.NewAttributeDecoder(data)
			if err != nil || !decoder.Next() {
				t.Fatalf("decode header: %v", err)
			}
			if got := decodeAmneziaHeader(decoder, test.version); got != test.value {
				t.Fatalf("decoded header = %q, want %q", got, test.value)
			}
		})
	}
	encoder := mdnetlink.NewAttributeEncoder()
	if err := encodeAmneziaHeader(encoder, awgDeviceH1, "not-a-number", 1); err == nil {
		t.Fatal("v1 accepted a non-numeric magic header")
	}
}

func TestAmneziaSockaddrRoundTrip(t *testing.T) {
	for _, endpoint := range []net.UDPAddr{
		{IP: net.ParseIP("192.0.2.10"), Port: 51820},
		{IP: net.ParseIP("2001:db8::10"), Port: 4242},
		{IP: net.ParseIP("fe80::10"), Port: 1234, Zone: "7"},
	} {
		data, err := encodeAmneziaSockaddr(endpoint)()
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := parseAmneziaSockaddr(data)
		if err != nil {
			t.Fatal(err)
		}
		if !parsed.IP.Equal(endpoint.IP) || parsed.Port != endpoint.Port || parsed.Zone != endpoint.Zone {
			t.Fatalf("round trip = %s, want %s", parsed, endpoint.String())
		}
	}
}

func TestWireGuardPeerStatusesExposeOperationalData(t *testing.T) {
	key, _ := wgtypes.GeneratePrivateKey()
	handshake := time.Now().Add(-time.Minute).UTC().Truncate(time.Second)
	statuses := wireGuardPeerStatuses([]wgtypes.Peer{{
		PublicKey:                   key.PublicKey(),
		Endpoint:                    &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 51820},
		PersistentKeepaliveInterval: 25 * time.Second,
		LastHandshakeTime:           handshake,
		ReceiveBytes:                1024,
		TransmitBytes:               2048,
		AllowedIPs:                  []net.IPNet{{IP: net.ParseIP("10.0.0.0"), Mask: net.CIDRMask(24, 32)}},
	}})
	if len(statuses) != 1 {
		t.Fatalf("statuses = %+v", statuses)
	}
	status := statuses[0]
	if status.PublicKey != key.PublicKey().String() || status.Endpoint != "192.0.2.10:51820" || status.KeepaliveSeconds != 25 || status.LastHandshakeTime == nil || !status.LastHandshakeTime.Equal(handshake) {
		t.Fatalf("peer status = %+v", status)
	}
	if len(status.AllowedIPs) != 1 || status.AllowedIPs[0] != "10.0.0.0/24" || status.ReceiveBytes != 1024 || status.TransmitBytes != 2048 {
		t.Fatalf("peer operational data = %+v", status)
	}
}

func TestParseAmneziaDeviceFixture(t *testing.T) {
	key, _ := wgtypes.GeneratePrivateKey()
	encoder := mdnetlink.NewAttributeEncoder()
	encoder.String(awgDeviceIfName, "awg0")
	public := key.PublicKey()
	encoder.Bytes(awgDevicePublicKey, public[:])
	encoder.Uint16(awgDeviceListenPort, 51820)
	encoder.Uint16(awgDeviceJC, 4)
	encoder.String(awgDeviceH1, "magic")
	data, err := encoder.Encode()
	if err != nil {
		t.Fatal(err)
	}
	device, err := parseAmneziaDevice([]genetlink.Message{{Data: data}}, 2)
	if err != nil {
		t.Fatal(err)
	}
	if device.Name != "awg0" || device.PublicKey != public || device.ListenPort != 51820 || device.JunkCount != 4 || device.H1 != "magic" {
		t.Fatalf("parsed fixture = %+v", device)
	}
}

func TestAmneziaPeerAttributesRoundTrip(t *testing.T) {
	privateKey, _ := wgtypes.GeneratePrivateKey()
	psk, _ := wgtypes.GenerateKey()
	want := model.WireGuardPeer{
		PublicKey: privateKey.PublicKey().String(), PresharedKey: psk.String(),
		Endpoint: "192.0.2.10:51820", Keepalive: 25,
		AllowedIPs: []netip.Prefix{
			netip.MustParsePrefix("10.20.0.0/24"),
			netip.MustParsePrefix("2001:db8:20::/48"),
		},
	}
	encoder := mdnetlink.NewAttributeEncoder()
	encoder.String(awgDeviceIfName, "awg0")
	encoder.Nested(awgDevicePeers, func(peers *mdnetlink.AttributeEncoder) error {
		peers.Nested(0, func(attributes *mdnetlink.AttributeEncoder) error {
			return encodeAmneziaPeer(context.Background(), attributes, want)
		})
		return nil
	})
	data, err := encoder.Encode()
	if err != nil {
		t.Fatal(err)
	}
	device, err := parseAmneziaDevice([]genetlink.Message{{Data: data}}, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(device.Peers) != 1 {
		t.Fatalf("decoded peers = %d, want 1", len(device.Peers))
	}
	got := device.Peers[0]
	if got.PublicKey.String() != want.PublicKey || got.PresharedKey.String() != want.PresharedKey ||
		got.Endpoint == nil || got.Endpoint.String() != want.Endpoint ||
		got.PersistentKeepaliveInterval != 25*time.Second || len(got.AllowedIPs) != len(want.AllowedIPs) {
		t.Fatalf("decoded peer = %+v", got)
	}
	for i, prefix := range want.AllowedIPs {
		if got.AllowedIPs[i].String() != prefix.String() {
			t.Fatalf("decoded AllowedIPs[%d] = %s, want %s", i, got.AllowedIPs[i], prefix)
		}
	}
}

func TestParseSRv6Feed(t *testing.T) {
	prefixes, err := parseSRv6Feed([]byte("# comment\n192.0.2.0/24\n192.0.2.1/24\n"), 4)
	if err != nil {
		t.Fatal(err)
	}
	if len(prefixes) != 1 || prefixes[0] != netip.MustParsePrefix("192.0.2.0/24") {
		t.Fatalf("parsed prefixes = %v", prefixes)
	}
	if _, err := parseSRv6Feed([]byte("2001:db8::/32\n"), 4); err == nil {
		t.Fatal("wrong-family feed was accepted")
	}
	if _, err := parseSRv6Feed([]byte("not-a-prefix\n"), 4); err == nil || !strings.Contains(err.Error(), "line 1") {
		t.Fatalf("malformed feed error = %v", err)
	}
}

func TestParseSRv6FeedRejectsTooManyRoutes(t *testing.T) {
	var feed strings.Builder
	for i := 0; i <= maxSRv6RoutesPerFeed; i++ {
		address := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		feed.WriteString(address.String())
		feed.WriteString("/32\n")
	}
	if _, err := parseSRv6Feed([]byte(feed.String()), 4); err == nil {
		t.Fatal("oversized SRv6 feed was accepted")
	}
}

func TestSRv6FetchCachesAndFallsBack(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/carrier_v4.txt" {
			http.NotFound(response, request)
			return
		}
		_, _ = response.Write([]byte("192.0.2.0/24\n"))
	}))
	cachePath := filepath.Join(t.TempDir(), "carrier_v4.txt")
	client := &http.Client{Timeout: time.Second}
	data, stale, err := fetchOrReadSRv6Feed(context.Background(), client, server.URL, "carrier_v4.txt", cachePath, time.Hour)
	if err != nil || stale || string(data) != "192.0.2.0/24\n" {
		t.Fatalf("fresh fetch = %q, stale=%t, err=%v", data, stale, err)
	}
	info, err := os.Stat(cachePath)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("cache mode = %v, %v", info, err)
	}
	server.Close()
	data, stale, err = fetchOrReadSRv6Feed(context.Background(), client, server.URL, "carrier_v4.txt", cachePath, -time.Second)
	if err != nil || !stale || string(data) != "192.0.2.0/24\n" {
		t.Fatalf("stale fallback = %q, stale=%t, err=%v", data, stale, err)
	}
}

func TestStaticXFRMBuildersAreExact(t *testing.T) {
	record := model.Tunnel{
		Name: "static", Kind: model.KindXFRMStatic, Interface: "xfrm0",
		Spec: model.Spec{XFRMStatic: &model.XFRMStaticSpec{
			UnderlayInterface: "eth0", Local: netip.MustParseAddr("192.0.2.1"), Remote: netip.MustParseAddr("192.0.2.2"),
		}},
	}
	if err := model.PrepareNew(&record, time.Now()); err != nil {
		t.Fatal(err)
	}
	backend := &Backend{}
	states, err := backend.desiredStaticStates(record.Spec.XFRMStatic)
	if err != nil {
		t.Fatal(err)
	}
	policies := backend.desiredStaticPolicies(record.Spec.XFRMStatic)
	if len(states) != 2 || len(policies) != 6 {
		t.Fatalf("states/policies = %d/%d, want 2/6", len(states), len(policies))
	}
	for _, state := range states {
		if state.Ifid != int(record.Spec.XFRMStatic.IfID) || state.Reqid != int(record.Spec.XFRMStatic.ReqID) || state.Aead == nil {
			t.Fatalf("unexpected state: %+v", state)
		}
	}
}

func TestManagedRouteEqualityIncludesSEG6(t *testing.T) {
	route := netlink.Route{
		LinkIndex: 2, Dst: prefixToIPNet(netip.MustParsePrefix("192.0.2.0/24")), Table: 100,
		Protocol: managedRouteProtocol, Realm: 1001, MTU: 1400,
		Encap: &netlink.SEG6Encap{Mode: 1, Segments: []net.IP{net.ParseIP("2001:db8::1")}},
	}
	copy := route
	copy.Encap = &netlink.SEG6Encap{Mode: 1, Segments: []net.IP{net.ParseIP("2001:db8::1")}}
	if !equalManagedRoute(route, copy) {
		t.Fatal("identical SEG6 routes compare unequal")
	}
	copy.Realm++
	if equalManagedRoute(route, copy) {
		t.Fatal("routes from different ownership realms compare equal")
	}
	copy.Realm = route.Realm
	copy.Encap = &netlink.SEG6Encap{Mode: 1, Segments: []net.IP{net.ParseIP("2001:db8::2")}}
	if equalManagedRoute(route, copy) {
		t.Fatal("different SEG6 routes compare equal")
	}
}

func TestManagedRouteOwnershipRequiresRecordRealm(t *testing.T) {
	record := model.Tunnel{ID: "11111111-2222-4333-8444-555555555555"}
	route := netlink.Route{Protocol: managedRouteProtocol, Realm: model.ManagedRouteRealm(record)}
	if !routeOwnedByRecord(record, route) {
		t.Fatal("record route realm was not recognized")
	}
	route.Realm++
	if routeOwnedByRecord(record, route) {
		t.Fatal("foreign route realm was treated as record-owned")
	}
	route.Realm = 0
	expected := map[string]netlink.Route{managedRouteKey(route): route}
	if !legacyExpectedRoute(route, expected) {
		t.Fatal("expected legacy route was not recognized for migration")
	}
	delete(expected, managedRouteKey(route))
	if legacyExpectedRoute(route, expected) {
		t.Fatal("unrelated legacy route was treated as record-owned")
	}
}

func generatedPublicDER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
