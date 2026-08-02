//go:build integration

// SPDX-FileCopyrightText: 2023-2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package babel

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/TunnelHelper/TH/internal/babel/proto"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// TestBabelTwoNodeOverVeth exercises the full protocol loop between two
// network namespaces connected by a veth pair: unicast Hello bootstrap with
// configured static neighbours (the WireGuard-style path), route
// advertisement, feasibility, selection and multipath export.
func TestBabelTwoNodeOverVeth(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	baselineGoroutines := runtime.NumGoroutine()

	runtime.LockOSThread()
	original, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		t.Fatal(err)
	}
	namespaceA, err := netns.New()
	if err != nil {
		original.Close()
		runtime.UnlockOSThread()
		if errors.Is(err, syscall.EPERM) {
			t.Skip("network namespace creation requires CAP_SYS_ADMIN")
		}
		t.Fatal(err)
	}
	namespaceB, err := netns.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = netns.Set(original)
		namespaceA.Close()
		namespaceB.Close()
		runtime.UnlockOSThread()
	}()

	// Create the veth pair in namespace A and move one end into B.
	_ = netns.Set(namespaceA)
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: "veth-a", MTU: 1500},
		PeerName:  "veth-b",
	}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Fatal(err)
	}
	linkA, err := netlink.LinkByName("veth-a")
	if err != nil {
		t.Fatal(err)
	}
	peer, err := netlink.LinkByName("veth-b")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(linkA); err != nil {
		t.Fatal(err)
	}
	if err := netlink.AddrAdd(linkA, &netlink.Addr{IPNet: integrationIPNet("fe80::a/64"), Flags: syscall.IFA_F_NODAD}); err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	paramsA := DefaultParameters
	paramsA.UnicastHelloInterval = time.Second
	paramsA.UpdateInterval = 4 * time.Second
	speakerA, err := NewSpeaker(&SpeakerConfig{
		Parameters:       &paramsA,
		RouterID:         proto.RouterID{0, 0, 0, 0, 0, 0, 0, 1},
		InterfaceFilter:  func(name string) bool { return name == "veth-a" },
		StaticNeighbours: map[string][]netip.Addr{"veth-a": {netip.MustParseAddr("fe80::b")}},
		StrictNeighbours: true,
		Logger:           logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer speakerA.Close()

	if err := netlink.LinkSetNsFd(peer, int(namespaceB)); err != nil {
		t.Fatal(err)
	}
	_ = netns.Set(namespaceB)
	linkB, err := netlink.LinkByName("veth-b")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(linkB); err != nil {
		t.Fatal(err)
	}
	if err := netlink.AddrAdd(linkB, &netlink.Addr{IPNet: integrationIPNet("fe80::b/64"), Flags: syscall.IFA_F_NODAD}); err != nil {
		t.Fatal(err)
	}

	paramsB := DefaultParameters
	paramsB.UnicastHelloInterval = time.Second
	paramsB.UpdateInterval = 4 * time.Second
	speakerB, err := NewSpeaker(&SpeakerConfig{
		Parameters:       &paramsB,
		RouterID:         proto.RouterID{0, 0, 0, 0, 0, 0, 0, 2},
		InterfaceFilter:  func(name string) bool { return name == "veth-b" },
		StaticNeighbours: map[string][]netip.Addr{"veth-b": {netip.MustParseAddr("fe80::a")}},
		StrictNeighbours: true,
		Logger:           logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer speakerB.Close()

	pfxA := netip.MustParsePrefix("10.0.0.0/24")
	pfxB := netip.MustParsePrefix("10.1.0.0/24")
	if err := speakerA.Advertise(pfxA, LocalRouteMetric); err != nil {
		t.Fatal(err)
	}
	if err := speakerB.Advertise(pfxB, LocalRouteMetric); err != nil {
		t.Fatal(err)
	}

	waitForRoute(t, speakerA, pfxB, "speaker A must learn B's prefix")
	waitForRoute(t, speakerB, pfxA, "speaker B must learn A's prefix")

	// Closing the speakers must stop every protocol goroutine; otherwise
	// long-running daemons accumulate leaks on every record update.
	if err := speakerA.Close(); err != nil {
		t.Errorf("close speaker A: %v", err)
	}
	if err := speakerB.Close(); err != nil {
		t.Errorf("close speaker B: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= baselineGoroutines+2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if goroutines := runtime.NumGoroutine(); goroutines > baselineGoroutines+2 {
		t.Fatalf("speaker goroutines leaked: baseline=%d now=%d", baselineGoroutines, goroutines)
	}
}

func waitForRoute(t *testing.T, speaker *Speaker, prefix netip.Prefix, message string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		for _, route := range speaker.SelectedRoutes() {
			if route.Prefix == prefix && !route.Local {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	routes := speaker.SelectedRoutes()
	t.Fatalf("%s (have %d routes: %+v)", message, len(routes), routes)
}

func integrationIPNet(prefix string) *net.IPNet {
	p := netip.MustParsePrefix(prefix)
	bits := 128
	if p.Addr().Is4() {
		bits = 32
	}
	return &net.IPNet{IP: net.IP(p.Addr().AsSlice()), Mask: net.CIDRMask(p.Bits(), bits)}
}

// TestBabelTwoWireGuardNodesLLAOnly runs the full Babel loop over two real
// WireGuard tunnels between two network namespaces. The WG interfaces only
// have IPv6 link-local addresses (derived from their public keys) and the
// Babel neighbours are derived from the peers' public keys, so no manual
// neighbour configuration is needed. Both an IPv4 and an IPv6 loopback-style
// prefix are advertised on each side, and the receiver must learn the peer's
// prefixes through both tunnels: the candidate set the bandwidth-weighted
// kernel ECMP routes are built from.
func TestBabelTwoWireGuardNodesLLAOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	runtime.LockOSThread()
	original, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		t.Fatal(err)
	}
	namespaceA, err := netns.New()
	if err != nil {
		original.Close()
		runtime.UnlockOSThread()
		if errors.Is(err, syscall.EPERM) {
			t.Skip("network namespace creation requires CAP_SYS_ADMIN")
		}
		t.Fatal(err)
	}
	namespaceB, err := netns.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = netns.Set(original)
		namespaceA.Close()
		namespaceB.Close()
		runtime.UnlockOSThread()
	}()

	setupUnderlay := func(nsA, nsB netns.NsHandle, linkA, linkB, ipA, ipB string) {
		_ = netns.Set(nsA)
		veth := &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{Name: linkA, MTU: 1500},
			PeerName:  linkB,
		}
		if err := netlink.LinkAdd(veth); err != nil {
			t.Fatal(err)
		}
		local, err := netlink.LinkByName(linkA)
		if err != nil {
			t.Fatal(err)
		}
		peer, err := netlink.LinkByName(linkB)
		if err != nil {
			t.Fatal(err)
		}
		if err := netlink.LinkSetUp(local); err != nil {
			t.Fatal(err)
		}
		if err := netlink.AddrAdd(local, &netlink.Addr{IPNet: integrationIPNet(ipA)}); err != nil {
			t.Fatal(err)
		}
		if err := netlink.LinkSetNsFd(peer, int(nsB)); err != nil {
			t.Fatal(err)
		}
		_ = netns.Set(nsB)
		remote, err := netlink.LinkByName(linkB)
		if err != nil {
			t.Fatal(err)
		}
		if err := netlink.LinkSetUp(remote); err != nil {
			t.Fatal(err)
		}
		if err := netlink.AddrAdd(remote, &netlink.Addr{IPNet: integrationIPNet(ipB)}); err != nil {
			t.Fatal(err)
		}
	}
	setupUnderlay(namespaceA, namespaceB, "u1-a", "u1-b", "192.168.1.1/24", "192.168.1.2/24")
	setupUnderlay(namespaceA, namespaceB, "u2-a", "u2-b", "192.168.2.1/24", "192.168.2.2/24")

	keyA0, _ := wgtypes.GeneratePrivateKey()
	keyB0, _ := wgtypes.GeneratePrivateKey()
	keyA1, _ := wgtypes.GeneratePrivateKey()
	keyB1, _ := wgtypes.GeneratePrivateKey()

	setupWGTunnel := func(ns netns.NsHandle, name string, private wgtypes.Key, peerPub wgtypes.Key, endpoint string, port int, localLLA netip.Addr) {
		_ = netns.Set(ns)
		link := &netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: name}}
		if err := netlink.LinkAdd(link); err != nil {
			t.Fatal(err)
		}
		client, err := wgctrl.New()
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		if err := client.ConfigureDevice(name, wgtypes.Config{
			PrivateKey:   &private,
			ListenPort:   &port,
			ReplacePeers: true,
			Peers: []wgtypes.PeerConfig{{
				PublicKey:         peerPub,
				Endpoint:          &net.UDPAddr{IP: net.ParseIP(endpoint), Port: port},
				ReplaceAllowedIPs: true,
				AllowedIPs:        []net.IPNet{*integrationIPNet("::/0")},
			}},
		}); err != nil {
			t.Fatal(err)
		}
		link2, _ := netlink.LinkByName(name)
		if err := netlink.LinkSetUp(link2); err != nil {
			t.Fatal(err)
		}
		if err := netlink.AddrAdd(link2, &netlink.Addr{IPNet: integrationIPNet(localLLA.String() + "/64"), Flags: syscall.IFA_F_NODAD}); err != nil {
			t.Fatal(err)
		}
	}

	setupWGTunnel(namespaceA, "wg0", keyA0, keyB0.PublicKey(), "192.168.1.2", 51820, integrationWGLLA(keyA0.PublicKey()))
	setupWGTunnel(namespaceA, "wg1", keyA1, keyB1.PublicKey(), "192.168.2.2", 51821, integrationWGLLA(keyA1.PublicKey()))
	setupWGTunnel(namespaceB, "wg0", keyB0, keyA0.PublicKey(), "192.168.1.1", 51820, integrationWGLLA(keyB0.PublicKey()))
	setupWGTunnel(namespaceB, "wg1", keyB1, keyA1.PublicKey(), "192.168.2.1", 51821, integrationWGLLA(keyB1.PublicKey()))

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	params := DefaultParameters
	params.UnicastHelloInterval = time.Second
	params.UpdateInterval = 4 * time.Second

	_ = netns.Set(namespaceA)
	speakerA, err := NewSpeaker(&SpeakerConfig{
		Parameters:      &params,
		RouterID:        proto.RouterID{0, 0, 0, 0, 0, 0, 0, 1},
		InterfaceFilter: func(name string) bool { return name == "wg0" || name == "wg1" },
		StaticNeighbours: map[string][]netip.Addr{
			"wg0": {integrationWGLLA(keyB0.PublicKey())},
			"wg1": {integrationWGLLA(keyB1.PublicKey())},
		},
		Logger: logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer speakerA.Close()

	_ = netns.Set(namespaceB)
	speakerB, err := NewSpeaker(&SpeakerConfig{
		Parameters:      &params,
		RouterID:        proto.RouterID{0, 0, 0, 0, 0, 0, 0, 2},
		InterfaceFilter: func(name string) bool { return name == "wg0" || name == "wg1" },
		StaticNeighbours: map[string][]netip.Addr{
			"wg0": {integrationWGLLA(keyA0.PublicKey())},
			"wg1": {integrationWGLLA(keyA1.PublicKey())},
		},
		Logger: logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer speakerB.Close()

	pfxAV4 := netip.MustParsePrefix("10.99.0.0/24")
	pfxAV6 := netip.MustParsePrefix("fd99::/48")
	pfxBV4 := netip.MustParsePrefix("10.88.0.0/24")
	pfxBV6 := netip.MustParsePrefix("fd88::/48")
	for _, pfx := range []netip.Prefix{pfxAV4, pfxAV6} {
		if err := speakerA.Advertise(pfx, LocalRouteMetric); err != nil {
			t.Fatal(err)
		}
	}
	for _, pfx := range []netip.Prefix{pfxBV4, pfxBV6} {
		if err := speakerB.Advertise(pfx, LocalRouteMetric); err != nil {
			t.Fatal(err)
		}
	}

	waitForMultipath(t, speakerA, pfxBV4, "A must learn B's IPv4 prefix via both tunnels")
	waitForMultipath(t, speakerA, pfxBV6, "A must learn B's IPv6 prefix via both tunnels")
	waitForMultipath(t, speakerB, pfxAV4, "B must learn A's IPv4 prefix via both tunnels")
	waitForMultipath(t, speakerB, pfxAV6, "B must learn A's IPv6 prefix via both tunnels")
}

// waitForMultipath waits until the speaker exports at least two next hops
// for the given prefix (the weighted-ECMP candidate set).
func waitForMultipath(t *testing.T, speaker *Speaker, prefix netip.Prefix, message string) {
	t.Helper()
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		candidates := 0
		for _, route := range speaker.SelectedRoutes() {
			if route.Prefix == prefix && !route.Local {
				candidates++
			}
		}
		if candidates >= 2 {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	routes := speaker.SelectedRoutes()
	t.Fatalf("%s (have %d routes: %+v)", message, len(routes), routes)
}

// integrationWGLLA mirrors the production public-key-derived link-local
// derivation so the test can configure neighbours without manual addresses.
func integrationWGLLA(publicKey wgtypes.Key) netip.Addr {
	digest := sha256.Sum256(append([]byte("th-wg-lla\x00"), publicKey[:]...))
	var address [16]byte
	address[0], address[1] = 0xfe, 0x80
	copy(address[8:], digest[:8])
	address[8] &^= 0x02
	return netip.AddrFrom16(address)
}

// TestBabelIPv4OnlyLink runs Babel over an IPv4-only veth pair (no IPv6
// address at all), exercising the dual-stack socket path with unicast
// neighbours and ordinary IPv4 announcements.
func TestBabelIPv4OnlyLink(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	runtime.LockOSThread()
	original, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		t.Fatal(err)
	}
	namespaceA, err := netns.New()
	if err != nil {
		original.Close()
		runtime.UnlockOSThread()
		if errors.Is(err, syscall.EPERM) {
			t.Skip("network namespace creation requires CAP_SYS_ADMIN")
		}
		t.Fatal(err)
	}
	namespaceB, err := netns.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = netns.Set(original)
		namespaceA.Close()
		namespaceB.Close()
		runtime.UnlockOSThread()
	}()

	_ = netns.Set(namespaceA)
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: "v4-a", MTU: 1500},
		PeerName:  "v4-b",
	}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Fatal(err)
	}
	local, _ := netlink.LinkByName("v4-a")
	peer, err := netlink.LinkByName("v4-b")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(local); err != nil {
		t.Fatal(err)
	}
	if err := netlink.AddrAdd(local, &netlink.Addr{IPNet: integrationIPNet("192.168.99.1/24")}); err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetNsFd(peer, int(namespaceB)); err != nil {
		t.Fatal(err)
	}
	_ = netns.Set(namespaceB)
	remote, err := netlink.LinkByName("v4-b")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(remote); err != nil {
		t.Fatal(err)
	}
	if err := netlink.AddrAdd(remote, &netlink.Addr{IPNet: integrationIPNet("192.168.99.2/24")}); err != nil {
		t.Fatal(err)
	}

	addrB4 := netip.MustParseAddr("192.168.99.2")
	addrA4 := netip.MustParseAddr("192.168.99.1")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	params := DefaultParameters
	params.UnicastHelloInterval = time.Second
	params.UpdateInterval = 4 * time.Second

	_ = netns.Set(namespaceA)
	speakerA, err := NewSpeaker(&SpeakerConfig{
		Parameters:      &params,
		RouterID:        proto.RouterID{0, 0, 0, 0, 0, 0, 0, 1},
		InterfaceFilter: func(name string) bool { return name == "v4-a" },
		StaticNeighbours: map[string][]netip.Addr{
			"v4-a": {netip.AddrFrom16(addrB4.As16())},
		},
		Logger: logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer speakerA.Close()

	_ = netns.Set(namespaceB)
	speakerB, err := NewSpeaker(&SpeakerConfig{
		Parameters:      &params,
		RouterID:        proto.RouterID{0, 0, 0, 0, 0, 0, 0, 2},
		InterfaceFilter: func(name string) bool { return name == "v4-b" },
		StaticNeighbours: map[string][]netip.Addr{
			"v4-b": {netip.AddrFrom16(addrA4.As16())},
		},
		Logger: logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer speakerB.Close()

	pfx := netip.MustParsePrefix("10.99.0.0/24")
	if err := speakerA.Advertise(pfx, LocalRouteMetric); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		found := false
		for _, route := range speakerB.SelectedRoutes() {
			if route.Prefix == pfx && !route.Local {
				if route.NextHop != netip.AddrFrom16(addrA4.As16()) {
					t.Fatalf("next hop = %s, want A's IPv4 address", route.NextHop)
				}
				found = true
				break
			}
		}
		if found {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("B never learned A's IPv4 prefix over the IPv4-only link: %+v", speakerB.SelectedRoutes())
}

// TestBabelBottleneckPropagation verifies the end-to-end bottleneck
// bandwidth propagation: A (10 Mbps) - B (1000 Mbps) - C, with a second
// originator D (1000 Mbps) - C announcing the same prefix. C must see the
// prefix via B with a 10 Mbps bottleneck and via D with a 1000 Mbps
// bottleneck, without knowing B's topology. Two different router-ids make
// the parallel candidates deterministic under Babel's feasibility rule.
func TestBabelBottleneckPropagation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	runtime.LockOSThread()
	original, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		t.Fatal(err)
	}
	namespaceA, err := netns.New()
	if err != nil {
		original.Close()
		runtime.UnlockOSThread()
		if errors.Is(err, syscall.EPERM) {
			t.Skip("network namespace creation requires CAP_SYS_ADMIN")
		}
		t.Fatal(err)
	}
	namespaceB, err := netns.New()
	if err != nil {
		t.Fatal(err)
	}
	namespaceC, err := netns.New()
	if err != nil {
		t.Fatal(err)
	}
	namespaceD, err := netns.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = netns.Set(original)
		namespaceA.Close()
		namespaceB.Close()
		namespaceC.Close()
		namespaceD.Close()
		runtime.UnlockOSThread()
	}()

	setupLLALink := func(leftNS, rightNS netns.NsHandle, leftName, rightName, leftLLA, rightLLA string) {
		_ = netns.Set(leftNS)
		veth := &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{Name: leftName, MTU: 1500},
			PeerName:  rightName,
		}
		if err := netlink.LinkAdd(veth); err != nil {
			t.Fatal(err)
		}
		left, _ := netlink.LinkByName(leftName)
		right, err := netlink.LinkByName(rightName)
		if err != nil {
			t.Fatal(err)
		}
		if err := netlink.LinkSetUp(left); err != nil {
			t.Fatal(err)
		}
		if err := netlink.AddrAdd(left, &netlink.Addr{IPNet: integrationIPNet(leftLLA + "/64"), Flags: syscall.IFA_F_NODAD}); err != nil {
			t.Fatal(err)
		}
		if err := netlink.LinkSetNsFd(right, int(rightNS)); err != nil {
			t.Fatal(err)
		}
		_ = netns.Set(rightNS)
		rightLink, err := netlink.LinkByName(rightName)
		if err != nil {
			t.Fatal(err)
		}
		if err := netlink.LinkSetUp(rightLink); err != nil {
			t.Fatal(err)
		}
		if err := netlink.AddrAdd(rightLink, &netlink.Addr{IPNet: integrationIPNet(rightLLA + "/64"), Flags: syscall.IFA_F_NODAD}); err != nil {
			t.Fatal(err)
		}
	}

	setupLLALink(namespaceA, namespaceB, "ab-a", "ab-b", "fe80::a1", "fe80::b1")
	setupLLALink(namespaceB, namespaceC, "bc-b", "bc-c", "fe80::b2", "fe80::c1")
	setupLLALink(namespaceD, namespaceC, "dc-d", "dc-c", "fe80::d1", "fe80::c2")

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	params := DefaultParameters
	params.UnicastHelloInterval = time.Second
	params.UpdateInterval = 4 * time.Second
	params.MultipathSlack = 512

	newSpeakerIn := func(ns netns.NsHandle, rid byte, filter func(string) bool, static map[string][]netip.Addr, bandwidth map[string]int) *Speaker {
		_ = netns.Set(ns)
		speaker, err := NewSpeaker(&SpeakerConfig{
			Parameters:         &params,
			RouterID:           proto.RouterID{0, 0, 0, 0, 0, 0, 0, rid},
			InterfaceFilter:    filter,
			StaticNeighbours:   static,
			InterfaceBandwidth: bandwidth,
			Logger:             logger,
		})
		if err != nil {
			t.Fatal(err)
		}
		return speaker
	}

	speakerA := newSpeakerIn(namespaceA, 1,
		func(name string) bool { return name == "ab-a" },
		map[string][]netip.Addr{
			"ab-a": {netip.MustParseAddr("fe80::b1")},
		},
		map[string]int{"ab-a": 10})
	defer speakerA.Close()

	speakerB := newSpeakerIn(namespaceB, 2,
		func(name string) bool { return name == "ab-b" || name == "bc-b" },
		map[string][]netip.Addr{
			"ab-b": {netip.MustParseAddr("fe80::a1")},
			"bc-b": {netip.MustParseAddr("fe80::c1")},
		},
		map[string]int{"ab-b": 10, "bc-b": 1000})
	defer speakerB.Close()

	speakerC := newSpeakerIn(namespaceC, 3,
		func(name string) bool { return name == "bc-c" || name == "dc-c" },
		map[string][]netip.Addr{
			"bc-c": {netip.MustParseAddr("fe80::b2")},
			"dc-c": {netip.MustParseAddr("fe80::d1")},
		},
		map[string]int{"bc-c": 1000, "dc-c": 1000})
	defer speakerC.Close()

	speakerD := newSpeakerIn(namespaceD, 4,
		func(name string) bool { return name == "dc-d" },
		map[string][]netip.Addr{
			"dc-d": {netip.MustParseAddr("fe80::c2")},
		},
		map[string]int{"dc-d": 1000})
	defer speakerD.Close()

	pfx := netip.MustParsePrefix("10.0.0.0/24")
	if err := speakerA.Advertise(pfx, LocalRouteMetric); err != nil {
		t.Fatal(err)
	}
	if err := speakerD.Advertise(pfx, LocalRouteMetric); err != nil {
		t.Fatal(err)
	}

	if err := waitForBottleneckValue(speakerC, pfx, 10, 20*time.Second); err != nil {
		t.Fatalf("C must see the 10 Mbps bottleneck via B: %v\nB routes: %+v\nC routes: %+v", err, speakerB.SelectedRoutes(), speakerC.SelectedRoutes())
	}
	waitForBottleneck(t, speakerC, pfx, 1000, "C must see the 1000 Mbps bottleneck via D")
	waitForBottleneck(t, speakerB, pfx, 10, "B must see the 10 Mbps bottleneck")
}

func waitForBottleneck(t *testing.T, speaker *Speaker, prefix netip.Prefix, wantBottleneck int, message string) {
	t.Helper()
	if err := waitForBottleneckValue(speaker, prefix, wantBottleneck, 45*time.Second); err != nil {
		t.Fatalf("%s: %v", message, err)
	}
}

func waitForBottleneckValue(speaker *Speaker, prefix netip.Prefix, wantBottleneck int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, route := range speaker.SelectedRoutes() {
			if route.Prefix == prefix && !route.Local && route.BottleneckMbps == wantBottleneck {
				return nil
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("bottleneck %d not observed (have %+v)", wantBottleneck, speaker.SelectedRoutes())
}
