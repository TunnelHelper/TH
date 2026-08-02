//go:build integration

// SPDX-FileCopyrightText: 2023-2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package babel

import (
	"errors"
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
