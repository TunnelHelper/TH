// SPDX-FileCopyrightText: 2023-2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package babel

import (
	"bytes"
	"io"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/TunnelHelper/TH/internal/babel/internal/queue"
	"github.com/TunnelHelper/TH/internal/babel/proto"
)

func newTestSpeaker(t *testing.T) *Speaker {
	t.Helper()
	params := DefaultParameters
	cfg := SpeakerConfig{
		Parameters: &params,
		RouterID:   proto.RouterID{0, 0, 0, 0, 0, 0, 0, 1},
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	return &Speaker{
		config:          cfg,
		costProvider:    DefaultCostProvider(),
		logger:          cfg.Logger,
		Routes:          NewRouteTable(),
		Sources:         NewSourceTable(),
		selected:        make(map[netip.Prefix]*Route),
		lastFingerprint: make(map[netip.Prefix]string),
		routeChanged:    make(chan struct{}, 1),
	}
}

func newFakeNeighbour(s *Speaker, addr string, txcost uint16) *Neighbour {
	intf := &Interface{
		Interface:   &net.Interface{Name: "test0", Index: 1},
		nominalCost: 96,
		speaker:     s,
		logger:      s.logger,
	}
	n := &Neighbour{
		Address: netip.MustParseAddr(addr),
		intf:    intf,
		TxCost:  txcost,
		Static:  true,
		logger:  s.logger,
		queue:   queue.NewQueue(1500, io.Discard),
		done:    make(chan struct{}),
		stopped: make(chan struct{}),
	}
	n.helloMulticast.Update(1)
	n.helloMulticast.Update(2)
	n.helloMulticast.Update(3)
	return n
}

func insertRoute(s *Speaker, n *Neighbour, prefix string, rid proto.RouterID, seqno uint16, advertised uint16) *Route {
	pfx := netip.MustParsePrefix(prefix)
	r := &Route{
		Source: &Source{
			Prefix:   pfx,
			RouterID: rid,
			SeqNo:    seqno,
			Metric:   int(advertised),
		},
		Neighbour:        n,
		AdvertisedMetric: advertised,
		SeqNo:            seqno,
		NextHop:          n.Address,
		Feasible:         true,
	}
	s.Routes.Insert(r)
	return r
}

func TestBandwidthCost(t *testing.T) {
	cases := []struct {
		bps  uint64
		cost proto.Metric
	}{
		{1e9, 512},   // 1 Gbps
		{1e8, 2816},  // 100 Mbps
		{1e7, 25856}, // 10 Mbps
		{0, proto.Retraction},
	}
	for _, tc := range cases {
		if got := BandwidthCost(tc.bps); got != tc.cost {
			t.Errorf("BandwidthCost(%d) = %d, want %d", tc.bps, got, tc.cost)
		}
	}
	if BandwidthCost(1e12) >= BandwidthCost(1e8) {
		t.Error("higher bandwidth must yield lower cost")
	}
}

func TestDefaultMetric(t *testing.T) {
	if got := defaultMetric(96, 100); got != 196 {
		t.Errorf("additive metric = %d, want 196", got)
	}
	if got := defaultMetric(proto.Retraction, 100); got != proto.Retraction {
		t.Errorf("infinite cost must yield infinite metric, got %d", got)
	}
	if got := defaultMetric(96, proto.Retraction); got != proto.Retraction {
		t.Errorf("retraction must stay retraction, got %d", got)
	}
	if got := defaultMetric(65500, 100); got != proto.Retraction-1 {
		t.Errorf("metric must saturate below infinity, got %d", got)
	}
}

func TestFeasibility(t *testing.T) {
	src := &Source{SeqNo: 5, Metric: 100}
	if !src.Feasible(6, 50) {
		t.Error("newer seqno must be feasible")
	}
	if !src.Feasible(5, 99) {
		t.Error("same seqno with lower metric must be feasible")
	}
	if src.Feasible(5, 100) {
		t.Error("same seqno with equal metric must not be feasible")
	}
	if src.Feasible(4, 1) {
		t.Error("older seqno must not be feasible")
	}

	if !src.UpdateFeasibility(6, 50) || src.SeqNo != 6 || src.Metric != 50 {
		t.Errorf("UpdateFeasibility must adopt newer seqno: %+v", src)
	}
	if src.UpdateFeasibility(6, 80) {
		t.Error("UpdateFeasibility must not regress the stored distance")
	}
}

func TestSelectionPicksBest(t *testing.T) {
	s := newTestSpeaker(t)
	n1 := newFakeNeighbour(s, "fe80::1", 96)
	n2 := newFakeNeighbour(s, "fe80::2", 96)
	r1 := insertRoute(s, n1, "10.0.0.0/24", proto.RouterID{2}, 1, 200)
	r2 := insertRoute(s, n2, "10.0.0.0/24", proto.RouterID{2}, 1, 50)

	s.runSelection()

	if !r2.Selected {
		t.Error("best metric route must be selected")
	}
	if r1.Selected {
		t.Error("worse route must not be selected")
	}
	exported := s.SelectedRoutes()
	if len(exported) != 1 || exported[0].NextHop != n2.Address {
		t.Errorf("unexpected export: %+v", exported)
	}
}

func TestSelectionHysteresis(t *testing.T) {
	s := newTestSpeaker(t)
	n1 := newFakeNeighbour(s, "fe80::1", 96)
	n2 := newFakeNeighbour(s, "fe80::2", 96)
	r1 := insertRoute(s, n1, "10.0.0.0/24", proto.RouterID{2}, 1, 100)
	r2 := insertRoute(s, n2, "10.0.0.0/24", proto.RouterID{2}, 1, 50)

	s.runSelection()
	if !r2.Selected {
		t.Fatal("route 2 must be selected initially")
	}

	// Route 1 becomes better on the instantaneous metric, but its smoothed
	// metric is still high because it was bad recently. The hysteresis rule
	// (RFC 8966 A.3) keeps the current route until both metrics improve.
	r1.AdvertisedMetric = 40
	s.runSelection()
	if r1.Selected {
		t.Fatal("hysteresis must not switch when the smoothed metric is not better")
	}
	if !r2.Selected {
		t.Fatal("previous route must stay selected")
	}

	// After enough selection runs the smoothed metric catches up and the
	// route is allowed to switch.
	for i := 0; i < 10; i++ {
		s.runSelection()
	}
	if !r1.Selected {
		t.Fatal("route must switch once both metrics are better")
	}
}

func TestMultipathSlackUsesTrueBestDuringHysteresis(t *testing.T) {
	s := newTestSpeaker(t)
	s.config.MaxPaths = 3
	s.config.MultipathSlack = 10
	old := insertRoute(s, newFakeNeighbour(s, "fe80::1", 96), "10.8.0.0/24", proto.RouterID{2}, 1, 100)
	best := insertRoute(s, newFakeNeighbour(s, "fe80::2", 96), "10.8.0.0/24", proto.RouterID{2}, 1, 200)
	middle := insertRoute(s, newFakeNeighbour(s, "fe80::3", 96), "10.8.0.0/24", proto.RouterID{2}, 1, 105)
	s.runSelection()
	best.AdvertisedMetric = 0
	s.runSelection()
	if !old.Selected {
		t.Fatal("hysteresis fixture must retain the old primary")
	}
	exported := s.SelectedRoutes()
	if len(exported) != 2 {
		t.Fatalf("selected old primary plus true best = 2 paths, got %+v", exported)
	}
	for _, route := range exported {
		if route.NextHop == middle.NextHop {
			t.Fatal("route outside true-best slack was admitted via retained primary")
		}
	}
}

func TestSelectionMultipath(t *testing.T) {
	s := newTestSpeaker(t)
	s.config.MaxPaths = 3
	s.config.MultipathSlack = 50

	n1 := newFakeNeighbour(s, "fe80::1", 96)
	n2 := newFakeNeighbour(s, "fe80::2", 96)
	n3 := newFakeNeighbour(s, "fe80::3", 96)
	n4 := newFakeNeighbour(s, "fe80::4", 96)
	rid := proto.RouterID{3}
	insertRoute(s, n1, "10.0.0.0/24", rid, 1, 100)
	insertRoute(s, n2, "10.0.0.0/24", rid, 1, 100)
	insertRoute(s, n3, "10.0.0.0/24", rid, 1, 120)
	insertRoute(s, n4, "10.0.0.0/24", rid, 1, 300)

	s.runSelection()

	exported := s.SelectedRoutes()
	if len(exported) != 3 {
		t.Fatalf("expected 3 multipath candidates, got %d: %+v", len(exported), exported)
	}
	// Metrics: 196, 196, 216 (96 + advertised); 396 is beyond the slack.
	for i, want := range []uint16{196, 196, 216} {
		if exported[i].Metric != want {
			t.Errorf("candidate %d metric = %d, want %d", i, exported[i].Metric, want)
		}
	}
}

func TestSelectionDeduplicatesEquivalentForwardingPaths(t *testing.T) {
	s := newTestSpeaker(t)
	s.config.MaxPaths = 4
	s.config.MultipathSlack = 50

	n4 := newFakeNeighbour(s, "::ffff:10.44.0.2", 96)
	n6 := newFakeNeighbour(s, "fe80::2", 96)
	otherLink := newFakeNeighbour(s, "fe80::3", 96)
	otherLink.intf.Interface = &net.Interface{Name: "test1", Index: 2}
	rid := proto.RouterID{3}
	insertRoute(s, n4, "2a0f:1cc5:3ff:1568::/64", rid, 1, 100).NextHop = netip.MustParseAddr("fe80::99")
	insertRoute(s, n6, "2a0f:1cc5:3ff:1568::/64", rid, 1, 100).NextHop = netip.MustParseAddr("fe80::99")
	insertRoute(s, otherLink, "2a0f:1cc5:3ff:1568::/64", rid, 1, 100).NextHop = netip.MustParseAddr("fe80::99")

	s.runSelection()
	exported := s.SelectedRoutes()
	if len(exported) != 2 {
		t.Fatalf("same-link duplicates must collapse while distinct interfaces remain, got %+v", exported)
	}
}

func TestOnUpdateReceived(t *testing.T) {
	s := newTestSpeaker(t)
	n := newFakeNeighbour(s, "fe80::1", 96)
	pfx := netip.MustParsePrefix("192.168.5.0/24")

	s.onUpdateReceived(n, &proto.Update{
		Prefix:   pfx,
		RouterID: proto.RouterID{9},
		Seqno:    7,
		Metric:   100,
		NextHop:  n.Address,
	})

	r, ok := s.Routes.LookupByNeighbour(pfx, n)
	if !ok {
		t.Fatal("route must be created")
	}
	if r.Metric != 196 {
		t.Errorf("route metric = %d, want 196 (96 cost + 100 advertised)", r.Metric)
	}
	if !r.Selected {
		t.Error("learnt route must be selected")
	}

	// Next-hop fallback: an update without a NextHop TLV uses the sender.
	s2 := newTestSpeaker(t)
	n2 := newFakeNeighbour(s2, "fe80::2", 96)
	s2.onUpdateReceived(n2, &proto.Update{
		Prefix:   pfx,
		RouterID: proto.RouterID{9},
		Seqno:    8,
		Metric:   50,
	})
	r2, ok := s2.Routes.LookupByNeighbour(pfx, n2)
	if !ok || r2.NextHop != n2.Address {
		t.Errorf("next hop must fall back to the sender, got %s", r2.NextHop)
	}
}

func TestLearnedRouteLogUnmapsIPv4Neighbour(t *testing.T) {
	var output bytes.Buffer
	s := newTestSpeaker(t)
	s.logger = slog.New(slog.NewJSONHandler(&output, nil))
	n := newFakeNeighbour(s, "::ffff:10.44.0.2", 96)
	s.onUpdateReceived(n, &proto.Update{
		Prefix:   netip.MustParsePrefix("192.0.2.0/24"),
		RouterID: proto.RouterID{9}, Seqno: 1, Metric: 100,
	})

	logLine := output.String()
	if !strings.Contains(logLine, `"neighbour":"10.44.0.2"`) || strings.Contains(logLine, "::ffff:") {
		t.Fatalf("IPv4-mapped neighbour leaked into log output: %s", logLine)
	}
}

func TestUnknownDelayRefreshPreservesMetricsForSamePath(t *testing.T) {
	s := newTestSpeaker(t)
	n := newFakeNeighbour(s, "fe80::1", 96)
	pfx := netip.MustParsePrefix("2a0f:1cc5:3ff:1568::/64")
	rid := proto.RouterID{9}
	nextHop := netip.MustParseAddr("fe80::99")

	s.onUpdateReceived(n, &proto.Update{
		Prefix: pfx, RouterID: rid, Seqno: 1, Metric: 100, NextHop: nextHop,
		PathBottleneckMbps: 100, PathRTTMicros: 9_456,
		PathJitterMicros: 39, PathMetricAgeMillis: 10, PathMetricConfidence: math.MaxUint16,
		PathMetricsPresent: true, PathQualityPresent: true,
	})
	route, ok := s.Routes.LookupByNeighbour(pfx, n)
	if !ok {
		t.Fatal("route was not learned")
	}
	measurementTime := route.PathMetricsReceivedAt

	// A shared multicast refresh can carry bandwidth but no per-neighbour
	// delay. It must not erase the last receiver-specific unicast sample.
	s.onUpdateReceived(n, &proto.Update{
		Prefix: pfx, RouterID: rid, Seqno: 2, Metric: 100, NextHop: nextHop,
		PathBottleneckMbps: 200, PathRTTMicros: -1, PathMetricsPresent: true,
	})
	if route.PathBottleneckMbps != 200 || route.PathRTTMicros != 9_456 || route.PathJitterMicros != 39 {
		t.Fatalf("unknown refresh erased path quality: %+v", route)
	}
	if !route.PathMetricsReceivedAt.Equal(measurementTime) {
		t.Fatal("unknown refresh made the retained measurement artificially fresh")
	}

	// The same data cannot be retained when forwarding actually moves to a
	// different next hop.
	s.onUpdateReceived(n, &proto.Update{
		Prefix: pfx, RouterID: rid, Seqno: 3, Metric: 100,
		NextHop: netip.MustParseAddr("fe80::98"), PathRTTMicros: -1,
	})
	if route.PathRTTMicros != -1 || route.PathMetricsReceivedAt != (time.Time{}) {
		t.Fatalf("metrics from the old next hop survived a path change: %+v", route)
	}
}

func TestOnUpdateRetraction(t *testing.T) {
	s := newTestSpeaker(t)
	n := newFakeNeighbour(s, "fe80::1", 96)
	pfx := netip.MustParsePrefix("192.168.6.0/24")

	s.onUpdateReceived(n, &proto.Update{Prefix: pfx, RouterID: proto.RouterID{9}, Seqno: 1, Metric: 100})
	s.onUpdateReceived(n, &proto.Update{Prefix: pfx, RouterID: proto.RouterID{9}, Seqno: 1, Metric: proto.Retraction})

	r, ok := s.Routes.LookupByNeighbour(pfx, n)
	if !ok {
		t.Fatal("hold-time entry must remain after retraction")
	}
	if r.Metric != proto.Retraction || r.Selected {
		t.Error("retracted route must be unselected with infinite metric")
	}
	if len(s.SelectedRoutes()) != 0 {
		t.Error("retracted route must not be exported")
	}
}

func TestOnUpdateUnfeasibleIgnored(t *testing.T) {
	s := newTestSpeaker(t)
	n := newFakeNeighbour(s, "fe80::1", 96)
	pfx := netip.MustParsePrefix("192.168.7.0/24")
	rid := proto.RouterID{9}

	// Simulate that we previously advertised (seqno 5, metric 200), so an
	// update with the same seqno and a larger metric is unfeasible.
	s.Sources.Insert(&Source{Prefix: pfx, RouterID: rid, SeqNo: 5, Metric: 200})
	s.onUpdateReceived(n, &proto.Update{Prefix: pfx, RouterID: rid, Seqno: 5, Metric: 300})
	if _, ok := s.Routes.LookupByNeighbour(pfx, n); ok {
		t.Fatal("unfeasible update for unknown route must be ignored")
	}

	// A feasible update creates the route; a later unfeasible update for the
	// selected route is ignored per RFC 8966 Section 3.5.3.
	s.onUpdateReceived(n, &proto.Update{Prefix: pfx, RouterID: rid, Seqno: 6, Metric: 100})
	r, ok := s.Routes.LookupByNeighbour(pfx, n)
	if !ok || !r.Selected {
		t.Fatal("feasible update must create a selected route")
	}
	s.Sources.Insert(&Source{Prefix: pfx, RouterID: rid, SeqNo: 6, Metric: 90})
	s.onUpdateReceived(n, &proto.Update{Prefix: pfx, RouterID: rid, Seqno: 6, Metric: 150})
	if !r.Selected || !r.Feasible {
		t.Error("selected route must not be disturbed by an ignored unfeasible update")
	}
}

func TestOnUpdateUnfeasibleBackupRouteUpdated(t *testing.T) {
	s := newTestSpeaker(t)
	n1 := newFakeNeighbour(s, "fe80::1", 96)
	n2 := newFakeNeighbour(s, "fe80::2", 96)
	pfx := netip.MustParsePrefix("192.168.9.0/24")
	rid := proto.RouterID{9}

	// Primary route via n1 (metric 186) and backup via n2 (metric 196).
	r1 := insertRoute(s, n1, pfx.String(), rid, 6, 90)
	r2 := insertRoute(s, n2, pfx.String(), rid, 6, 100)
	s.runSelectionLocked()
	if !r1.Selected || r2.Selected {
		t.Fatal("n1 route must be selected and n2 route must be the backup")
	}

	// The feasibility distance (6, 100) makes a same-seqno metric-100 update
	// unfeasible. RFC 8966 Section 3.5.3 only permits ignoring an unfeasible
	// same-router-id update when the entry is currently selected; a backup
	// entry is updated and immediately unselected so that it cannot be
	// installed while it is not known to be loop-free.
	s.Sources.Insert(&Source{Prefix: pfx, RouterID: rid, SeqNo: 6, Metric: 100})
	s.onUpdateReceived(n2, &proto.Update{Prefix: pfx, RouterID: rid, Seqno: 6, Metric: 100})

	if r2.SeqNo != 6 || r2.AdvertisedMetric != 100 || r2.Feasible {
		t.Errorf("backup route must be updated and marked unfeasible: seqno=%d metric=%d feasible=%v",
			r2.SeqNo, r2.AdvertisedMetric, r2.Feasible)
	}
	if r2.Selected {
		t.Error("unfeasible backup route must not be selected")
	}
	if !r1.Selected || !r1.Feasible {
		t.Error("selected route must be unaffected by the backup update")
	}
}

func TestAdvertiseWithdrawLocal(t *testing.T) {
	s := newTestSpeaker(t)
	pfx := netip.MustParsePrefix("10.1.0.0/16")

	if err := s.Advertise(pfx, LocalRouteMetric); err != nil {
		t.Fatal(err)
	}
	exported := s.SelectedRoutes()
	if len(exported) != 1 || !exported[0].Local || exported[0].Prefix != pfx {
		t.Fatalf("local route must be exported: %+v", exported)
	}

	if err := s.Withdraw(pfx); err != nil {
		t.Fatal(err)
	}
	if got := s.SelectedRoutes(); len(got) != 0 {
		t.Fatalf("withdrawn route must not be exported: %+v", got)
	}
}

func TestSweepExpiry(t *testing.T) {
	s := newTestSpeaker(t)
	n := newFakeNeighbour(s, "fe80::1", 96)
	r := insertRoute(s, n, "192.168.8.0/24", proto.RouterID{9}, 1, 100)
	r.Expiry = time.Now().Add(-time.Second)

	s.sweep()
	if r.Metric != proto.Retraction {
		t.Error("expired route must become a retraction first")
	}
	if _, ok := s.Routes.LookupByNeighbour(r.Source.Prefix, n); !ok {
		t.Error("hold-time entry must survive the first sweep")
	}

	// Once the hold time itself expires, the entry is flushed.
	r.Expiry = time.Now().Add(-time.Second)
	s.sweep()
	if _, ok := s.Routes.LookupByNeighbour(r.Source.Prefix, n); ok {
		t.Error("hold-time entry must be flushed on the second sweep")
	}
}

func TestCostOverrideChangesSelection(t *testing.T) {
	s := newTestSpeaker(t)
	n1 := newFakeNeighbour(s, "fe80::1", 96)
	n2 := newFakeNeighbour(s, "fe80::2", 96)
	insertRoute(s, n1, "10.2.0.0/24", proto.RouterID{2}, 1, 100)
	insertRoute(s, n2, "10.2.0.0/24", proto.RouterID{2}, 1, 100)

	s.runSelection()
	if s.selected[netip.MustParsePrefix("10.2.0.0/24")].Neighbour != n1 {
		t.Fatal("tie must be broken by next-hop order")
	}

	// Making the second link much cheaper must flip the selection.
	n2.SetCostOverride(1)
	s.runSelection()
	if s.selected[netip.MustParsePrefix("10.2.0.0/24")].Neighbour != n2 {
		t.Fatal("cost override must change route selection")
	}
}

func TestDefaultIHUHoldTimeFactor(t *testing.T) {
	if DefaultParameters.IHUHoldTimeFactor != DefaultIHUHoldTimeFactor {
		t.Fatalf("default IHU hold time factor = %v, want %v", DefaultParameters.IHUHoldTimeFactor, DefaultIHUHoldTimeFactor)
	}
}

func TestIHUDoesNotExpireImmediately(t *testing.T) {
	s := newTestSpeaker(t)
	n := newFakeNeighbour(s, "fe80::1", 96)

	n.onIHU(&proto.IHU{RxCost: 42, Interval: 12 * time.Second, Address: n.Address})
	if got := n.transmissionCost(); got != 42 {
		t.Fatalf("TxCost = %d, want 42", got)
	}
	if n.ihuTimeout.Expired() {
		t.Fatal("IHU hold time must not expire immediately after receiving an IHU")
	}
	time.Sleep(50 * time.Millisecond)
	if n.ihuTimeout.Expired() {
		t.Fatal("IHU hold time expired far too early")
	}
}

func TestWildcardPrefixDetection(t *testing.T) {
	if !isWildcardPrefix(netip.PrefixFrom(netip.Addr{}, -1)) {
		t.Fatal("invalid prefix must be treated as a wildcard route request")
	}
	for _, pfx := range []netip.Prefix{
		netip.PrefixFrom(netip.IPv6Unspecified(), 0),
		netip.MustParsePrefix("::/0"),
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("10.0.0.0/8"),
	} {
		if isWildcardPrefix(pfx) {
			t.Errorf("%s must not be treated as a wildcard by the prefix check", pfx)
		}
	}
}

func TestSeqnoRequestConcurrent(t *testing.T) {
	s := newTestSpeaker(t)
	n := newFakeNeighbour(s, "fe80::1", 96)
	s.Advertise(netip.MustParsePrefix("10.9.0.0/24"), LocalRouteMetric)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			s.handleSeqnoRequest(n, &proto.SeqnoRequest{
				Prefix:   netip.MustParsePrefix("10.9.0.0/24"),
				RouterID: s.config.RouterID,
				Seqno:    uint16(i),
				HopCount: 64,
			})
		}
	}()
	for i := 0; i < 200; i++ {
		_ = s.Advertise(netip.MustParsePrefix("10.9.0.0/24"), LocalRouteMetric)
	}
	<-done
	n.queue.Close()
}

func TestDelayCostMapping(t *testing.T) {
	if got := DelayCost(5*time.Millisecond, 96, 10*time.Millisecond, 120*time.Millisecond, 150); got != 96 {
		t.Errorf("below rtt-min must keep nominal cost, got %d", got)
	}
	if got := DelayCost(65*time.Millisecond, 96, 10*time.Millisecond, 120*time.Millisecond, 150); got != 96+75 {
		t.Errorf("mid range must scale linearly, got %d", got)
	}
	if got := DelayCost(200*time.Millisecond, 96, 10*time.Millisecond, 120*time.Millisecond, 150); got != 96+150 {
		t.Errorf("at or above rtt-max must cap at the penalty, got %d", got)
	}
}

func TestInverseBandwidthPenalty(t *testing.T) {
	if got := InverseBandwidthPenalty(100, 10); got != 10 {
		t.Fatalf("penalty = %d, want 10", got)
	}
	if got := InverseBandwidthPenalty(100, 1000); got != 0 {
		t.Fatalf("rounded sub-unit penalty = %d, want 0", got)
	}
	if got := InverseBandwidthPenalty(math.Inf(1), 1); got != proto.Retraction-1 {
		t.Fatalf("infinite penalty = %d, want saturation", got)
	}
}

func TestComputeRTT(t *testing.T) {
	s := newTestSpeaker(t)
	s.config.DelayMetric = true
	n := newFakeNeighbour(s, "fe80::1", 96)

	// A sends Hello(t1); B receives at t1'; B sends Hello(t2') + IHU(t1, t1');
	// A receives at t2. RTT = (t2 - t1) - (t2' - t1').
	t1 := uint32(1_000_000)
	t1p := uint32(1_001_000)
	t2p := uint32(1_005_000)
	t2 := uint32(1_006_000)
	n.computeRTT(t2, &proto.TimestampHello{Transmit: t2p}, &proto.TimestampIHU{Origin: t1, Receive: t1p})

	if !n.HasRTT() || n.RTT() != 2*time.Millisecond {
		t.Fatalf("rtt = %v (has=%v), want 2ms", n.RTT(), n.HasRTT())
	}
	if got := n.Cost(); got != 96 {
		t.Errorf("2ms RTT must keep nominal cost 96, got %d", got)
	}
	n.SetCostOverride(10)
	n.setTransmissionCost(proto.Retraction)
	if got := n.Cost(); got != proto.Retraction {
		t.Fatalf("an IHU-dead neighbour with finite RTT and an override must retract, got %d", got)
	}
	n.setTransmissionCost(96)
	n.SetCostOverride(proto.Retraction)

	// A stale sample (origin more than 3 minutes old) must be discarded.
	before := n.RTT()
	n.computeRTT(t2+uint32(4*time.Minute/time.Microsecond), &proto.TimestampHello{Transmit: t2p}, &proto.TimestampIHU{Origin: t1, Receive: t1p})
	if n.RTT() != before {
		t.Errorf("stale RTT sample must be discarded, rtt changed to %v", n.RTT())
	}
}

func TestPathMetricsPropagation(t *testing.T) {
	s := newTestSpeaker(t)
	pfx := netip.MustParsePrefix("10.0.0.0/24")
	if err := s.Advertise(pfx, LocalRouteMetric); err != nil {
		t.Fatal(err)
	}
	local, ok := s.Routes.LookupByNeighbour(pfx, nil)
	if !ok {
		t.Fatal("local route must exist")
	}

	ifaceAB := &Interface{
		Interface:     &net.Interface{Name: "ab", Index: 1},
		bandwidthMbps: 10,
		speaker:       s,
		logger:        s.logger,
	}
	// Hop A->B: source bottleneck is unlimited, the outgoing interface
	// declares 10 Mbps and the link RTT is 500 us.
	now := time.Now()
	linkAB := DelayStats{Mean: 500 * time.Microsecond, Samples: 4, LastSample: now}
	values := s.encodeRoutes(ifaceAB, []*Route{local}, linkAB)
	var hopAB *proto.Update
	for _, value := range values {
		if update, ok := value.(*proto.Update); ok {
			hopAB = update
		}
	}
	if hopAB == nil || hopAB.PathBottleneckMbps != 10 || hopAB.PathRTTMicros != 500 {
		t.Fatalf("hop A->B path metrics = (%d, %d), want (10, 500)", hopAB.PathBottleneckMbps, hopAB.PathRTTMicros)
	}

	// B learns the route and re-advertises on a 1000 Mbps interface with
	// an additional 300 us of RTT: bottleneck stays 10, RTT accumulates.
	learned := &Route{
		Source:               &Source{Prefix: pfx, RouterID: proto.RouterID{5}},
		Neighbour:            newFakeNeighbour(s, "fe80::b", 96),
		AdvertisedMetric:     100,
		Metric:               196,
		SeqNo:                1,
		NextHop:              netip.MustParseAddr("fe80::b"),
		Feasible:             true,
		PathBottleneckMbps:   10,
		PathRTTMicros:        500,
		PathJitterMicros:     200,
		PathMetricAgeMillis:  100,
		PathMetricConfidence: 60_000,
	}
	ifaceBC := &Interface{
		Interface:     &net.Interface{Name: "bc", Index: 2},
		bandwidthMbps: 1000,
		speaker:       s,
		logger:        s.logger,
	}
	linkBC := DelayStats{Mean: 300 * time.Microsecond, VarianceMicros2: 10_000, Samples: 4, LastSample: now}
	values = s.encodeRoutes(ifaceBC, []*Route{learned}, linkBC)
	var hopBC *proto.Update
	for _, value := range values {
		if update, ok := value.(*proto.Update); ok {
			hopBC = update
		}
	}
	if hopBC == nil || hopBC.PathBottleneckMbps != 10 || hopBC.PathRTTMicros != 800 {
		t.Fatalf("hop B->C path metrics = (%d, %d), want (10, 800)", hopBC.PathBottleneckMbps, hopBC.PathRTTMicros)
	}
	if hopBC.PathJitterMicros != 300 || hopBC.PathMetricAgeMillis < 100 || hopBC.PathMetricConfidence != 60_000 {
		t.Fatalf("hop B->C path quality = jitter %d age %d confidence %d", hopBC.PathJitterMicros, hopBC.PathMetricAgeMillis, hopBC.PathMetricConfidence)
	}
}

func TestUpdateECMPParamsAppliesPenalty(t *testing.T) {
	s := newTestSpeaker(t)
	n := newFakeNeighbour(s, "fe80::1", 96)
	n.intf.bandwidthMbps = 10
	rid := proto.RouterID{9}
	r := insertRoute(s, n, "10.0.0.0/24", rid, 1, 100)
	r.PathBottleneckMbps = 10
	s.runSelection()
	before := r.Metric
	if before != 196 {
		t.Fatalf("base metric = %d, want 196", before)
	}

	// A K penalty of 100 over a 10 Mbps local link adds 10 to the metric,
	// applied to the running speaker without a rebuild.
	s.UpdateECMPParams(4, 0, 100)
	if r.Metric != before+10 {
		t.Fatalf("metric after penalty = %d, want %d", r.Metric, before+10)
	}
}
