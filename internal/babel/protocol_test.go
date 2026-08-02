// SPDX-FileCopyrightText: 2023-2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package babel

import (
	"io"
	"log/slog"
	"net"
	"net/netip"
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
	if n.TxCost != 42 {
		t.Fatalf("TxCost = %d, want 42", n.TxCost)
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
