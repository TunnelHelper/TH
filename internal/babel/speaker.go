// SPDX-FileCopyrightText: 2023-2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package babel

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/TunnelHelper/TH/internal/babel/proto"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type SpeakerConfig struct {
	*Parameters

	Handler any

	// RouterID is the 8-octet router identifier. When zero, a random one
	// is generated.
	RouterID proto.RouterID

	// InterfaceFilter selects which local interfaces participate in the
	// protocol. A nil filter enables all non-loopback interfaces.
	InterfaceFilter func(string) bool

	// RouteFilter, when set, is invoked for every locally injected route
	// and may return a modified metric.
	RouteFilter func(*Route) proto.Metric

	// StaticNeighbours lists peers that must be contacted with unicast
	// Hellos on non-multicast links (WireGuard and unicast VXLAN). The map
	// key is the interface name.
	StaticNeighbours map[string][]netip.Addr

	// StrictNeighbours restricts non-multicast interfaces to packets from
	// configured static neighbours.
	StrictNeighbours bool

	// MulticastInterfaces lists the interfaces that can carry multicast
	// Hellos and updates (single-peer WireGuard with multicast-covered
	// AllowedIPs, GRE, multicast-capable VXLAN). Interfaces not listed run
	// in unicast mode with static neighbours and unicast Hellos.
	MulticastInterfaces map[string]bool

	// Cost plugs custom cost and metric computation in (RFC 8966
	// Sections 3.4.3 and 3.5.2). When nil, the default wired behaviour
	// (2-out-of-3 sensing, additive metrics) is used.
	Cost *CostProvider

	// InterfaceBandwidth maps interface names to their declared usable
	// bandwidth in Mbps. Zero means unset (unlimited). It is the per-hop
	// contribution of the end-to-end bottleneck bandwidth announced in
	// Babel updates.
	InterfaceBandwidth map[string]int

	Logger *slog.Logger
}

func (c *SpeakerConfig) SetDefaults() error {
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	if c.RouterID == proto.RouterIDUnspecified {
		var err error
		if c.RouterID, err = proto.GenerateRouterID(); err != nil {
			return fmt.Errorf("failed to generate router ID: %w", err)
		}
		c.Logger.Info("Generated random router ID", slog.String("rid", hex.EncodeToString(c.RouterID[:])))
	}

	if c.Parameters == nil {
		dp := DefaultParameters
		c.Parameters = &dp
	}
	if c.NominalLinkCost == 0 {
		c.NominalLinkCost = DefaultWiredLinkCost
	}
	if c.SmoothingAlpha <= 0 || c.SmoothingAlpha > 1 {
		c.SmoothingAlpha = DefaultSmoothingAlpha
	}
	if c.MaxPaths < 1 {
		c.MaxPaths = DefaultMaxPaths
	}
	if c.DelayMin <= 0 {
		c.DelayMin = DefaultDelayMin
	}
	if c.DelayMax <= c.DelayMin {
		c.DelayMax = DefaultDelayMax
	}
	if c.DelayMaxPenalty == 0 {
		c.DelayMaxPenalty = DefaultDelayMaxPenalty
	}
	if c.DelaySmoothingAlpha <= 0 || c.DelaySmoothingAlpha > 1 {
		c.DelaySmoothingAlpha = DefaultDelayAlpha
	}
	if c.BottleneckPenalty < 0 {
		c.BottleneckPenalty = 0
	}
	if c.RouteExpiryTime == 0 {
		c.RouteExpiryTime = DefaultRouteExpiryTime
	}
	if c.SourceGCTime == 0 {
		c.SourceGCTime = DefaultSourceGCTime
	}
	if c.UpdateInterval == 0 {
		c.UpdateInterval = DefaultUpdateInterval
	}
	if c.MulticastHelloInterval == 0 {
		c.MulticastHelloInterval = DefaultMulticastHelloInterval
	}
	if c.IHUInterval == 0 {
		c.IHUInterval = DefaultIHUInterval
	}
	if c.IHUHoldTimeFactor <= 0 {
		c.IHUHoldTimeFactor = DefaultIHUHoldTimeFactor
	}
	if c.UrgentTimeout == 0 {
		c.UrgentTimeout = DefaultUrgentTimeout
	}
	return nil
}

// selectionResult reports the outcome of one route-selection run.
type selectionResult struct {
	changed     []netip.Prefix
	urgent      bool
	updates     []*Route
	retractions []*Route
}

type Speaker struct {
	Interfaces InterfaceTable
	Sources    SourceTable
	Routes     RouteTable

	conn6 *ipv6.PacketConn
	conn4 *ipv4.PacketConn

	config       SpeakerConfig
	costProvider *CostProvider
	logger       *slog.Logger

	// mu serialises route-table, source-table, selection and sequence
	// number state. It must not be held while blocking on I/O.
	mu sync.Mutex

	localSeqNo proto.SequenceNumber

	selected        map[netip.Prefix]*Route
	lastFingerprint map[netip.Prefix]string

	routeChanged chan struct{}
	notifyOnce   sync.Once
	notifyDone   chan struct{}

	sweepTicker *time.Ticker
	sweepDone   chan struct{}
	workerWG    sync.WaitGroup
	closeOnce   sync.Once
}

func NewSpeaker(cfg *SpeakerConfig) (*Speaker, error) {
	s := &Speaker{
		config:          *cfg,
		Interfaces:      NewInterfaceTable(),
		Sources:         NewSourceTable(),
		Routes:          NewRouteTable(),
		selected:        make(map[netip.Prefix]*Route),
		lastFingerprint: make(map[netip.Prefix]string),
		routeChanged:    make(chan struct{}, 1),
		notifyDone:      make(chan struct{}),
		sweepDone:       make(chan struct{}),
	}

	if err := s.config.SetDefaults(); err != nil {
		return nil, err
	}

	s.logger = s.config.Logger
	if s.config.Cost != nil {
		s.costProvider = s.config.Cost
	} else {
		s.costProvider = DefaultCostProvider()
	}

	var err error
	if s.conn6, err = s.createConn6(); err != nil {
		return nil, fmt.Errorf("failed to create IPv6 conn: %w", err)
	}
	if s.conn4, err = s.createConn4(); err != nil {
		s.conn6.Close()
		return nil, fmt.Errorf("failed to create IPv4 conn: %w", err)
	}

	intfs, err := net.Interfaces()
	if err != nil {
		s.conn6.Close()
		s.conn4.Close()
		return nil, fmt.Errorf("failed to get interfaces: %w", err)
	}

	created := make([]*Interface, 0, 8)
	for _, intf := range intfs {
		if intf.Flags&net.FlagLoopback != 0 {
			continue
		}
		if cfg.InterfaceFilter != nil && !cfg.InterfaceFilter(intf.Name) {
			continue
		}
		i, err := s.newInterface(intf.Index)
		if err != nil {
			for _, createdInterface := range created {
				_ = createdInterface.Close()
			}
			s.conn6.Close()
			s.conn4.Close()
			return nil, fmt.Errorf("failed to create interface: %w", err)
		}
		if i == nil {
			// The interface was skipped (for example multicast was
			// requested but is unavailable and no unicast neighbours are
			// configured); the reason was already logged.
			continue
		}

		if h, ok := s.config.Handler.(InterfaceHandler); ok {
			h.InterfaceAdded(i)
		}

		s.Interfaces.Insert(i)
		created = append(created, i)
	}

	s.sweepTicker = time.NewTicker(time.Second)
	s.workerWG.Add(4)
	go s.runSweep()
	go s.runNotifier()
	go s.runReadLoop6()
	go s.runReadLoop4()

	return s, nil
}

func (s *Speaker) Close() error {
	var closeErr error
	s.closeOnce.Do(func() {
		s.sweepTicker.Stop()
		close(s.sweepDone)
		close(s.notifyDone)
		s.Interfaces.Foreach(func(_ int, i *Interface) error {
			closeErr = errors.Join(closeErr, i.Close())
			return nil
		})
		if err := s.conn6.Close(); err != nil {
			closeErr = errors.Join(closeErr, err)
		}
		if err := s.conn4.Close(); err != nil {
			closeErr = errors.Join(closeErr, err)
		}
		s.workerWG.Wait()
	})
	return closeErr
}

// Advertise injects a local route (a directly attached network or a route
// redistributed by the data plane) into the Babel domain with the given
// metric (usually LocalRouteMetric). It returns an error when the prefix is
// invalid.
func (s *Speaker) Advertise(pfx netip.Prefix, metric proto.Metric) error {
	if !pfx.IsValid() {
		return errors.New("invalid prefix")
	}
	pfx = pfx.Masked()

	s.mu.Lock()
	if r, ok := s.Routes.LookupByNeighbour(pfx, nil); ok {
		if r.AdvertisedMetric == metric && r.SeqNo == s.localSeqNo {
			s.mu.Unlock()
			return nil
		}
		r.AdvertisedMetric = metric
		r.SeqNo = s.bumpLocalSeqNoLocked()
		r.Expiry = time.Time{}
		s.logger.Info("Updated local route", slog.String("prefix", pfx.String()), slog.Int("metric", int(metric)))
	} else {
		seqno := s.bumpLocalSeqNoLocked()
		r := &Route{
			Source: &Source{
				Prefix:   pfx,
				RouterID: s.config.RouterID,
				SeqNo:    seqno,
				Metric:   int(metric),
			},
			AdvertisedMetric: metric,
			Metric:           metric,
			SmoothedMetric:   metric,
			SeqNo:            seqno,
			Feasible:         true,
			Local:            true,
			PathRTTMicros:    0,
		}
		s.Routes.Insert(r)
		s.logger.Info("Added local route", slog.String("prefix", pfx.String()), slog.Int("metric", int(metric)))
	}
	res := s.runSelectionLocked()
	s.mu.Unlock()

	s.afterSelection(res)
	return nil
}

// Withdraw removes a locally injected route and triggers a retraction.
func (s *Speaker) Withdraw(pfx netip.Prefix) error {
	if !pfx.IsValid() {
		return errors.New("invalid prefix")
	}
	pfx = pfx.Masked()

	s.mu.Lock()
	r, ok := s.Routes.LookupByNeighbour(pfx, nil)
	if !ok {
		s.mu.Unlock()
		return nil
	}
	s.Routes.Remove(r)
	s.logger.Info("Withdrew local route", slog.String("prefix", pfx.String()))
	res := s.runSelectionLocked()
	s.mu.Unlock()

	s.afterSelection(res)
	return nil
}

// SelectedRoutes returns the current forwarding set: the primary route plus
// any multipath candidates for every reachable prefix. TH installs these
// into its own route tables.
func (s *Speaker) SelectedRoutes() []SelectedRoute {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]SelectedRoute, 0)
	for _, pfx := range s.Routes.Prefixes() {
		selected := s.selected[pfx]
		if selected == nil {
			continue
		}
		out = append(out, s.exportForPrefixLocked(pfx, selected)...)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Prefix.String() < out[j].Prefix.String()
	})
	return out
}

// SelectedRouteForPrefix returns the primary route for a prefix, if any.
func (s *Speaker) SelectedRouteForPrefix(pfx netip.Prefix) (*Route, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.selected[pfx.Masked()]
	return r, ok && r != nil
}

// SetNeighbourCost is the bandwidth-measurement hook: callers feed a
// measured link cost (e.g. BandwidthCost) and the next route selection uses
// it for this neighbour instead of the nominal cost.
func (s *Speaker) SetNeighbourCost(ifName string, addr netip.Addr, cost proto.Metric) {
	i, ok := s.Interfaces.LookupByName(ifName)
	if !ok {
		return
	}
	if n, ok := i.Neighbours.Lookup(addr); ok {
		n.SetCostOverride(cost)
	}
}

// NeighbourRTT returns the smoothed RTT measured for a neighbour. It is the
// raw signal the data plane uses for weighted-ECMP decisions, independent
// of the bounded protocol cost.
func (s *Speaker) NeighbourRTT(ifName string, addr netip.Addr) (time.Duration, bool) {
	i, ok := s.Interfaces.LookupByName(ifName)
	if !ok {
		return 0, false
	}
	n, ok := i.Neighbours.Lookup(addr)
	if !ok {
		return 0, false
	}
	return n.RTT(), n.HasRTT()
}

func (s *Speaker) runSweep() {
	defer s.workerWG.Done()
	for {
		select {
		case <-s.sweepDone:
			return
		case <-s.sweepTicker.C:
			s.sweep()
		}
	}
}

func (s *Speaker) sweep() {
	now := time.Now()

	s.mu.Lock()
	for _, r := range s.Routes.All() {
		if r.Local || r.Expiry.IsZero() {
			continue
		}
		if now.Before(r.Expiry) {
			continue
		}
		if r.Metric != proto.Retraction {
			r.Metric = proto.Retraction
			r.Expired = true
			r.Expiry = now.Add(s.config.RouteExpiryTime)
		} else {
			s.Routes.Remove(r)
		}
	}
	for _, src := range s.Sources.All() {
		if !src.GC.IsZero() && now.After(src.GC) {
			s.Sources.Remove(src.Prefix, src.RouterID)
		}
	}
	res := s.runSelectionLocked()
	s.mu.Unlock()

	s.afterSelection(res)
}

func (s *Speaker) runNotifier() {
	defer s.workerWG.Done()
	for {
		select {
		case <-s.notifyDone:
			return
		case <-s.routeChanged:
			if h, ok := s.config.Handler.(RouteHandler); ok {
				h.RoutesChanged()
			}
		}
	}
}

// afterSelection handles the side effects of a selection run that must not
// happen while s.mu is held.
func (s *Speaker) afterSelection(res selectionResult) {
	if len(res.changed) == 0 {
		return
	}
	select {
	case s.routeChanged <- struct{}{}:
	default:
	}
	s.sendTriggeredUpdates(res.updates, res.retractions, res.urgent)
}

// sendTriggeredUpdates implements RFC 8966 Section 3.7.2. Updates are
// subject to split horizon; retractions are sent on every interface.
func (s *Speaker) sendTriggeredUpdates(updates, retractions []*Route, urgent bool) {
	s.Interfaces.Foreach(func(_ int, i *Interface) error {
		var localUpdates []*Route
		for _, r := range updates {
			if r.Local || r.Neighbour == nil || r.Neighbour.intf != i || !s.config.SplitHorizon {
				localUpdates = append(localUpdates, r)
			}
		}
		i.sendTriggered(localUpdates, retractions, urgent)
		return nil
	})
}

// advertisedRoutes returns the routes to advertise on an interface: local
// routes, selected routes not learnt on this interface (split horizon) and
// hold-time retraction entries that have not expired.
func (s *Speaker) advertisedRoutes(iface *Interface) (updates, retractions []*Route) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for _, pfx := range s.Routes.Prefixes() {
		for _, r := range s.Routes.ForPrefix(pfx) {
			if r.Local {
				updates = append(updates, r)
				continue
			}
			if r.Metric == proto.Retraction {
				if !r.Expiry.IsZero() && now.Before(r.Expiry) {
					retractions = append(retractions, r)
				}
				continue
			}
			if r.Selected && (r.Neighbour == nil || r.Neighbour.intf != iface || !s.config.SplitHorizon) {
				updates = append(updates, r)
			}
		}
	}
	return
}

// encodeRoutes builds the RouterId/NextHop/Update TLV sequence for the
// given routes, updating source-table feasibility distances first.
func (s *Speaker) encodeRoutes(iface *Interface, routes []*Route, rttMicros int64) []proto.Value {
	s.mu.Lock()
	defer s.mu.Unlock()

	values := make([]proto.Value, 0, len(routes)*3)
	var linkLocal netip.Addr
	var interfaceV4 netip.Addr
	if ip, err := iface.findLinkLocalAddress(); err == nil {
		if addr, ok := netip.AddrFromSlice(ip); ok {
			linkLocal = addr
		}
	}
	if ip := iface.sourceAddress4(); ip != nil {
		if addr, ok := netip.AddrFromSlice(ip); ok {
			interfaceV4 = addr
		}
	}
	for _, r := range routes {
		isV4 := r.Source.Prefix.Addr().Is4()
		// The advertised next hop is this node's own address on the
		// outgoing interface: the receiver must send towards us.
		var nextHop netip.Addr
		if isV4 && interfaceV4.IsValid() {
			nextHop = interfaceV4
		} else if linkLocal.IsValid() {
			nextHop = linkLocal
		}
		// v4-via-v6 is only used when the outgoing interface has no IPv4
		// address (RFC 9229 Section 2.1).
		v4ViaV6 := isV4 && !interfaceV4.IsValid()

		if r.Local {
			values = append(values, &proto.RouterIDValue{RouterID: s.config.RouterID})
			if nextHop.IsValid() {
				values = append(values, &proto.NextHop{NextHop: nextHop})
			}
			s.sourceFeasibilityLocked(r.Source.Prefix, s.config.RouterID, r.SeqNo, int(r.AdvertisedMetric))
			values = append(values, &proto.Update{
				Prefix:             r.Source.Prefix,
				Seqno:              r.SeqNo,
				Metric:             r.AdvertisedMetric,
				Interval:           s.config.UpdateInterval,
				V4ViaV6:            v4ViaV6,
				PathBottleneckMbps: iface.bandwidthMbps,
				PathRTTMicros:      rttMicros,
			})
			continue
		}
		if r.Metric == proto.Retraction {
			continue
		}
		values = append(values, &proto.RouterIDValue{RouterID: r.Source.RouterID})
		if nextHop.IsValid() {
			values = append(values, &proto.NextHop{NextHop: nextHop})
		}
		s.sourceFeasibilityLocked(r.Source.Prefix, r.Source.RouterID, r.SeqNo, int(r.Metric))
		bottleneckOut := 0
		switch {
		case r.PathBottleneckMbps > 0 && iface.bandwidthMbps > 0:
			bottleneckOut = min(r.PathBottleneckMbps, iface.bandwidthMbps)
		case r.PathBottleneckMbps > 0:
			bottleneckOut = r.PathBottleneckMbps
		case iface.bandwidthMbps > 0:
			bottleneckOut = iface.bandwidthMbps
		}
		rttOut := rttMicros
		if r.PathRTTMicros > 0 {
			rttOut += r.PathRTTMicros
		}
		values = append(values, &proto.Update{
			Prefix:             r.Source.Prefix,
			Seqno:              r.SeqNo,
			Metric:             r.Metric,
			Interval:           s.config.UpdateInterval,
			V4ViaV6:            v4ViaV6,
			PathBottleneckMbps: bottleneckOut,
			PathRTTMicros:      rttOut,
		})
	}
	return values
}

// encodeRetraction builds a retraction (infinite metric) update.
func (s *Speaker) encodeRetraction(rid proto.RouterID, seqno proto.SequenceNumber, pfx netip.Prefix) []proto.Value {
	s.mu.Lock()
	defer s.mu.Unlock()
	return []proto.Value{
		&proto.RouterIDValue{RouterID: rid},
		&proto.Update{
			Prefix:   pfx,
			Seqno:    seqno,
			Metric:   proto.Retraction,
			Interval: s.config.UpdateInterval,
		},
	}
}

// sourceFeasibilityLocked maintains the source table (RFC 8966 Section 3.7.3)
// before a finite update is sent.
func (s *Speaker) sourceFeasibilityLocked(pfx netip.Prefix, rid proto.RouterID, seqno uint16, metric int) {
	src, ok := s.Sources.Lookup(pfx, rid)
	if !ok {
		s.Sources.Insert(&Source{
			Prefix:   pfx,
			RouterID: rid,
			SeqNo:    seqno,
			Metric:   metric,
			GC:       time.Now().Add(s.config.SourceGCTime),
		})
		return
	}
	src.UpdateFeasibility(seqno, metric)
	src.GC = time.Now().Add(s.config.SourceGCTime)
}

// bumpLocalSeqNoLocked increments the local sequence number (modulo 2^16).
func (s *Speaker) bumpLocalSeqNoLocked() proto.SequenceNumber {
	s.localSeqNo++
	return s.localSeqNo
}

func (s *Speaker) bumpLocalSeqNo() {
	s.mu.Lock()
	s.bumpLocalSeqNoLocked()
	s.mu.Unlock()
}

// LocalSeqNo returns the current local sequence number.
func (s *Speaker) LocalSeqNo() proto.SequenceNumber {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.localSeqNo
}

// onUpdateReceived implements RFC 8966 Section 3.5.3 (route acquisition).
func (s *Speaker) onUpdateReceived(n *Neighbour, upd *proto.Update) {
	pfx := upd.Prefix.Masked()
	if pfx.Addr().Is4In6() {
		pfx = netip.PrefixFrom(pfx.Addr().Unmap(), pfx.Bits())
	}
	rid := upd.RouterID
	if rid == proto.RouterIDUnspecified {
		s.logger.Debug("Ignoring update without router-id", slog.String("prefix", pfx.String()))
		return
	}

	s.mu.Lock()
	res := func() selectionResult {
		defer s.mu.Unlock()

		src, srcExists := s.Sources.Lookup(pfx, rid)
		// RFC 8966 Section 3.5.1: an update is feasible when it is a
		// retraction, when no source entry exists, or when it is strictly
		// better than the feasibility distance.
		feasible := upd.Metric == proto.Retraction || !srcExists || src.Feasible(upd.Seqno, upd.Metric)

		r, exists := s.Routes.LookupByNeighbour(pfx, n)
		if !exists {
			if !feasible {
				s.logger.Debug("Ignoring unfeasible update for unknown route",
					slog.String("prefix", pfx.String()))
				return selectionResult{}
			}
			if upd.Metric == proto.Retraction {
				return selectionResult{} // retraction of a route we do not know about
			}
			nextHop := upd.NextHop
			if !nextHop.IsValid() {
				nextHop = n.Address
			}
			r = &Route{
				Source: &Source{
					Prefix:   pfx,
					RouterID: rid,
					SeqNo:    upd.Seqno,
					Metric:   int(upd.Metric),
				},
				Neighbour:          n,
				AdvertisedMetric:   upd.Metric,
				SeqNo:              upd.Seqno,
				NextHop:            nextHop,
				Feasible:           true,
				Expiry:             time.Now().Add(s.config.RouteExpiryTime),
				PathBottleneckMbps: upd.PathBottleneckMbps,
				PathRTTMicros:      upd.PathRTTMicros,
			}
			s.Routes.Insert(r)
			s.logger.Info("Learnt route",
				slog.String("prefix", pfx.String()),
				slog.String("neighbour", n.Address.String()),
				slog.Any("metric", upd.Metric))
		} else {
			if r.Selected && !feasible && r.Source.RouterID == rid {
				// RFC 8966: this update MAY be ignored; ignoring keeps a
				// selected route stable in the face of flapping updates.
				return selectionResult{}
			}
			r.Source.RouterID = rid
			r.SeqNo = upd.Seqno
			r.AdvertisedMetric = upd.Metric
			r.Feasible = feasible
			r.Expired = false
			r.PathBottleneckMbps = upd.PathBottleneckMbps
			r.PathRTTMicros = upd.PathRTTMicros
			if upd.NextHop.IsValid() {
				r.NextHop = upd.NextHop
			}
			r.Expiry = time.Now().Add(s.config.RouteExpiryTime)
		}

		return s.runSelectionLocked()
	}()
	s.afterSelection(res)
}

// onNeighbourCostChanged re-runs route selection after a link-cost change.
func (s *Speaker) onNeighbourCostChanged(n *Neighbour) {
	s.mu.Lock()
	res := s.runSelectionLocked()
	s.mu.Unlock()
	s.afterSelection(res)
}

// onNeighbourRemoved drops all routes learnt from a neighbour.
func (s *Speaker) onNeighbourRemoved(n *Neighbour) {
	s.mu.Lock()
	s.Routes.RemoveNeighbour(n)
	res := s.runSelectionLocked()
	s.mu.Unlock()
	s.afterSelection(res)
}

// handleSeqnoRequest implements RFC 8966 Section 3.8.1.2 under the speaker
// lock so route state and the local sequence number are read and mutated
// atomically. Network sends happen after the lock is released.
func (s *Speaker) handleSeqnoRequest(n *Neighbour, sr *proto.SeqnoRequest) {
	var send []*Route
	var forward *proto.SeqnoRequest
	var forwardTo *Neighbour

	s.mu.Lock()
	if r, ok := s.selected[sr.Prefix.Masked()]; ok && r != nil && r.Metric != proto.Retraction {
		ridMatches := r.Source.RouterID == sr.RouterID
		switch {
		case !ridMatches || !proto.SeqnoLess(r.SeqNo, sr.Seqno):
			send = append(send, r)
		case ridMatches && r.Source.RouterID == s.config.RouterID:
			r.SeqNo = s.bumpLocalSeqNoLocked()
			send = append(send, r)
		}
	}
	if send == nil && sr.HopCount >= 2 {
		if next := s.forwardNeighbourLocked(sr.Prefix, n); next != nil {
			forwarded := *sr
			forwarded.HopCount--
			forward, forwardTo = &forwarded, next
		}
	}
	s.mu.Unlock()

	if len(send) > 0 {
		n.sendUpdateForRoutes(send, true)
	}
	if forward != nil {
		forwardTo.sendSeqnoRequest(forward)
	}
}

// forwardNeighbourLocked selects the next hop for forwarding a seqno request
// (RFC 8966 Section 3.8.1.2): a feasible route first, any other route
// otherwise, never back to the requesting neighbour.
func (s *Speaker) forwardNeighbourLocked(pfx netip.Prefix, requesting *Neighbour) *Neighbour {
	routes := s.Routes.ForPrefix(pfx)
	for _, r := range routes {
		if r.Feasible && r.Metric != proto.Retraction && r.Neighbour != nil && r.Neighbour != requesting {
			return r.Neighbour
		}
	}
	for _, r := range routes {
		if r.Neighbour != nil && r.Neighbour != requesting {
			return r.Neighbour
		}
	}
	return nil
}

// runSelectionLocked performs route selection for every prefix, applies the
// hysteresis from RFC 8966 Appendix A.3 and computes multipath candidates.
// It must be called with s.mu held.
func (s *Speaker) runSelectionLocked() selectionResult {
	res := selectionResult{}
	prefixes := s.Routes.Prefixes()
	newSelected := make(map[netip.Prefix]*Route, len(prefixes))
	newFingerprints := make(map[netip.Prefix]string, len(prefixes))

	for _, pfx := range prefixes {
		routes := s.Routes.ForPrefix(pfx)
		candidates := make([]*Route, 0, len(routes))
		for _, r := range routes {
			if r.Local {
				r.Metric = r.AdvertisedMetric
				r.Feasible = true
				r.updateSmoothedMetric(s.config.SmoothingAlpha)
				candidates = append(candidates, r)
				continue
			}
			if r.Expired {
				r.Metric = proto.Retraction
				r.updateSmoothedMetric(s.config.SmoothingAlpha)
				continue
			}
			cost := r.Neighbour.Cost()
			r.Metric = s.costProvider.Metric(cost, r.AdvertisedMetric)
			if s.config.BottleneckPenalty > 0 && r.PathBottleneckMbps > 0 && r.Metric != proto.Retraction {
				penalty := uint16(s.config.BottleneckPenalty / float64(r.PathBottleneckMbps))
				if penalty > 0 {
					if int(r.Metric)+int(penalty) > int(proto.Retraction)-1 {
						r.Metric = proto.Retraction - 1
					} else {
						r.Metric += penalty
					}
				}
			}
			r.updateSmoothedMetric(s.config.SmoothingAlpha)
			if r.Feasible && r.Metric != proto.Retraction {
				candidates = append(candidates, r)
			}
		}

		var selected *Route
		if len(candidates) > 0 {
			best := candidates[0]
			for _, c := range candidates[1:] {
				if routeLess(c, best) {
					best = c
				}
			}
			prev := s.selected[pfx]
			if prev != nil && containsRoute(candidates, prev) && prev != best {
				if best.Metric < prev.Metric && best.SmoothedMetric < prev.SmoothedMetric {
					selected = best
				} else {
					selected = prev
				}
			} else {
				selected = best
			}
		}

		for _, r := range routes {
			r.Selected = r == selected
		}
		newSelected[pfx] = selected
		newFingerprints[pfx] = s.exportFingerprintLocked(pfx, selected)

		prev := s.selected[pfx]
		if s.lastFingerprint[pfx] == newFingerprints[pfx] {
			continue
		}
		res.changed = append(res.changed, pfx)
		switch {
		case selected != nil && prev != nil && prev.Source.RouterID != selected.Source.RouterID:
			res.urgent = true
			res.updates = append(res.updates, selected)
		case selected != nil:
			res.updates = append(res.updates, selected)
		case prev != nil:
			res.retractions = append(res.retractions, prev)
		}
	}

	// Prefixes that were selected before but have disappeared entirely.
	for pfx, prev := range s.selected {
		if _, ok := newSelected[pfx]; ok {
			continue
		}
		res.changed = append(res.changed, pfx)
		res.retractions = append(res.retractions, prev)
		delete(s.lastFingerprint, pfx)
	}

	s.selected = newSelected
	for pfx, fp := range newFingerprints {
		s.lastFingerprint[pfx] = fp
	}
	return res
}

// runSelection executes route selection and applies its side effects
// (handler notification and triggered updates).
func (s *Speaker) runSelection() {
	s.mu.Lock()
	res := s.runSelectionLocked()
	s.mu.Unlock()
	s.afterSelection(res)
}

// UpdateECMPParams applies data-plane ECMP parameters (multipath limits and
// the bottleneck penalty) to a running speaker without rebuilding it, so
// adjacencies are not disturbed. It re-runs route selection so metric
// changes from the penalty take effect immediately.
func (s *Speaker) UpdateECMPParams(maxPaths int, slack uint16, bottleneckPenalty float64) {
	s.mu.Lock()
	changed := false
	if s.config.MaxPaths != maxPaths {
		s.config.MaxPaths = maxPaths
		changed = true
	}
	if s.config.MultipathSlack != slack {
		s.config.MultipathSlack = slack
		changed = true
	}
	if s.config.BottleneckPenalty != bottleneckPenalty {
		s.config.BottleneckPenalty = bottleneckPenalty
		changed = true
	}
	s.mu.Unlock()
	if changed {
		s.runSelection()
	}
}

func routeLess(a, b *Route) bool {
	if a.Metric != b.Metric {
		return a.Metric < b.Metric
	}
	if c := a.NextHop.Compare(b.NextHop); c != 0 {
		return c < 0
	}
	return strings.Compare(hex.EncodeToString(a.Source.RouterID[:]), hex.EncodeToString(b.Source.RouterID[:])) < 0
}

func containsRoute(routes []*Route, target *Route) bool {
	for _, r := range routes {
		if r == target {
			return true
		}
	}
	return false
}

// exportCandidatesLocked returns the routes to export for a prefix: the
// primary route plus feasible routes within MultipathSlack of its metric,
// limited to MaxPaths entries.
func (s *Speaker) exportCandidatesLocked(pfx netip.Prefix, selected *Route) []*Route {
	if selected == nil {
		return nil
	}
	if selected.Local {
		return []*Route{selected}
	}

	limit := s.config.MaxPaths
	if limit < 1 {
		limit = 1
	}
	slack := int(s.config.MultipathSlack)
	candidates := make([]*Route, 0, limit)
	candidates = append(candidates, selected)
	for _, r := range s.Routes.ForPrefix(pfx) {
		if r == selected || !r.Feasible || r.Metric == proto.Retraction {
			continue
		}
		if int(r.Metric) > int(selected.Metric)+slack {
			continue
		}
		candidates = append(candidates, r)
	}
	sort.SliceStable(candidates[1:], func(i, j int) bool {
		return routeLess(candidates[i+1], candidates[j+1])
	})
	if len(candidates) > limit {
		candidates = candidates[:limit]
	}
	return candidates
}

func (s *Speaker) exportForPrefixLocked(pfx netip.Prefix, selected *Route) []SelectedRoute {
	candidates := s.exportCandidatesLocked(pfx, selected)
	out := make([]SelectedRoute, 0, len(candidates))
	for _, r := range candidates {
		ifName := ""
		if r.Neighbour != nil {
			ifName = r.Neighbour.intf.Name
		}
		out = append(out, SelectedRoute{
			Prefix:         r.Source.Prefix,
			RouterID:       r.Source.RouterID,
			NextHop:        r.NextHop,
			Interface:      ifName,
			Metric:         r.Metric,
			Local:          r.Local,
			BottleneckMbps: r.PathBottleneckMbps,
			PathRTTMicros:  r.PathRTTMicros,
		})
	}
	return out
}

func (s *Speaker) exportFingerprintLocked(pfx netip.Prefix, selected *Route) string {
	exported := s.exportForPrefixLocked(pfx, selected)
	parts := make([]string, 0, len(exported))
	for _, r := range exported {
		parts = append(parts, fmt.Sprintf("%s|%s|%s|%d", r.Prefix, r.NextHop, r.Interface, r.Metric))
	}
	return strings.Join(parts, ",")
}

func (s *Speaker) runReadLoop6() {
	defer s.workerWG.Done()
	s.logger.Debug("Start receiving packets")

	buf := make([]byte, 1500)

	for {
		n, cm, sAddr, err := s.conn6.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			s.logger.Error("Failed to read from socket", slog.Any("error", err))
			continue
		}

		srcAddr := proto.AddressFrom(sAddr).WithZone("")
		rxTime := timestampNow()
		dstAddr, ok := netip.AddrFromSlice(cm.Dst)
		if !ok {
			s.logger.Error("Invalid destination address")
			continue
		}

		if !srcAddr.IsLinkLocalUnicast() && !srcAddr.Is4() && !srcAddr.Is4In6() {
			s.logger.Debug("Ignoring packet from non-link-local source", slog.Any("saddr", srcAddr))
			continue
		}

		if udpAddr, ok := sAddr.(*net.UDPAddr); !ok {
			s.logger.Debug("Ignoring non UDP source address", slog.Any("saddr", srcAddr))
			continue
		} else if udpAddr.Port != Port {
			s.logger.Debug("Ignoring packet from non-babel source port", slog.Any("saddr", udpAddr))
			continue
		}

		if !proto.IsBabelPacket(buf[:n]) {
			s.logger.Debug("Ignoring non-babel packet")
			continue
		}

		p := proto.NewParser()
		_, pkt, err := p.Packet(buf[:n])
		if err != nil {
			s.logger.Error("Failed to decode packet", slog.Any("error", err))
			continue
		}

		if err := s.onPacket(pkt, cm.IfIndex, srcAddr, dstAddr, rxTime); err != nil {
			s.logger.Error("Failed to handle packet", slog.Any("error", err))
			continue
		}
	}
}

func (s *Speaker) runReadLoop4() {
	defer s.workerWG.Done()
	s.logger.Debug("Start receiving IPv4 packets")

	buf := make([]byte, 1500)

	for {
		n, cm, sAddr, err := s.conn4.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			s.logger.Error("Failed to read from IPv4 socket", slog.Any("error", err))
			continue
		}

		srcAddr := proto.AddressFrom(sAddr).WithZone("")
		if srcAddr.Is4() {
			// Neighbour keys are normalised to the 4-in-6 form.
			srcAddr = netip.AddrFrom16(srcAddr.As16())
		}
		dstAddr, ok := netip.AddrFromSlice(cm.Dst)
		if !ok {
			s.logger.Error("Invalid IPv4 destination address")
			continue
		}

		if udpAddr, ok := sAddr.(*net.UDPAddr); !ok {
			s.logger.Debug("Ignoring non UDP source address", slog.Any("saddr", sAddr))
			continue
		} else if udpAddr.Port != Port {
			s.logger.Debug("Ignoring packet from non-babel source port", slog.Any("saddr", udpAddr))
			continue
		}

		if !proto.IsBabelPacket(buf[:n]) {
			s.logger.Debug("Ignoring non-babel packet")
			continue
		}

		p := proto.NewParser()
		_, pkt, err := p.Packet(buf[:n])
		if err != nil {
			s.logger.Error("Failed to decode packet", slog.Any("error", err))
			continue
		}

		if err := s.onPacket(pkt, cm.IfIndex, srcAddr, dstAddr, timestampNow()); err != nil {
			s.logger.Error("Failed to handle packet", slog.Any("error", err))
			continue
		}
	}
}

func (s *Speaker) createConn6() (*ipv6.PacketConn, error) {
	udpConn, err := net.ListenUDP("udp6", &net.UDPAddr{
		Port: Port,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create socket: %w", err)
	}

	pktConn := ipv6.NewPacketConn(udpConn)

	if err := pktConn.SetControlMessage(ipv6.FlagDst|ipv6.FlagInterface|ipv6.FlagSrc, true); err != nil {
		return nil, fmt.Errorf("failed to set destination flag: %w", err)
	}
	if err := pktConn.SetHopLimit(1); err != nil {
		return nil, fmt.Errorf("failed to set hop limit: %w", err)
	}
	if err := pktConn.SetMulticastHopLimit(1); err != nil {
		return nil, fmt.Errorf("failed to set multicast hop limit: %w", err)
	}
	if err := pktConn.SetMulticastLoopback(false); err != nil {
		return nil, fmt.Errorf("failed to set multicast loopback: %w", err)
	}
	if err := pktConn.SetTrafficClass(TrafficClassNetworkControl); err != nil {
		return nil, fmt.Errorf("failed to set traffic class: %w", err)
	}

	return pktConn, nil
}

func (s *Speaker) createConn4() (*ipv4.PacketConn, error) {
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{
		Port: Port,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create IPv4 socket: %w", err)
	}

	pktConn := ipv4.NewPacketConn(udpConn)

	if err := pktConn.SetControlMessage(ipv4.FlagDst|ipv4.FlagInterface|ipv4.FlagSrc, true); err != nil {
		return nil, fmt.Errorf("failed to set IPv4 control messages: %w", err)
	}
	if err := pktConn.SetTTL(1); err != nil {
		return nil, fmt.Errorf("failed to set IPv4 TTL: %w", err)
	}
	if err := pktConn.SetMulticastTTL(1); err != nil {
		return nil, fmt.Errorf("failed to set multicast TTL: %w", err)
	}
	if err := pktConn.SetMulticastLoopback(false); err != nil {
		return nil, fmt.Errorf("failed to disable multicast loopback: %w", err)
	}

	return pktConn, nil
}

func (s *Speaker) onPacket(pkt *proto.Packet, ifIndex int, srcAddr, dstAddr proto.Address, rxTime proto.Timestamp) error {
	i, ok := s.Interfaces.Lookup(ifIndex)
	if !ok {
		s.logger.Debug("Ignoring packet from unknown interface", slog.Int("ifindex", ifIndex))
		return nil
	}
	return i.onPacket(pkt, srcAddr, dstAddr, rxTime)
}
