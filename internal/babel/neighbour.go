// SPDX-FileCopyrightText: 2023-2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package babel

import (
	"log/slog"
	"math"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/TunnelHelper/TH/internal/babel/internal/deadline"
	"github.com/TunnelHelper/TH/internal/babel/internal/history"
	netx "github.com/TunnelHelper/TH/internal/babel/internal/net"
	"github.com/TunnelHelper/TH/internal/babel/internal/queue"
	"github.com/TunnelHelper/TH/internal/babel/proto"
)

// 3.2.4. The Neighbour Table
// https://datatracker.ietf.org/doc/html/rfc8966#section-3.2.4

type Neighbour struct {
	intf *Interface

	logger *slog.Logger

	Address proto.Address

	TxCost uint16

	helloUnicast   history.HelloHistory
	helloMulticast history.HelloHistory

	outgoingUnicastHelloSeqNo proto.SequenceNumber

	ihuTicker        *time.Ticker
	helloTicker      *time.Ticker
	delayProbeTicker *time.Ticker
	ihuTimeout       deadline.Deadline

	queue *queue.Queue

	// Static marks neighbours configured explicitly for unicast bootstrap
	// on non-multicast links (e.g. WireGuard peers).
	Static bool

	// costOverride, when set, replaces the interface nominal cost in the
	// reception-cost computation. TH uses it to feed measured bandwidth
	// or latency into routing decisions.
	costOverride *proto.Metric

	// RFC 9616 delay-based metric state.
	stateMu            sync.RWMutex
	lastHelloOrigin    proto.Timestamp // timestamp of the last Hello received from this neighbour
	lastHelloReceive   proto.Timestamp // local receive time of that Hello
	hasHelloTimestamps bool
	delayMu            sync.RWMutex
	delayStats         DelayStats
	lastPublishedDelay DelayStats
	lastDelayPublish   time.Time

	done      chan struct{}
	stopped   chan struct{}
	closeOnce sync.Once
}

// timestampNow returns the current time in microseconds, wrapped to 32 bits
// as required by the RFC 9616 timestamp extension.
func timestampNow() proto.Timestamp {
	return proto.Timestamp(time.Now().UnixMicro())
}

func (i *Interface) NewNeighbour(addr proto.Address) (*Neighbour, error) {
	zone := ""
	if addr.IsLinkLocalUnicast() {
		// Link-local destinations require the interface zone so the
		// kernel can resolve the scope.
		zone = i.Name
	}
	neighbourAddr := &net.UDPAddr{
		IP:   addr.AsSlice(),
		Port: Port,
		Zone: zone,
	}
	if addr.Is4In6() {
		neighbourAddr = &net.UDPAddr{
			IP: addr.Unmap().AsSlice(),
			// The IPv4 socket has no zone.
			Port: Port,
		}
	}

	n := &Neighbour{
		Address: addr,
		// Start with the nominal cost instead of zero so the link cost
		// stays strictly positive (RFC 8966 Section 3.4.3) until the
		// first IHU updates it.
		TxCost: i.nominalCost,

		queue: queue.NewQueue(babelPayloadSize(i.MTU, !addr.Unmap().Is4()), &netx.PacketConnWriter{
			Conn6:   i.speaker.conn6,
			Conn4:   i.speaker.conn4,
			Dest:    neighbourAddr,
			Src:     i.sourceAddress(),
			Src4:    i.sourceAddress4(),
			IfIndex: i.Index,
		}),

		ihuTimeout: deadline.NewDeadline(),
		ihuTicker:  time.NewTicker(i.speaker.config.IHUInterval),

		intf: i,

		logger:  i.logger,
		done:    make(chan struct{}),
		stopped: make(chan struct{}),
	}

	// Only create a unicast hello ticker when enabled; otherwise keep a
	// stopped ticker so the goroutine can be started later.
	if interval := n.intf.speaker.config.UnicastHelloInterval; interval > 0 {
		n.helloTicker = time.NewTicker(interval)
	} else {
		n.helloTicker = time.NewTicker(math.MaxInt64)
		n.helloTicker.Stop()
	}
	if interval := n.intf.speaker.config.DelayProbeInterval; n.intf.speaker.config.DelayMetric && interval > 0 {
		n.delayProbeTicker = time.NewTicker(interval)
	} else {
		n.delayProbeTicker = time.NewTicker(math.MaxInt64)
		n.delayProbeTicker.Stop()
	}

	return n, nil
}

func (n *Neighbour) startTimers() {
	go n.runTimers()
}

func (n *Neighbour) runTimers() {
	defer close(n.stopped)
	for {
		select {
		case <-n.done:
			return
		case <-n.helloTicker.C:
			if err := n.sendUnicastHello(); err != nil {
				n.logger.Error("Failed to send Hello", slog.Any("error", err))
			}

		case <-n.ihuTicker.C:
			if err := n.sendIHU(); err != nil {
				n.logger.Error("Failed to send IHU", slog.Any("error", err))
			}
		case <-n.delayProbeTicker.C:
			// Re-evaluate freshness even when no response arrives; otherwise a
			// once-valid estimate could remain in route cost until IHU expiry.
			n.intf.speaker.onNeighbourCostChanged(n)
			if now := time.Now(); n.shouldPublishDelay(now) {
				n.sendDelayUpdate()
				n.intf.speaker.notifyRouteMetricsChanged()
			}
			if err := n.sendDelayProbe(); err != nil {
				n.logger.Error("Failed to send delay probe", slog.Any("error", err))
			}

		case <-n.ihuTimeout.C:
			n.logger.Warn("IHU deadline missed")
			n.setTransmissionCost(proto.Retraction)
			n.intf.speaker.onNeighbourCostChanged(n)
		}
	}
}

// Close stops the neighbour timers and its outgoing queue.
func (n *Neighbour) Close() error {
	var closeErr error
	n.closeOnce.Do(func() {
		close(n.done)
		n.ihuTicker.Stop()
		n.helloTicker.Stop()
		if n.delayProbeTicker != nil {
			n.delayProbeTicker.Stop()
		}
		n.ihuTimeout.Stop()
		<-n.stopped
		if n.queue != nil {
			closeErr = n.queue.Close()
		}
	})
	return closeErr
}

func (n *Neighbour) onUpdate(upd *proto.Update) {
	n.intf.speaker.onUpdateReceived(n, upd)
}

func (n *Neighbour) onHello(hello *proto.Hello, rxTime proto.Timestamp) {
	if isUnicast := hello.Flags&proto.FlagHelloUnicast != 0; isUnicast {
		n.helloUnicast.Update(hello.Seqno)
	} else {
		n.helloMulticast.Update(hello.Seqno)
	}
	if hello.Timestamp != nil {
		n.stateMu.Lock()
		n.lastHelloOrigin = hello.Timestamp.Transmit
		n.lastHelloReceive = rxTime
		n.hasHelloTimestamps = true
		n.stateMu.Unlock()
	}

	n.logger.Debug("Handled Hello", "rxcost", n.RxCost())
}

func (n *Neighbour) onIHU(ihu *proto.IHU) {
	n.ihuTimeout.Reset(time.Duration(n.intf.speaker.config.IHUHoldTimeFactor * float32(ihu.Interval)))

	old := n.setTransmissionCost(ihu.RxCost)
	if old != ihu.RxCost {
		n.intf.speaker.onNeighbourCostChanged(n)
	}

	n.logger.Debug("Handled IHU", "txcost", ihu.RxCost, "rxcost", n.RxCost(), "cost", n.Cost())
}

// onRouteRequest implements RFC 8966 Section 3.8.1.1.
func (n *Neighbour) onRouteRequest(rr *proto.RouteRequest) {
	s := n.intf.speaker
	if rr.Wildcard || isWildcardPrefix(rr.Prefix) {
		n.sendFullDump()
		return
	}

	pfx := rr.Prefix.Masked()
	if r, ok := s.SelectedRouteForPrefix(pfx); ok && r.Metric != proto.Retraction {
		n.sendUpdateForRoutes([]*Route{r}, true)
	} else {
		n.sendRetraction(pfx)
	}
}

// onSeqnoRequest implements RFC 8966 Section 3.8.1.2.
func (n *Neighbour) onSeqnoRequest(sr *proto.SeqnoRequest) {
	n.intf.speaker.handleSeqnoRequest(n, sr)
}

func (n *Neighbour) onAcknowledgmentRequest(ar *proto.AcknowledgmentRequest) {
	if err := n.sendAcknowledgment(ar.Opaque, ar.Interval*3/5); err != nil {
		n.logger.Error("Failed to send acknowledgement", slog.Any("error", err))
	}
}

func (n *Neighbour) onAcknowledgment(a *proto.Acknowledgment) {
}

func (n *Neighbour) onPacket(pkt *proto.Packet, srcAddr, dstAddr proto.Address, rxTime proto.Timestamp) error {
	var helloTimestamp *proto.TimestampHello
	var ihuTimestamp *proto.TimestampIHU

	for _, value := range pkt.Body {
		typ := proto.ValuesType(value).String()
		n.logger.Debug("Received value",
			slog.Any("type", typ),
			slog.Any(strings.ToLower(typ), value))

		switch value := value.(type) {
		case *proto.Update:
			n.onUpdate(value)
		case *proto.Acknowledgment:
			n.onAcknowledgment(value)
		case *proto.AcknowledgmentRequest:
			n.onAcknowledgmentRequest(value)
		case *proto.Hello:
			n.onHello(value, rxTime)
			helloTimestamp = value.Timestamp
		case *proto.IHU:
			n.onIHU(value)
			ihuTimestamp = value.Timestamp
		case *proto.RouteRequest:
			n.onRouteRequest(value)
		case *proto.SeqnoRequest:
			n.onSeqnoRequest(value)
		}
	}

	if helloTimestamp != nil && ihuTimestamp != nil {
		n.computeRTT(rxTime, helloTimestamp, ihuTimestamp)
	}

	return nil
}

// computeRTT implements the Mills-style RTT estimation from RFC 9616
// Section 3.2: RTT = (t2 - t1) - (t2' - t1'), where t1/t1' are the Origin
// and Receive timestamps carried by the peer's IHU and t2' is the peer's
// Hello transmit timestamp.
func (n *Neighbour) computeRTT(t2 proto.Timestamp, hello *proto.TimestampHello, ihu *proto.TimestampIHU) {
	s := n.intf.speaker
	if !s.config.DelayMetric {
		return
	}
	const maxTimestampAge = uint32(3 * time.Minute / time.Microsecond)

	// RFC 9616 Section 3.3: discard stale or nonsensical samples.
	originAge := int32(t2 - ihu.Origin)
	if originAge < 0 || uint32(originAge) > maxTimestampAge {
		return
	}
	processingDelay := int32(hello.Transmit - ihu.Receive)
	if processingDelay < 0 || uint32(processingDelay) > maxTimestampAge {
		return
	}
	rttMicros := int32((t2 - ihu.Origin) - (hello.Transmit - ihu.Receive))
	if rttMicros < 0 || uint32(rttMicros) > maxTimestampAge {
		return
	}

	sample := time.Duration(rttMicros) * time.Microsecond
	now := time.Now()
	n.recordDelaySample(sample, now)
	stats := n.DelayStats()
	n.logger.Debug("RTT sample", slog.Duration("rtt", stats.Mean), slog.Duration("jitter", stats.Jitter()), slog.Uint64("samples", uint64(stats.Samples)))
	s.onNeighbourCostChanged(n)
	if n.shouldPublishDelay(now) {
		n.sendDelayUpdate()
		s.notifyRouteMetricsChanged()
	}
}

func (n *Neighbour) recordDelaySample(sample time.Duration, now time.Time) {
	n.delayMu.Lock()
	n.delayStats = n.delayStats.updated(sample, now,
		n.intf.speaker.config.DelaySmoothingTimeConstant,
		n.intf.speaker.config.DelayMinWindow)
	n.delayMu.Unlock()
}

// DelayStats returns a consistent copy of the neighbour's current estimator.
func (n *Neighbour) DelayStats() DelayStats {
	n.delayMu.RLock()
	defer n.delayMu.RUnlock()
	return n.delayStats
}

func (n *Neighbour) shouldPublishDelay(now time.Time) bool {
	n.delayMu.Lock()
	defer n.delayMu.Unlock()
	stats := n.delayStats
	if stats.Samples < n.intf.speaker.config.DelayWarmupSamples {
		return false
	}
	minInterval := max(2*n.intf.speaker.config.DelayProbeInterval, 2*time.Second)
	if !n.lastDelayPublish.IsZero() && now.Sub(n.lastDelayPublish) < minInterval {
		return false
	}
	old := n.lastPublishedDelay
	significant := old.Samples == 0 || relativeDurationChange(old.Mean, stats.Mean, time.Millisecond) > 0.10 ||
		relativeDurationChange(old.Jitter(), stats.Jitter(), time.Millisecond) > 0.10 ||
		math.Abs(old.Confidence(n.lastDelayPublish, n.intf.speaker.config.DelayWarmupSamples, n.intf.speaker.config.DelaySampleMaxAge)-
			stats.Confidence(now, n.intf.speaker.config.DelayWarmupSamples, n.intf.speaker.config.DelaySampleMaxAge)) > 0.10 ||
		now.Sub(n.lastDelayPublish) >= n.intf.speaker.config.UpdateInterval
	if !significant {
		return false
	}
	n.lastPublishedDelay = stats
	n.lastDelayPublish = now
	return true
}

func relativeDurationChange(a, b, floor time.Duration) float64 {
	denominator := max(absDuration(a), absDuration(b), floor)
	if denominator <= 0 {
		return 0
	}
	return float64(absDuration(a-b)) / float64(denominator)
}

func absDuration(value time.Duration) time.Duration {
	if value < 0 {
		return -value
	}
	return value
}

// RTT returns the smoothed round-trip time measured for this neighbour.
func (n *Neighbour) RTT() time.Duration {
	return n.DelayStats().Mean
}

// HasRTT reports whether at least one valid RTT sample was measured.
func (n *Neighbour) HasRTT() bool {
	return n.DelayStats().Samples > 0
}

// HasFreshRTT reports whether the estimate is sufficiently warmed up and has
// not exceeded the configured sample age.
func (n *Neighbour) HasFreshRTT() bool {
	s := n.DelayStats()
	return s.Fresh(time.Now(), n.intf.speaker.config.DelayWarmupSamples, n.intf.speaker.config.DelaySampleMaxAge)
}

func (n *Neighbour) sendUnicastHello() error {
	n.outgoingUnicastHelloSeqNo++
	hello := &proto.Hello{
		Flags:    proto.FlagHelloUnicast,
		Seqno:    n.outgoingUnicastHelloSeqNo,
		Interval: n.intf.speaker.config.UnicastHelloInterval,
	}
	if n.intf.speaker.config.DelayMetric {
		hello.Timestamp = &proto.TimestampHello{Transmit: timestampNow()}
	}
	n.queue.SendValue(hello, n.intf.speaker.config.UnicastHelloInterval*3/5)

	return nil
}

func (n *Neighbour) sendIHU() error {
	return n.sendIHUWithin(n.intf.speaker.config.IHUInterval * 3 / 5)
}

func (n *Neighbour) sendDelayProbe() error {
	return n.sendIHUWithin(n.intf.speaker.config.DelayProbeInterval / 2)
}

func (n *Neighbour) sendIHUWithin(maxDelay time.Duration) error {
	ihu := &proto.IHU{
		RxCost:   n.RxCost(),
		Address:  n.Address,
		Interval: n.intf.speaker.config.IHUInterval,
	}
	values := []proto.Value{ihu}
	if n.intf.speaker.config.DelayMetric {
		// RFC 9616 Section 3.2: the IHU must travel in a packet that also
		// carries a timestamped Hello, and echoes the timestamps of the
		// last Hello received from this neighbour.
		n.outgoingUnicastHelloSeqNo++
		hello := &proto.Hello{
			Flags:     proto.FlagHelloUnicast,
			Seqno:     n.outgoingUnicastHelloSeqNo,
			Interval:  n.intf.speaker.config.UnicastHelloInterval,
			Timestamp: &proto.TimestampHello{Transmit: timestampNow()},
		}
		origin, receive, hasTimestamps := n.helloTimestampSnapshot()
		if hasTimestamps {
			ihu.Timestamp = &proto.TimestampIHU{
				Origin:  origin,
				Receive: receive,
			}
		}
		values = []proto.Value{hello, ihu}
	}
	n.queue.SendValues(values, maxDelay)

	return nil
}

func (n *Neighbour) sendAcknowledgment(opaque uint16, interval time.Duration) error {
	n.queue.SendValue(&proto.Acknowledgment{
		Opaque: opaque,
	}, interval*2/3)

	return nil
}

// A.2.1. k-out-of-j
// See: https://datatracker.ietf.org/doc/html/rfc8966#section-a.2.1
func (n *Neighbour) RxCost() proto.Metric {
	provider := n.intf.speaker.costProvider
	return provider.RxCost(n, n.intf.nominalCost)
}

// Cost returns the link cost towards this neighbour, combining the
// reception cost (derived from Hello history and overrides) with the
// transmission cost (from IHU packets) according to the configured policy.
func (n *Neighbour) Cost() proto.Metric {
	s := n.intf.speaker
	// Delay measurements describe quality, not reachability. Always honour
	// Hello/IHU liveness first so a stale finite RTT can never keep a dead
	// neighbour usable.
	base := s.costProvider.Combine(n.RxCost(), n.transmissionCost())
	if base == proto.Retraction {
		return proto.Retraction
	}
	cost := base
	if override, ok := n.costOverrideValue(); ok {
		cost = override
	} else if s.config.DelayMetric && n.HasFreshRTT() {
		cost = DelayCost(n.RTT(), n.intf.nominalCost, s.config.DelayMin, s.config.DelayMax, s.config.DelayMaxPenalty)
	}
	return addMetricPenalty(cost, InverseBandwidthPenalty(s.config.BottleneckPenalty, n.intf.bandwidthMbps))
}

// SetCostOverride replaces the nominal cost used for this neighbour with an
// operator-provided value. It is the bandwidth-measurement hook: callers
// feed measured values here and the next route selection picks them up.
func (n *Neighbour) SetCostOverride(cost proto.Metric) {
	if cost == 0 {
		cost = 1
	}
	n.stateMu.Lock()
	if cost == proto.Retraction {
		n.costOverride = nil
	} else {
		n.costOverride = &cost
	}
	n.stateMu.Unlock()
	n.intf.speaker.onNeighbourCostChanged(n)
}

func (n *Neighbour) transmissionCost() proto.Metric {
	n.stateMu.RLock()
	defer n.stateMu.RUnlock()
	return n.TxCost
}

func (n *Neighbour) setTransmissionCost(cost proto.Metric) proto.Metric {
	n.stateMu.Lock()
	defer n.stateMu.Unlock()
	old := n.TxCost
	n.TxCost = cost
	return old
}

func (n *Neighbour) costOverrideValue() (proto.Metric, bool) {
	n.stateMu.RLock()
	defer n.stateMu.RUnlock()
	if n.costOverride == nil {
		return 0, false
	}
	return *n.costOverride, true
}

func (n *Neighbour) helloTimestampSnapshot() (proto.Timestamp, proto.Timestamp, bool) {
	n.stateMu.RLock()
	defer n.stateMu.RUnlock()
	return n.lastHelloOrigin, n.lastHelloReceive, n.hasHelloTimestamps
}

// sendUpdateForRoutes sends RouterId/NextHop/Update TLVs for the given
// routes, optionally as an urgent triggered update.
func (n *Neighbour) sendUpdateForRoutes(routes []*Route, urgent bool) {
	maxDelay := n.intf.speaker.config.UpdateInterval
	if urgent {
		maxDelay = n.intf.speaker.config.UrgentTimeout
	}
	values := n.intf.speaker.encodeRoutes(n.intf, routes, n.DelayStats())
	if len(values) == 0 {
		return
	}
	n.queue.SendValues(values, maxDelay)
}

func (n *Neighbour) sendRetraction(pfx proto.Prefix) {
	rid := n.intf.speaker.config.RouterID
	seqno := n.intf.speaker.LocalSeqNo()
	n.queue.SendValues(n.intf.speaker.encodeRetraction(rid, seqno, pfx), n.intf.speaker.config.UrgentTimeout)
}

func (n *Neighbour) sendFullDump() {
	updates, retractions := n.intf.speaker.advertisedRoutes(n.intf)
	values := n.intf.speaker.encodeRoutes(n.intf, updates, n.DelayStats())
	for _, r := range retractions {
		values = append(values, n.intf.speaker.encodeRetraction(r.Source.RouterID, r.SeqNo, r.Source.Prefix)...)
	}
	if len(values) > 0 {
		n.queue.SendValues(values, n.intf.speaker.config.UpdateInterval)
	}
}

func (n *Neighbour) sendDelayUpdate() {
	updates, retractions := n.intf.speaker.advertisedRoutes(n.intf)
	values := n.intf.speaker.encodeRoutes(n.intf, updates, n.DelayStats())
	for _, r := range retractions {
		values = append(values, n.intf.speaker.encodeRetraction(r.Source.RouterID, r.SeqNo, r.Source.Prefix)...)
	}
	if len(values) > 0 {
		n.queue.SendValues(values, n.intf.speaker.config.UrgentTimeout)
	}
}

func (n *Neighbour) sendSeqnoRequest(sr *proto.SeqnoRequest) {
	n.queue.SendValue(sr, n.intf.speaker.config.UrgentTimeout)
}

func (n *Neighbour) sendRouteRequest(pfx proto.Prefix) {
	n.queue.SendValue(&proto.RouteRequest{Prefix: pfx}, n.intf.speaker.config.UrgentTimeout)
}

func isWildcardPrefix(pfx proto.Prefix) bool {
	// The AE=0 wildcard is tracked separately on RouteRequest.Wildcard;
	// here only a structurally invalid prefix is treated as wildcard.
	return pfx.Bits() < 0 || !pfx.Addr().IsValid()
}
