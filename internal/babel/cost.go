// SPDX-FileCopyrightText: 2023-2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package babel

import (
	"math"
	"time"

	"github.com/TunnelHelper/TH/internal/babel/proto"
)

// CostProvider makes the cost and metric computation of a Babel node
// pluggable. RFC 8966 Section 3.4.3 explicitly leaves the combination of
// rxcost (derived from Hello reception) and txcost (from IHU packets) to
// local policy; Section 3.5.2 does the same for metric computation. This
// is the hook used to feed measured bandwidth or latency into routing
// decisions without changing the protocol.
type CostProvider struct {
	// RxCost computes the reception cost for a neighbour. nominal is the
	// interface's nominal link cost. Return proto.Retraction when the
	// link is considered down. When nil, the RFC 8966 Appendix A.2.1
	// 2-out-of-3 strategy is used (nominal cost when at least 2 of the
	// last 3 Hellos were received, infinity otherwise).
	RxCost func(n *Neighbour, nominal proto.Metric) proto.Metric

	// Combine merges rxcost and txcost into the link cost used for metric
	// computation. When nil, the cost equals txcost unless rxcost is
	// infinite, in which case the link is down (Section 3.4.3 constraints:
	// cost is strictly positive; infinite when no Hellos were received
	// recently or when txcost is infinite).
	Combine func(rxcost, txcost proto.Metric) proto.Metric

	// Metric computes M(cost, advertised), the metric of a route learnt
	// from a neighbour (Section 3.5.2). When nil, the additive metric
	// M(c, m) = c + m, saturated at 65535, is used.
	Metric func(cost, advertised proto.Metric) proto.Metric
}

func defaultRxCost(n *Neighbour, nominal proto.Metric) proto.Metric {
	if n.helloUnicast.OutOf(2, 3) || n.helloMulticast.OutOf(2, 3) {
		if override, ok := n.costOverrideValue(); ok {
			return override
		}
		return nominal
	}
	return proto.Retraction
}

func defaultCombine(rxcost, txcost proto.Metric) proto.Metric {
	if rxcost == proto.Retraction {
		return proto.Retraction
	}
	return txcost
}

func defaultMetric(cost, advertised proto.Metric) proto.Metric {
	if cost == proto.Retraction || advertised == proto.Retraction {
		return proto.Retraction
	}
	sum := int(cost) + int(advertised)
	if sum >= int(proto.Retraction) {
		return proto.Retraction - 1
	}
	return proto.Metric(sum)
}

// DefaultCostProvider returns the RFC 8966 recommended behaviour for wired
// links: 2-out-of-3 link sensing with additive metrics.
func DefaultCostProvider() *CostProvider {
	return &CostProvider{
		RxCost:  defaultRxCost,
		Combine: defaultCombine,
		Metric:  defaultMetric,
	}
}

// BandwidthCost maps a measured bandwidth to a Babel link cost. It uses the
// traditional wired-link formula cost = 256 * (1 + 1e6 / kbps), saturated
// below infinity. Higher bandwidth yields lower cost, so the shortest-path
// selection naturally prefers faster links. A zero or invalid bandwidth
// returns infinity.
func BandwidthCost(bps uint64) proto.Metric {
	kbps := bps / 1000
	if kbps == 0 {
		return proto.Retraction
	}
	cost := uint64(256) * (1 + 1000000/kbps)
	if cost >= uint64(proto.Retraction) {
		return proto.Retraction - 1
	}
	return proto.Metric(cost)
}

// DelayCost maps a measured RTT to a link cost using the bounded linear
// mapping recommended by RFC 9616 Section 4.2: the nominal cost below
// rtt-min, a linear increase between rtt-min and rtt-max, and the constant
// nominal + max-rtt-penalty at or above rtt-max.
func DelayCost(rtt time.Duration, nominal uint16, min, max time.Duration, maxPenalty uint16) proto.Metric {
	if rtt <= min {
		return nominal
	}
	if rtt >= max {
		return nominal + maxPenalty
	}
	fraction := float64(rtt-min) / float64(max-min)
	extra := uint16(fraction*float64(maxPenalty) + 0.5)
	return nominal + extra
}

// InverseBandwidthPenalty maps a local link bandwidth to an additive Babel
// cost. Applying the penalty once per link keeps the metric additive; applying
// K/bottleneck repeatedly to an already accumulated path metric would count
// the same bottleneck once at every downstream hop.
func InverseBandwidthPenalty(k float64, bandwidthMbps int) proto.Metric {
	if k <= 0 || bandwidthMbps <= 0 || math.IsNaN(k) {
		return 0
	}
	penalty := k / float64(bandwidthMbps)
	if math.IsInf(penalty, 1) || penalty >= float64(proto.Retraction-1) {
		return proto.Retraction - 1
	}
	return proto.Metric(math.Round(penalty))
}

func addMetricPenalty(metric, penalty proto.Metric) proto.Metric {
	if metric == proto.Retraction {
		return proto.Retraction
	}
	if int(metric)+int(penalty) >= int(proto.Retraction) {
		return proto.Retraction - 1
	}
	return metric + penalty
}
