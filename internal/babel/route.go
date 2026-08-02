// SPDX-FileCopyrightText: 2023-2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package babel

import (
	"encoding/hex"
	"net/netip"
	"time"

	"github.com/TunnelHelper/TH/internal/babel/proto"
)

// 3.2.6. The Route Table
// https://datatracker.ietf.org/doc/html/rfc8966#section-3.2.6
//
// Route is a single entry in the route table, indexed by destination
// prefix and the neighbour it was learnt from (RFC 8966 Section 3.5.3).
// A local route (injected by the local node) has a nil Neighbour.
type Route struct {
	Source    *Source
	Neighbour *Neighbour

	// AdvertisedMetric is the metric carried by the update this route was
	// learnt from (or LocalRouteMetric for local routes).
	AdvertisedMetric proto.Metric

	// Metric is the route metric computed from the advertised metric and
	// the link cost: M(cost, advertised). proto.Retraction means
	// unreachable.
	Metric         proto.Metric
	SmoothedMetric uint16
	SeqNo          proto.SequenceNumber
	NextHop        netip.Addr

	// Feasible reports whether the last received update passed the
	// feasibility condition (RFC 8966 Section 3.5.1). Local routes are
	// always feasible.
	Feasible bool

	// Selected is true for the primary route chosen for a destination
	// prefix. Multipath candidates are exported in addition to it.
	Selected bool

	// Local marks routes injected by the local node.
	Local bool

	// Expiry is the time at which the route's hold time expires. A zero
	// value means the entry has no expiry timer (local routes).
	Expiry time.Time

	// Expired marks a route whose expiry timer fired. It stays in the
	// table as a hold-time retraction and is never selected again until a
	// fresh finite update arrives.
	Expired bool
}

// SelectedRoute is an exported view of a route chosen by the selection
// procedure. It is the unit handed to the data plane (TH) for kernel route
// installation and weighted ECMP.
type SelectedRoute struct {
	Prefix    netip.Prefix
	RouterID  proto.RouterID
	NextHop   netip.Addr
	Interface string
	Metric    proto.Metric
	Local     bool
}

func (r *Route) key() (netip.Prefix, netip.Addr) {
	neighbour := netip.Addr{}
	if r.Neighbour != nil {
		neighbour = r.Neighbour.Address
	}
	return r.Source.Prefix, neighbour
}

// updateSmoothedMetric applies the exponential smoothing from RFC 8966
// Appendix A.3. Infinite metrics are kept at infinity so a lost route does
// not need to be "un-learned" gradually.
func (r *Route) updateSmoothedMetric(alpha float64) {
	if r.Metric == proto.Retraction {
		r.SmoothedMetric = proto.Retraction
		return
	}
	if r.SmoothedMetric == 0 {
		r.SmoothedMetric = r.Metric
		return
	}
	if r.Metric == r.SmoothedMetric {
		return
	}
	smoothed := float64(r.SmoothedMetric) + alpha*(float64(r.Metric)-float64(r.SmoothedMetric))
	if smoothed < 1 {
		smoothed = 1
	}
	if smoothed > float64(proto.Retraction-1) {
		smoothed = float64(proto.Retraction - 1)
	}
	r.SmoothedMetric = uint16(smoothed + 0.5)
}

// fingerprint returns a stable string identity for change detection.
func (r *Route) fingerprint() string {
	return r.Source.Prefix.String() + "/" + hex.EncodeToString(r.Source.RouterID[:]) + "/" + r.NextHop.String()
}
