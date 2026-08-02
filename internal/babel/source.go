// SPDX-FileCopyrightText: 2023-2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package babel

import (
	"net/netip"
	"time"

	"github.com/TunnelHelper/TH/internal/babel/proto"
)

// 3.2.5. The Source Table
// https://datatracker.ietf.org/doc/html/rfc8966#section-3.2.5
//
// Source tracks the feasibility distance for a source (prefix + router-id):
// the best (seqno, metric) pair ever sent by the local node for that source
// (RFC 8966 Section 3.7.3), plus the garbage-collection deadline.
type Source struct {
	Prefix   netip.Prefix
	RouterID proto.RouterID

	Metric int
	SeqNo  uint16
	GC     time.Time
}

// UpdateFeasibility applies Section 3.7.3 before sending a finite update:
// the stored distance is the minimum of all finite updates sent so far.
// It returns true when the stored distance changed.
func (s *Source) UpdateFeasibility(seqno uint16, metric int) bool {
	changed := false
	if proto.SeqnoLess(s.SeqNo, seqno) {
		s.SeqNo = seqno
		s.Metric = metric
		changed = true
	} else if s.SeqNo == seqno && metric < s.Metric {
		s.Metric = metric
		changed = true
	}
	return changed
}

// Feasible reports whether an update carrying (seqno, metric) passes the
// feasibility condition (Section 3.5.1) with respect to this source entry.
// When no source entry exists the update is feasible (handled by callers).
func (s *Source) Feasible(seqno uint16, metric proto.Metric) bool {
	return proto.SeqnoLess(s.SeqNo, seqno) || (s.SeqNo == seqno && int(metric) < s.Metric)
}
