// SPDX-FileCopyrightText: 2023-2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package proto

import (
	"log/slog"
	"net/netip"
)

// 4.6.9. Update
// https://datatracker.ietf.org/doc/html/rfc8966#section-4.6.9
type Update struct {
	Flags    uint8          // The individual bits of this field specify special handling of this TLV (see FlagUpdate*).
	Interval Interval       // An upper bound, expressed in centiseconds, on the time after which the sending node will send a new update for this prefix. This MUST NOT be 0. The receiving node will use this value to compute a hold time for the route table entry. The value FFFF hexadecimal (infinity) expresses that this announcement will not be repeated unless a request is received (Section 3.8.2.3).
	Seqno    SequenceNumber // The originator's sequence number for this update.
	Metric   Metric         // The sender's metric for this route. The value FFFF hexadecimal (infinity) means that this is a route retraction.
	Prefix   netip.Prefix   // The prefix being advertised. This field's size is (Plen/8 - Omitted) rounded upwards.

	// The following fields are not actually encoded in an update TLV.
	// Instead are derived from the parser state / preceding TLVs.
	RouterID RouterID // Taken from a previous RouterID TLV
	NextHop  Address  // Taken from a previous NextHop TLV

	// V4ViaV6 marks an IPv4 prefix announced with the AE=4 (v4-via-v6)
	// encoding from RFC 9229: the IPv4 prefix is carried with an IPv6
	// next hop, allowing IPv4 routes over interfaces without an IPv4
	// address. It is derived from the AE field, not encoded separately.
	V4ViaV6 bool

	// PathBottleneckMbps is the end-to-end bottleneck bandwidth (Mbps) of
	// the path being announced. Zero means unset/unknown (treated as
	// unlimited). It is carried in a PathMetrics sub-TLV.
	PathBottleneckMbps int

	// PathRTTMicros is the accumulated end-to-end smoothed RTT (microseconds)
	// of the path being announced. Negative means unset/unknown. It is
	// carried in a PathMetrics sub-TLV and wrapped on the wire.
	PathRTTMicros int64

	// Sub-TLVs
	SourcePrefix *Prefix
}

func (u *Update) LogValue() slog.Value {
	attrs := []slog.Attr{
		slog.Any("flags", u.Flags),
		slog.Duration("intv", u.Interval),
		slog.Any("seqno", u.Seqno),
		slog.Any("metric", u.Metric),
		slog.Any("pfx", u.Prefix),
		slog.Any("rid", u.RouterID),
		slog.Any("nh", u.NextHop),
	}

	if u.SourcePrefix != nil {
		attrs = append(attrs,
			slog.Any("src_prefix", *u.SourcePrefix))
	}

	return slog.GroupValue(attrs...)
}
