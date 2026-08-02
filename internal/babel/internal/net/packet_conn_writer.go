// SPDX-FileCopyrightText: 2023-2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package net

import (
	"io"
	"net"

	"golang.org/x/net/ipv6"
)

type PacketConnWriter struct {
	PacketConn *ipv6.PacketConn
	Dest       net.Addr
	// Src, when set, pins the IPv6 source address of every packet through
	// an IPV6_PKTINFO control message. Babel uses the interface's
	// configured link-local address so peers can match it against their
	// configured neighbours even when the interface has multiple
	// auto-generated link-local addresses.
	Src net.IP

	// IfIndex pins the outgoing interface for link-local destinations.
	IfIndex int
}

var _ = (io.Writer)(&PacketConnWriter{})

func (w *PacketConnWriter) Write(p []byte) (int, error) {
	if w.Src != nil {
		return w.PacketConn.WriteTo(p, &ipv6.ControlMessage{Src: w.Src, IfIndex: w.IfIndex}, w.Dest)
	}
	return w.PacketConn.WriteTo(p, nil, w.Dest)
}
