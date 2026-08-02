// SPDX-FileCopyrightText: 2023-2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package net

import (
	"io"
	"net"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type PacketConnWriter struct {
	Conn6 *ipv6.PacketConn
	Conn4 *ipv4.PacketConn
	Dest  net.Addr
	// Src, when set, pins the IPv6 source address of every packet through
	// an IPV6_PKTINFO control message. Babel uses the interface's
	// configured link-local address so peers can match it against their
	// configured neighbours even when the interface has multiple
	// auto-generated link-local addresses.
	Src net.IP
	// Src4 pins the IPv4 source address for IPv4 destinations.
	Src4 net.IP

	// IfIndex pins the outgoing interface for link-local destinations.
	IfIndex int
}

var _ = (io.Writer)(&PacketConnWriter{})

func (w *PacketConnWriter) Write(p []byte) (int, error) {
	if udp, ok := w.Dest.(*net.UDPAddr); ok && udp.IP.To4() != nil {
		message := &ipv4.ControlMessage{IfIndex: w.IfIndex}
		if w.Src4 != nil {
			message.Src = w.Src4
		}
		written, err := w.Conn4.WriteTo(p, message, w.Dest)
		if err == nil {
			return written, nil
		}
		// A pinned source may be unusable (e.g. still tentative after
		// duplicate-address detection); let the kernel choose instead.
		return w.Conn4.WriteTo(p, nil, w.Dest)
	}
	message := &ipv6.ControlMessage{IfIndex: w.IfIndex}
	if w.Src != nil {
		message.Src = w.Src
	}
	written, err := w.Conn6.WriteTo(p, message, w.Dest)
	if err == nil {
		return written, nil
	}
	return w.Conn6.WriteTo(p, nil, w.Dest)
}
