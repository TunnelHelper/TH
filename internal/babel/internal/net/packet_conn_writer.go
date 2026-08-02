// SPDX-FileCopyrightText: 2023-2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package net

import (
	"errors"
	"io"
	"net"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type PacketConnWriter struct {
	Conn6 *ipv6.PacketConn
	Conn4 *ipv4.PacketConn
	// Dest is the primary IPv6 destination (a multicast group for
	// multicast interfaces, or a unicast neighbour address). IPv4 unicast
	// destinations are detected from the address itself.
	Dest net.Addr
	// Dest4, when set, additionally sends every value as an IPv4 multicast
	// datagram. It is used on multicast interfaces that can carry IPv4 so
	// IPv4-only peers on the same link can hear the announcements.
	Dest4 net.Addr
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
	var (
		total      int
		sendErrors []error
	)
	if w.Dest4 != nil {
		written, err := w.write4(p, w.Dest4)
		total += written
		if err != nil {
			sendErrors = append(sendErrors, err)
		}
	}
	if w.Dest != nil {
		written, err := w.writeDest(p)
		total += written
		if err != nil {
			sendErrors = append(sendErrors, err)
		}
	}
	if len(sendErrors) == 0 {
		return total, nil
	}
	if total == 0 {
		return 0, errors.Join(sendErrors...)
	}
	return total, nil
}

// writeDest sends to the primary destination, choosing the IPv4 socket when
// the destination itself is an IPv4 address (unicast neighbours) and the
// IPv6 socket otherwise.
func (w *PacketConnWriter) writeDest(p []byte) (int, error) {
	if udp, ok := w.Dest.(*net.UDPAddr); ok && udp.IP.To4() != nil {
		return w.write4(p, w.Dest)
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

// write4 sends one datagram over the IPv4 socket, pinning the source when
// available. A pinned source may be unusable (e.g. still tentative after
// duplicate-address detection); the kernel is allowed to choose instead.
func (w *PacketConnWriter) write4(p []byte, dest net.Addr) (int, error) {
	message := &ipv4.ControlMessage{IfIndex: w.IfIndex}
	if w.Src4 != nil {
		message.Src = w.Src4
	}
	written, err := w.Conn4.WriteTo(p, message, dest)
	if err == nil {
		return written, nil
	}
	return w.Conn4.WriteTo(p, nil, dest)
}
