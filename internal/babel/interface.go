// SPDX-FileCopyrightText: 2023-2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package babel

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	netx "github.com/TunnelHelper/TH/internal/babel/internal/net"
	"github.com/TunnelHelper/TH/internal/babel/internal/queue"
	"github.com/TunnelHelper/TH/internal/babel/proto"
)

const (
	// TrafficClassNetworkControl represents a class selector code-point
	// as defined by RFC 2474. Routing protocols are recommended to use
	// the network control service class (CS6) as recommended by RFC 4594.
	TrafficClassNetworkControl = 48 << 2 // DiffServ / DSCP name CS6
)

// 3.2.3. The Interface Table
// https://datatracker.ietf.org/doc/html/rfc8966#section-3.2.3

type Interface struct {
	*net.Interface

	multicast bool

	// nominalCost is the cost used by the default k-out-of-j link sensing.
	// It can be overridden per neighbour through Neighbour.SetCostOverride.
	nominalCost proto.Metric

	Neighbours NeighbourTable

	helloMulticastSeqNo proto.SequenceNumber
	helloMulticastTimer *time.Ticker
	periodicUpdateTimer *time.Ticker

	queue   *queue.Queue
	speaker *Speaker

	logger *slog.Logger

	done      chan struct{}
	stopped   chan struct{}
	closeOnce sync.Once
}

func (s *Speaker) newInterface(index int) (*Interface, error) {
	intf, err := net.InterfaceByIndex(index)
	if err != nil {
		return nil, err
	}

	i := &Interface{
		Interface:  intf,
		Neighbours: NewNeighbourTable(),

		speaker: s,

		multicast:           s.config.Multicast,
		nominalCost:         s.config.NominalLinkCost,
		helloMulticastTimer: time.NewTicker(s.config.MulticastHelloInterval),
		periodicUpdateTimer: time.NewTicker(s.config.UpdateInterval),

		logger: s.config.Logger.With(
			slog.String("intf", intf.Name)),
		done:    make(chan struct{}),
		stopped: make(chan struct{}),
	}

	if i.multicast {
		multicastAddr := &net.UDPAddr{
			IP:   MulticastGroupIPv6.AsSlice(),
			Port: Port,
		}

		i.queue = queue.NewQueue(intf.MTU, &netx.PacketConnWriter{
			PacketConn: i.speaker.conn,
			Dest:       multicastAddr,
			Src:        i.sourceAddress(),
			IfIndex:    intf.Index,
		})

		if err := i.speaker.conn.JoinGroup(i.Interface, multicastAddr); err != nil {
			return nil, fmt.Errorf("failed to join multicast group: %w", err)
		}
	} else {
		i.queue = queue.NewQueue(intf.MTU, &netx.PacketConnWriter{
			PacketConn: i.speaker.conn,
			Dest:       nil,
			Src:        i.sourceAddress(),
			IfIndex:    intf.Index,
		})
	}

	// Bootstrap static neighbours on non-multicast links (e.g. WireGuard):
	// create the neighbour entries up front and send an initial unicast
	// Hello so the remote side learns about us immediately.
	if static, ok := s.config.StaticNeighbours[intf.Name]; ok {
		for _, addr := range static {
			if err := i.addStaticNeighbour(addr); err != nil {
				return nil, err
			}
		}
	}

	go i.runTimers()

	i.logger.Debug("Added new interface")

	return i, nil
}

func (i *Interface) addStaticNeighbour(addr proto.Address) error {
	addr = addr.WithZone("")
	if _, exists := i.Neighbours.Lookup(addr); exists {
		return nil
	}
	n, err := i.NewNeighbour(addr)
	if err != nil {
		return fmt.Errorf("create static neighbour %s: %w", addr, err)
	}
	n.Static = true
	i.Neighbours.Insert(n)
	i.logger.Info("Added static neighbour", slog.String("addr", addr.String()))

	if h, ok := i.speaker.config.Handler.(NeighbourHandler); ok {
		h.NeighbourAdded(n)
	}

	// Send the initial unicast Hello immediately to speed up adjacency.
	if i.speaker.config.UnicastHelloInterval > 0 {
		_ = n.sendUnicastHello()
	}
	return nil
}

func (i *Interface) Close() error {
	var closeErr error
	i.closeOnce.Do(func() {
		close(i.done)
		i.periodicUpdateTimer.Stop()
		i.helloMulticastTimer.Stop()
		_ = i.Neighbours.Foreach(func(n *Neighbour) error {
			closeErr = errors.Join(closeErr, n.Close())
			return nil
		})
		if i.queue != nil {
			closeErr = errors.Join(closeErr, i.queue.Close())
		}
		<-i.stopped
	})
	return closeErr
}

func (i *Interface) runTimers() {
	defer close(i.stopped)
	for {
		select {
		case <-i.done:
			return
		case <-i.periodicUpdateTimer.C:
			if err := i.sendUpdate(); err != nil {
				i.logger.Error("Failed to send periodic update", slog.Any("error", err))
			}

		case <-i.helloMulticastTimer.C:
			if err := i.sendMulticastHello(); err != nil {
				i.logger.Error("Failed to send multicast hello", slog.Any("error", err))
			}
		}
	}
}

func (i *Interface) onPacket(pkt *proto.Packet, srcAddr, dstAddr proto.Address) error {
	// Neighbour identity is per-interface; strip the link zone so a packet
	// received on this interface always matches its configured address.
	srcAddr = srcAddr.WithZone("")
	isMulticast := dstAddr.IsLinkLocalMulticast()

	i.logger.Debug("Received packet",
		slog.Any("src_addr", srcAddr),
		slog.Any("dst_addr", dstAddr),
		slog.Bool("multicast", isMulticast),
		slog.Any("packet", pkt))

	n, ok := i.Neighbours.Lookup(srcAddr)
	if !ok {
		// On strict non-multicast links only configured neighbours are
		// accepted; everything else is ignored.
		if !i.multicast && i.speaker.config.StrictNeighbours {
			i.logger.Debug("Ignoring packet from unconfigured neighbour",
				slog.String("addr", srcAddr.String()))
			return nil
		}

		var err error
		if n, err = i.NewNeighbour(srcAddr); err != nil {
			return fmt.Errorf("failed to create neighbour: %w", err)
		}

		i.logger.Debug("Found new neighbour", slog.String("addr", srcAddr.String()))

		if h, ok := i.speaker.config.Handler.(NeighbourHandler); ok {
			h.NeighbourAdded(n)
		}

		i.Neighbours.Insert(n)
	}

	return n.onPacket(pkt, srcAddr, dstAddr)
}

func (i *Interface) sendMulticastHello() error {
	i.logger.Debug("Sending multicast hello")

	i.helloMulticastSeqNo++

	i.sendValue([]proto.Value{
		&proto.Hello{
			Seqno:    i.helloMulticastSeqNo,
			Interval: i.speaker.config.MulticastHelloInterval,
		},
	}, i.speaker.config.MulticastHelloInterval/2)

	return nil
}

// sendUpdate implements the periodic full route dump (RFC 8966 Section 3.7.1).
func (i *Interface) sendUpdate() error {
	updates, retractions := i.speaker.advertisedRoutes(i)
	values := i.speaker.encodeRoutes(i, updates)
	for _, r := range retractions {
		values = append(values, i.speaker.encodeRetraction(r.Source.RouterID, r.SeqNo, r.Source.Prefix)...)
	}
	if len(values) == 0 {
		return nil
	}
	i.sendValue(values, i.speaker.config.UpdateInterval)
	return nil
}

// sendTriggered sends an urgent update for the given routes (RFC 8966
// Section 3.7.2). Retractions are never subject to split horizon.
func (i *Interface) sendTriggered(routes []*Route, retractions []*Route, urgent bool) {
	values := i.speaker.encodeRoutes(i, routes)
	for _, r := range retractions {
		values = append(values, i.speaker.encodeRetraction(r.Source.RouterID, r.SeqNo, r.Source.Prefix)...)
	}
	if len(values) == 0 {
		return
	}
	// Triggered updates must be sent promptly so the network converges
	// quickly (RFC 8966 Section 3.7.2); the periodic dump handles refresh.
	maxDelay := i.speaker.config.UrgentTimeout
	i.sendValue(values, maxDelay)
}

// sendRouteRequestFor sends a route request for a prefix to all neighbours
// (used to re-synchronise after a mobility event).
func (i *Interface) sendRouteRequestFor(pfx proto.Prefix) {
	i.Neighbours.Foreach(func(n *Neighbour) error {
		n.sendRouteRequest(pfx)
		return nil
	})
}

func (i *Interface) sendValue(vs []proto.Value, maxDelay time.Duration) {
	if len(vs) == 0 {
		return
	}
	if i.multicast {
		i.queue.SendValues(vs, maxDelay)
	} else {
		i.Neighbours.Foreach(func(n *Neighbour) error {
			n.queue.SendValues(vs, maxDelay)
			return nil
		})
	}
}

// findLinkLocalAddress returns the interface's IPv6 link-local address.
func (i *Interface) findLinkLocalAddress() (net.IP, error) {
	addrs, err := i.Addrs()
	if err != nil {
		return nil, err
	}

	for _, addr := range addrs {
		ipNetAddr, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}

		ipAddr := ipNetAddr.IP
		if ipAddr.To4() != nil {
			continue // skip IPv4
		}
		if !ipAddr.IsLinkLocalUnicast() {
			continue // skip non link-local
		}
		return ipAddr, nil
	}

	return nil, errors.New("failed to find IPv6 link-local address")
}

// sourceAddress returns the interface's configured IPv6 link-local address
// to pin as the source of outgoing Babel packets.
func (i *Interface) sourceAddress() net.IP {
	if ip, err := i.findLinkLocalAddress(); err == nil {
		return ip
	}
	return nil
}
