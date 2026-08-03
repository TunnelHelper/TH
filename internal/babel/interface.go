// SPDX-FileCopyrightText: 2023-2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package babel

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
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

	ipv4UDPHeaderLength = 28
	ipv6UDPHeaderLength = 48
	minBabelPacketSize  = 512
	maxBabelIPv4Size    = 65535 - ipv4UDPHeaderLength
	maxBabelIPv6Size    = 65535 - ipv6UDPHeaderLength
	maxBabelReceiveSize = maxBabelIPv4Size
)

// 3.2.3. The Interface Table
// https://datatracker.ietf.org/doc/html/rfc8966#section-3.2.3

type Interface struct {
	*net.Interface

	multicast bool

	// nominalCost is the cost used by the default k-out-of-j link sensing.
	// It can be overridden per neighbour through Neighbour.SetCostOverride.
	nominalCost proto.Metric

	// bandwidthMbps is the declared usable bandwidth of this interface,
	// the per-hop contribution to the advertised end-to-end bottleneck.
	bandwidthMbps int

	Neighbours NeighbourTable

	helloMulticastSeqNo  proto.SequenceNumber
	helloMulticastTimer  *time.Ticker
	periodicUpdateTimer  *time.Ticker
	lastMulticastHelloTx proto.Timestamp

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

		multicast:           s.config.MulticastInterfaces[intf.Name],
		nominalCost:         s.config.NominalLinkCost,
		bandwidthMbps:       s.config.InterfaceBandwidth[intf.Name],
		helloMulticastTimer: time.NewTicker(s.config.MulticastHelloInterval),
		periodicUpdateTimer: time.NewTicker(s.config.UpdateInterval),

		logger: s.config.Logger.With(
			slog.String("intf", intf.Name)),
		done:    make(chan struct{}),
		stopped: make(chan struct{}),
	}

	writer := &netx.PacketConnWriter{
		Conn6:   i.speaker.conn6,
		Conn4:   i.speaker.conn4,
		Src:     i.sourceAddress(),
		Src4:    i.sourceAddress4(),
		IfIndex: intf.Index,
	}

	if i.multicast {
		dest6, dest4 := i.multicastGroups()
		if dest6 != nil {
			writer.Dest = dest6
			if err := i.speaker.conn6.JoinGroup(i.Interface, dest6); err != nil {
				i.logger.Warn("IPv6 multicast unavailable on Babel interface; continuing without it",
					slog.String("intf", intf.Name), slog.Any("error", err))
				writer.Dest = nil
			}
		}
		if dest4 != nil {
			writer.Dest4 = dest4
			if err := i.speaker.conn4.JoinGroup(i.Interface, dest4); err != nil {
				i.logger.Warn("IPv4 multicast unavailable on Babel interface; continuing without it",
					slog.String("intf", intf.Name), slog.Any("error", err))
				writer.Dest4 = nil
			}
		}
		if writer.Dest == nil && writer.Dest4 == nil {
			// The link cannot carry Babel multicast (down, unaddressed, or
			// both group joins failed). Fall back to unicast when static
			// neighbours are configured; otherwise skip the interface so a
			// single unusable link cannot take down the whole engine.
			if static, ok := s.config.StaticNeighbours[intf.Name]; ok && len(static) > 0 {
				i.logger.Warn("Multicast unavailable on Babel interface; falling back to unicast neighbours",
					slog.String("intf", intf.Name))
				i.multicast = false
			} else {
				i.logger.Warn("Multicast unavailable on Babel interface and no unicast neighbours are configured; skipping it",
					slog.String("intf", intf.Name))
				return nil, nil
			}
		}
	}
	i.queue = queue.NewQueue(babelPayloadSize(intf.MTU, writer.Dest != nil), writer)

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

// multicastGroups selects the Babel multicast destination per address
// family the interface can actually carry: the IPv6 group when the
// interface has IPv6 addresses, the IPv4 group when it has IPv4 addresses.
// An interface without any address cannot carry Babel multicast at all.
func (i *Interface) multicastGroups() (v6, v4 *net.UDPAddr) {
	addrs, err := i.Addrs()
	if err != nil {
		return nil, nil
	}
	return multicastGroupsForAddresses(addrs)
}

// multicastGroupsForAddresses is the pure address-family selection behind
// multicastGroups so it can be unit-tested without a real interface.
func multicastGroupsForAddresses(addrs []net.Addr) (v6, v4 *net.UDPAddr) {
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		if ipNet.IP.To4() != nil {
			if v4 == nil {
				v4 = &net.UDPAddr{IP: MulticastGroupIPv4.AsSlice(), Port: Port}
			}
			continue
		}
		if v6 == nil {
			v6 = &net.UDPAddr{IP: MulticastGroupIPv6.AsSlice(), Port: Port}
		}
	}
	return v6, v4
}

func babelPayloadSize(mtu int, ipv6Transport bool) int {
	overhead := ipv4UDPHeaderLength
	if ipv6Transport {
		overhead = ipv6UDPHeaderLength
	}
	size := mtu - overhead
	maximum := maxBabelIPv4Size
	if ipv6Transport {
		maximum = maxBabelIPv6Size
	}
	if size < minBabelPacketSize {
		size = minBabelPacketSize
	}
	if size > maximum {
		size = maximum
	}
	return size
}

func (i *Interface) acceptsIPv4Source(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.Is4() {
		return false
	}
	for _, configured := range i.speaker.config.StaticNeighbours[i.Name] {
		if configured.Unmap() == addr {
			return true
		}
	}
	addrs, err := i.Addrs()
	if err != nil {
		return false
	}
	return ipv4SourceOnLocalNetwork(addrs, addr)
}

func ipv4SourceOnLocalNetwork(addrs []net.Addr, source netip.Addr) bool {
	source = source.Unmap()
	if !source.Is4() {
		return false
	}
	ip := net.IP(source.AsSlice())
	for _, addr := range addrs {
		if network, ok := addr.(*net.IPNet); ok && network.IP.To4() != nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

func (i *Interface) addStaticNeighbour(addr proto.Address) error {
	addr = addr.WithZone("")
	if _, exists := i.Neighbours.Lookup(addr); exists {
		return nil
	}
	n, err := i.NewNeighbour(addr)
	if err != nil {
		return fmt.Errorf("create static neighbour %s: %w", displayAddress(addr), err)
	}
	n.Static = true
	i.Neighbours.Insert(n)
	i.logger.Info("Added static neighbour", slog.String("addr", displayAddress(addr)))

	if h, ok := i.speaker.config.Handler.(NeighbourHandler); ok {
		h.NeighbourAdded(n)
	}

	// Send the initial unicast Hello immediately to speed up adjacency.
	if i.speaker.config.UnicastHelloInterval > 0 {
		_ = n.sendUnicastHello()
	}
	n.startTimers()
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

func (i *Interface) onPacket(pkt *proto.Packet, srcAddr, dstAddr proto.Address, rxTime proto.Timestamp) error {
	// Neighbour identity is per-interface; strip the link zone so a packet
	// received on this interface always matches its configured address.
	srcAddr = srcAddr.WithZone("")
	isMulticast := dstAddr.IsLinkLocalMulticast()

	i.logger.Debug("Received packet",
		slog.String("src_addr", displayAddress(srcAddr)),
		slog.String("dst_addr", displayAddress(dstAddr)),
		slog.Bool("multicast", isMulticast),
		slog.Any("packet", pkt))

	n, ok := i.Neighbours.Lookup(srcAddr)
	if !ok {
		// On strict non-multicast links only configured neighbours are
		// accepted; everything else is ignored.
		if !i.multicast && i.speaker.config.StrictNeighbours {
			i.logger.Debug("Ignoring packet from unconfigured neighbour",
				slog.String("addr", displayAddress(srcAddr)))
			return nil
		}

		var err error
		if n, err = i.NewNeighbour(srcAddr); err != nil {
			return fmt.Errorf("failed to create neighbour: %w", err)
		}

		i.logger.Debug("Found new neighbour", slog.String("addr", displayAddress(srcAddr)))

		if h, ok := i.speaker.config.Handler.(NeighbourHandler); ok {
			h.NeighbourAdded(n)
		}

		i.Neighbours.Insert(n)
		n.startTimers()
	}

	return n.onPacket(pkt, srcAddr, dstAddr, rxTime)
}

func (i *Interface) sendMulticastHello() error {
	i.logger.Debug("Sending multicast hello")

	i.helloMulticastSeqNo++

	hello := &proto.Hello{
		Seqno:    i.helloMulticastSeqNo,
		Interval: i.speaker.config.MulticastHelloInterval,
	}
	if i.speaker.config.DelayMetric {
		i.lastMulticastHelloTx = timestampNow()
		hello.Timestamp = &proto.TimestampHello{Transmit: i.lastMulticastHelloTx}
	}

	i.sendValue([]proto.Value{hello}, i.speaker.config.MulticastHelloInterval/2)

	return nil
}

// sendUpdate implements the periodic full route dump (RFC 8966 Section 3.7.1).
func (i *Interface) sendUpdate() error {
	updates, retractions := i.speaker.advertisedRoutes(i)
	values := i.speaker.encodeRoutes(i, updates, i.outgoingDelayStats())
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
	values := i.speaker.encodeRoutes(i, routes, i.outgoingDelayStats())
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
	tentative := tentativeLinkLocals(i.Index)
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
		if _, blocked := tentative[ipAddr.String()]; blocked {
			continue // skip addresses still undergoing duplicate-address detection
		}
		return ipAddr, nil
	}

	return nil, errors.New("failed to find IPv6 link-local address")
}

// tentativeLinkLocals returns the link-local addresses of an interface that
// are still tentative (duplicate-address detection not finished) by parsing
// /proc/net/if_inet6. Tentative addresses cannot be used as packet sources.
func tentativeLinkLocals(ifIndex int) map[string]struct{} {
	data, err := os.ReadFile("/proc/net/if_inet6")
	if err != nil {
		return nil
	}
	tentative := make(map[string]struct{})
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		index, err := strconv.Atoi(fields[1])
		if err != nil || index != ifIndex {
			continue
		}
		flags, err := strconv.ParseUint(fields[5], 16, 32)
		if err != nil || flags&0x40 == 0 { // IFA_F_TENTATIVE
			continue
		}
		if len(fields[0]) != 32 {
			continue
		}
		address := make([]byte, 16)
		for i := 0; i < 16; i++ {
			value, err := strconv.ParseUint(fields[0][i*2:i*2+2], 16, 8)
			if err != nil {
				continue
			}
			address[i] = byte(value)
		}
		tentative[net.IP(address).String()] = struct{}{}
	}
	return tentative
}

// sourceAddress returns the interface's configured IPv6 link-local address
// to pin as the source of outgoing Babel packets.
func (i *Interface) sourceAddress() net.IP {
	if ip, err := i.findLinkLocalAddress(); err == nil {
		return ip
	}
	return nil
}

// sourceAddress4 returns the interface's first non-loopback IPv4 address,
// pinned as the source of outgoing IPv4 Babel packets.
func (i *Interface) sourceAddress4() net.IP {
	addrs, err := i.Addrs()
	if err != nil {
		return nil
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipNet.IP.To4()
		if ip == nil || ip.IsLoopback() {
			continue
		}
		return ip
	}
	return nil
}

// outgoingDelayStats returns delay quality for the single neighbour on this
// interface. Shared multicast links cannot advertise receiver-specific delay.
func (i *Interface) outgoingDelayStats() DelayStats {
	var stats DelayStats
	count := 0
	_ = i.Neighbours.Foreach(func(n *Neighbour) error {
		count++
		if count == 1 {
			stats = n.DelayStats()
		}
		return nil
	})
	if count != 1 {
		return DelayStats{}
	}
	return stats
}
