//go:build linux

package linux

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/TunnelHelper/TH/internal/core"
	"github.com/TunnelHelper/TH/internal/model"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func parseAmneziaSockaddr(data []byte) (*net.UDPAddr, error) {
	switch len(data) {
	case unix.SizeofSockaddrInet4:
		if binary.NativeEndian.Uint16(data[0:2]) != unix.AF_INET {
			return nil, errors.New("IPv4 endpoint has an invalid address family")
		}
		return &net.UDPAddr{IP: net.IP(append([]byte(nil), data[4:8]...)), Port: int(binary.BigEndian.Uint16(data[2:4]))}, nil
	case unix.SizeofSockaddrInet6:
		if binary.NativeEndian.Uint16(data[0:2]) != unix.AF_INET6 {
			return nil, errors.New("IPv6 endpoint has an invalid address family")
		}
		scopeID := binary.NativeEndian.Uint32(data[24:28])
		zone := ""
		if scopeID != 0 {
			zone = strconv.FormatUint(uint64(scopeID), 10)
		}
		return &net.UDPAddr{IP: net.IP(append([]byte(nil), data[8:24]...)), Port: int(binary.BigEndian.Uint16(data[2:4])), Zone: zone}, nil
	default:
		return nil, fmt.Errorf("unexpected endpoint sockaddr size %d", len(data))
	}
}

func parseAmneziaTimespec(data []byte) time.Time {
	if len(data) == 16 {
		seconds := int64(binary.NativeEndian.Uint64(data[0:8]))
		nanoseconds := int64(binary.NativeEndian.Uint64(data[8:16]))
		if seconds > 0 || nanoseconds > 0 {
			return time.Unix(seconds, nanoseconds)
		}
	}
	if len(data) == 8 {
		seconds := int64(int32(binary.NativeEndian.Uint32(data[0:4])))
		nanoseconds := int64(int32(binary.NativeEndian.Uint32(data[4:8])))
		if seconds > 0 || nanoseconds > 0 {
			return time.Unix(seconds, nanoseconds)
		}
	}
	return time.Time{}
}

func (b *Backend) applyAmneziaWG(ctx context.Context, record model.Tunnel) (core.Observation, error) {
	if b.awgErr != nil {
		return core.Observation{}, b.awgErr
	}
	spec := record.Spec.AmneziaWG
	desired := &netlink.GenericLink{
		LinkAttrs: netlink.LinkAttrs{Name: record.Interface, MTU: spec.MTU, Alias: ownershipAlias(record.ID)},
		LinkType:  amneziaFamilyName,
	}
	link, err := b.ensureLink(record, desired, func(existing netlink.Link) bool {
		return existing.Type() == amneziaFamilyName
	})
	if err != nil {
		return core.Observation{}, err
	}
	if err := b.awg.Configure(ctx, record.Interface, spec, record); err != nil {
		return observationFromLink(link), err
	}
	if err := b.configureOwnedLink(record, link, spec.MTU, spec.Addresses); err != nil {
		return observationFromLink(link), err
	}
	if err := b.reconcileWireGuardRoutes(record, &spec.WireGuardSpec, link); err != nil {
		return observationFromLink(link), err
	}
	return b.observeAmneziaWG(ctx, record)
}

func (b *Backend) observeAmneziaWG(ctx context.Context, record model.Tunnel) (core.Observation, error) {
	observation, err := b.observeLink(record)
	if err != nil || !observation.InterfaceExists {
		return observation, err
	}
	if b.awgErr != nil {
		return observation, b.awgErr
	}
	device, err := b.awg.Device(ctx, record.Interface)
	if err != nil {
		return observation, err
	}
	if observation.Details == nil {
		observation.Details = make(map[string]string)
	}
	observation.Details["public_key"] = device.PublicKey.String()
	observation.Details["listen_port"] = strconv.Itoa(device.ListenPort)
	observation.Details["peers"] = strconv.Itoa(len(device.Peers))
	var rx, tx int64
	var latest time.Time
	for _, peer := range device.Peers {
		rx += peer.ReceiveBytes
		tx += peer.TransmitBytes
		if peer.LastHandshakeTime.After(latest) {
			latest = peer.LastHandshakeTime
		}
	}
	observation.Details["receive_bytes"] = strconv.FormatInt(rx, 10)
	observation.Details["transmit_bytes"] = strconv.FormatInt(tx, 10)
	observation.Details["counter_source"] = "amneziawg"
	observation.Peers = wireGuardPeerStatuses(device.Peers)
	if !latest.IsZero() {
		observation.Details["latest_handshake"] = latest.UTC().Format(time.RFC3339)
	}
	return observation, nil
}
