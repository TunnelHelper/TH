//go:build linux

package linux

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/mdlayher/genetlink"
	mdnetlink "github.com/mdlayher/netlink"
	"github.com/sudogeeker/tunnel-helper/internal/core"
	"github.com/sudogeeker/tunnel-helper/internal/model"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const amneziaFamilyName = "amneziawg"

const (
	awgCommandGetDevice uint8 = iota
	awgCommandSetDevice
)

const (
	awgDeviceUnspec uint16 = iota
	awgDeviceIfIndex
	awgDeviceIfName
	awgDevicePrivateKey
	awgDevicePublicKey
	awgDeviceFlags
	awgDeviceListenPort
	awgDeviceFirewallMark
	awgDevicePeers
	awgDeviceJC
	awgDeviceJMin
	awgDeviceJMax
	awgDeviceS1
	awgDeviceS2
	awgDeviceH1
	awgDeviceH2
	awgDeviceH3
	awgDeviceH4
	awgDevicePeer
	awgDeviceS3
	awgDeviceS4
	awgDeviceI1
	awgDeviceI2
	awgDeviceI3
	awgDeviceI4
	awgDeviceI5
)

const (
	awgPeerUnspec uint16 = iota
	awgPeerPublicKey
	awgPeerPresharedKey
	awgPeerFlags
	awgPeerEndpoint
	awgPeerKeepalive
	awgPeerLastHandshake
	awgPeerReceiveBytes
	awgPeerTransmitBytes
	awgPeerAllowedIPs
	awgPeerProtocolVersion
	awgPeerAWG
)

const (
	awgAllowedIPUnspec uint16 = iota
	awgAllowedIPFamily
	awgAllowedIPAddress
	awgAllowedIPCIDRMask
)

const (
	awgDeviceReplacePeers uint32 = 1 << iota
)

const (
	awgPeerRemove uint32 = 1 << iota
	awgPeerReplaceAllowedIPs
	awgPeerUpdateOnly
	awgPeerHasAWG
)

type amneziaClient struct {
	conn    *genetlink.Conn
	timeout time.Duration
	mu      sync.Mutex
}

type amneziaDevice struct {
	Name         string
	PublicKey    wgtypes.Key
	ListenPort   int
	FirewallMark int
	Peers        []wgtypes.Peer
	JunkCount    int
	JunkMin      int
	JunkMax      int
	S1           int
	S2           int
	H1           string
	H2           string
	H3           string
	H4           string
}

func newAmneziaClient(timeout time.Duration) (*amneziaClient, error) {
	conn, err := genetlink.Dial(nil)
	if err != nil {
		return nil, fmt.Errorf("open AmneziaWG generic netlink: %w", err)
	}
	for _, option := range []mdnetlink.ConnOption{mdnetlink.ExtendedAcknowledge, mdnetlink.GetStrictCheck} {
		_ = conn.SetOption(option, true)
	}
	return &amneziaClient{conn: conn, timeout: timeout}, nil
}

func (c *amneziaClient) Close() error {
	return c.conn.Close()
}

func (c *amneziaClient) health(ctx context.Context) error {
	_, err := c.family(ctx)
	return err
}

func (c *amneziaClient) family(ctx context.Context) (genetlink.Family, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.setDeadline(ctx); err != nil {
		return genetlink.Family{}, err
	}
	defer c.conn.SetDeadline(time.Time{})
	return c.familyLocked(ctx)
}

func (c *amneziaClient) familyLocked(ctx context.Context) (genetlink.Family, error) {
	if err := ctx.Err(); err != nil {
		return genetlink.Family{}, err
	}
	family, err := c.conn.GetFamily(amneziaFamilyName)
	if err != nil {
		return genetlink.Family{}, fmt.Errorf("resolve %s generic-netlink family: %w", amneziaFamilyName, err)
	}
	return family, nil
}

func (c *amneziaClient) execute(ctx context.Context, command uint8, flags mdnetlink.HeaderFlags, data []byte) ([]genetlink.Message, genetlink.Family, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.setDeadline(ctx); err != nil {
		return nil, genetlink.Family{}, err
	}
	defer c.conn.SetDeadline(time.Time{})
	family, err := c.familyLocked(ctx)
	if err != nil {
		return nil, genetlink.Family{}, err
	}
	messages, err := c.conn.Execute(genetlink.Message{
		Header: genetlink.Header{Command: command, Version: family.Version},
		Data:   data,
	}, family.ID, flags)
	if err != nil {
		return nil, family, fmt.Errorf("AmneziaWG generic-netlink command %d: %w", command, err)
	}
	return messages, family, nil
}

func (c *amneziaClient) setDeadline(ctx context.Context) error {
	deadline := time.Now().Add(c.timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := c.conn.SetDeadline(deadline); err != nil {
		return err
	}
	return nil
}

func (c *amneziaClient) Configure(ctx context.Context, name string, spec *model.AmneziaWGSpec, record model.Tunnel) error {
	privateKey, err := wgtypes.ParseKey(spec.PrivateKey)
	if err != nil {
		return err
	}
	family, err := c.family(ctx)
	if err != nil {
		return err
	}
	encoder := mdnetlink.NewAttributeEncoder()
	encoder.String(awgDeviceIfName, name)
	encoder.Bytes(awgDevicePrivateKey, privateKey[:])
	encoder.Uint16(awgDeviceListenPort, uint16(spec.ListenPort))
	encoder.Uint32(awgDeviceFirewallMark, uint32(effectiveFirewallMark(record, &spec.WireGuardSpec)))
	encoder.Uint32(awgDeviceFlags, awgDeviceReplacePeers)
	encoder.Uint16(awgDeviceJC, uint16(spec.JunkPacketCount))
	encoder.Uint16(awgDeviceJMin, uint16(spec.JunkPacketMinSize))
	encoder.Uint16(awgDeviceJMax, uint16(spec.JunkPacketMaxSize))
	encoder.Uint16(awgDeviceS1, uint16(spec.InitPacketJunkSize))
	encoder.Uint16(awgDeviceS2, uint16(spec.ResponsePacketJunkSize))
	for attribute, value := range map[uint16]string{
		awgDeviceH1: spec.InitMagicHeader,
		awgDeviceH2: spec.ResponseMagicHeader,
		awgDeviceH3: spec.UnderloadMagicHeader,
		awgDeviceH4: spec.TransportMagicHeader,
	} {
		if err := encodeAmneziaHeader(encoder, attribute, value, family.Version); err != nil {
			return err
		}
	}
	if len(spec.Peers) > 0 {
		encoder.Nested(awgDevicePeers, func(peers *mdnetlink.AttributeEncoder) error {
			for i, peer := range spec.Peers {
				peer := peer
				peers.Nested(uint16(i), func(attributes *mdnetlink.AttributeEncoder) error {
					return encodeAmneziaPeer(ctx, attributes, peer)
				})
			}
			return nil
		})
	}
	data, err := encoder.Encode()
	if err != nil {
		return fmt.Errorf("encode AmneziaWG configuration: %w", err)
	}
	_, _, err = c.execute(ctx, awgCommandSetDevice, mdnetlink.Request|mdnetlink.Acknowledge, data)
	return err
}

func encodeAmneziaHeader(encoder *mdnetlink.AttributeEncoder, attribute uint16, value string, version uint8) error {
	if version < 2 {
		number, err := strconv.ParseUint(value, 10, 32)
		if err != nil || number == 0 {
			return fmt.Errorf("AmneziaWG family version %d requires non-zero numeric H1-H4 values", version)
		}
		encoder.Uint32(attribute, uint32(number))
		return nil
	}
	encoder.String(attribute, value)
	return nil
}

func encodeAmneziaPeer(ctx context.Context, encoder *mdnetlink.AttributeEncoder, peer model.WireGuardPeer) error {
	publicKey, err := wgtypes.ParseKey(peer.PublicKey)
	if err != nil {
		return err
	}
	encoder.Bytes(awgPeerPublicKey, publicKey[:])
	encoder.Uint32(awgPeerFlags, awgPeerReplaceAllowedIPs|awgPeerHasAWG)
	encoder.Flag(awgPeerAWG, true)
	if peer.PresharedKey != "" {
		key, err := wgtypes.ParseKey(peer.PresharedKey)
		if err != nil {
			return err
		}
		encoder.Bytes(awgPeerPresharedKey, key[:])
	}
	if peer.Endpoint != "" {
		endpoint, err := resolveEndpoint(ctx, peer.Endpoint)
		if err != nil {
			return err
		}
		encoder.Do(awgPeerEndpoint, encodeAmneziaSockaddr(*endpoint))
	}
	encoder.Uint16(awgPeerKeepalive, uint16(peer.Keepalive))
	if len(peer.AllowedIPs) > 0 {
		encoder.Nested(awgPeerAllowedIPs, func(allowed *mdnetlink.AttributeEncoder) error {
			for i, prefix := range peer.AllowedIPs {
				prefix := prefix.Masked()
				allowed.Nested(uint16(i), func(attributes *mdnetlink.AttributeEncoder) error {
					family := uint16(unix.AF_INET6)
					address := prefix.Addr().AsSlice()
					if prefix.Addr().Is4() {
						family = unix.AF_INET
					}
					attributes.Uint16(awgAllowedIPFamily, family)
					attributes.Bytes(awgAllowedIPAddress, address)
					attributes.Uint8(awgAllowedIPCIDRMask, uint8(prefix.Bits()))
					return nil
				})
			}
			return nil
		})
	}
	return nil
}

func encodeAmneziaSockaddr(endpoint net.UDPAddr) func() ([]byte, error) {
	return func() ([]byte, error) {
		if endpoint.Port < 1 || endpoint.Port > 65535 || endpoint.IP.To16() == nil {
			return nil, errors.New("invalid endpoint IP")
		}
		if endpoint.IP.To4() != nil {
			data := make([]byte, unix.SizeofSockaddrInet4)
			binary.NativeEndian.PutUint16(data[0:2], unix.AF_INET)
			binary.BigEndian.PutUint16(data[2:4], uint16(endpoint.Port))
			copy(data[4:8], endpoint.IP.To4())
			return data, nil
		}
		scopeID, err := endpointScopeID(endpoint.Zone)
		if err != nil {
			return nil, err
		}
		data := make([]byte, unix.SizeofSockaddrInet6)
		binary.NativeEndian.PutUint16(data[0:2], unix.AF_INET6)
		binary.BigEndian.PutUint16(data[2:4], uint16(endpoint.Port))
		copy(data[8:24], endpoint.IP.To16())
		binary.NativeEndian.PutUint32(data[24:28], scopeID)
		return data, nil
	}
}

func endpointScopeID(zone string) (uint32, error) {
	if zone == "" {
		return 0, nil
	}
	if value, err := strconv.ParseUint(zone, 10, 32); err == nil {
		return uint32(value), nil
	}
	device, err := net.InterfaceByName(zone)
	if err != nil {
		return 0, fmt.Errorf("resolve endpoint zone %q: %w", zone, err)
	}
	return uint32(device.Index), nil
}

func (c *amneziaClient) Device(ctx context.Context, name string) (*amneziaDevice, error) {
	encoder := mdnetlink.NewAttributeEncoder()
	encoder.String(awgDeviceIfName, name)
	data, err := encoder.Encode()
	if err != nil {
		return nil, err
	}
	messages, family, err := c.execute(ctx, awgCommandGetDevice, mdnetlink.Request|mdnetlink.Dump, data)
	if err != nil {
		return nil, err
	}
	return parseAmneziaDevice(messages, family.Version)
}

func parseAmneziaDevice(messages []genetlink.Message, version uint8) (*amneziaDevice, error) {
	device := &amneziaDevice{}
	peerIndex := make(map[wgtypes.Key]int)
	for _, message := range messages {
		decoder, err := mdnetlink.NewAttributeDecoder(message.Data)
		if err != nil {
			return nil, err
		}
		for decoder.Next() {
			switch decoder.Type() {
			case awgDeviceIfName:
				device.Name = decoder.String()
			case awgDevicePublicKey:
				if err := parseAmneziaKey(decoder.Bytes(), &device.PublicKey); err != nil {
					return nil, err
				}
			case awgDeviceListenPort:
				device.ListenPort = int(decoder.Uint16())
			case awgDeviceFirewallMark:
				device.FirewallMark = int(decoder.Uint32())
			case awgDeviceJC:
				device.JunkCount = int(decoder.Uint16())
			case awgDeviceJMin:
				device.JunkMin = int(decoder.Uint16())
			case awgDeviceJMax:
				device.JunkMax = int(decoder.Uint16())
			case awgDeviceS1:
				device.S1 = int(decoder.Uint16())
			case awgDeviceS2:
				device.S2 = int(decoder.Uint16())
			case awgDeviceH1:
				device.H1 = decodeAmneziaHeader(decoder, version)
			case awgDeviceH2:
				device.H2 = decodeAmneziaHeader(decoder, version)
			case awgDeviceH3:
				device.H3 = decodeAmneziaHeader(decoder, version)
			case awgDeviceH4:
				device.H4 = decodeAmneziaHeader(decoder, version)
			case awgDevicePeers:
				decoder.Nested(func(peers *mdnetlink.AttributeDecoder) error {
					for peers.Next() {
						var peer wgtypes.Peer
						peers.Nested(func(attributes *mdnetlink.AttributeDecoder) error {
							parsed, err := parseAmneziaPeer(attributes)
							peer = parsed
							return err
						})
						if index, ok := peerIndex[peer.PublicKey]; ok {
							device.Peers[index].AllowedIPs = append(device.Peers[index].AllowedIPs, peer.AllowedIPs...)
						} else {
							peerIndex[peer.PublicKey] = len(device.Peers)
							device.Peers = append(device.Peers, peer)
						}
					}
					return nil
				})
			}
		}
		if err := decoder.Err(); err != nil {
			return nil, err
		}
	}
	return device, nil
}

func decodeAmneziaHeader(decoder *mdnetlink.AttributeDecoder, version uint8) string {
	if version < 2 {
		return strconv.FormatUint(uint64(decoder.Uint32()), 10)
	}
	return decoder.String()
}

func parseAmneziaPeer(decoder *mdnetlink.AttributeDecoder) (wgtypes.Peer, error) {
	var peer wgtypes.Peer
	for decoder.Next() {
		switch decoder.Type() {
		case awgPeerPublicKey:
			if err := parseAmneziaKey(decoder.Bytes(), &peer.PublicKey); err != nil {
				return peer, err
			}
		case awgPeerPresharedKey:
			if err := parseAmneziaKey(decoder.Bytes(), &peer.PresharedKey); err != nil {
				return peer, err
			}
		case awgPeerEndpoint:
			endpoint, err := parseAmneziaSockaddr(decoder.Bytes())
			if err != nil {
				return peer, err
			}
			peer.Endpoint = endpoint
		case awgPeerKeepalive:
			peer.PersistentKeepaliveInterval = time.Duration(decoder.Uint16()) * time.Second
		case awgPeerLastHandshake:
			peer.LastHandshakeTime = parseAmneziaTimespec(decoder.Bytes())
		case awgPeerReceiveBytes:
			peer.ReceiveBytes = int64(decoder.Uint64())
		case awgPeerTransmitBytes:
			peer.TransmitBytes = int64(decoder.Uint64())
		case awgPeerAllowedIPs:
			decoder.Nested(func(allowed *mdnetlink.AttributeDecoder) error {
				for allowed.Next() {
					allowed.Nested(func(attributes *mdnetlink.AttributeDecoder) error {
						var address net.IP
						family, bits := 0, 0
						for attributes.Next() {
							switch attributes.Type() {
							case awgAllowedIPFamily:
								family = int(attributes.Uint16())
							case awgAllowedIPAddress:
								address = net.IP(attributes.Bytes())
							case awgAllowedIPCIDRMask:
								bits = int(attributes.Uint8())
							}
						}
						width := 0
						switch family {
						case unix.AF_INET:
							width = 32
							address = address.To4()
						case unix.AF_INET6:
							width = 128
							if len(address) != net.IPv6len {
								address = nil
							}
						default:
							return fmt.Errorf("unexpected allowed-IP family %d", family)
						}
						if address == nil || bits < 0 || bits > width {
							return fmt.Errorf("invalid allowed IP for family %d with prefix length %d", family, bits)
						}
						peer.AllowedIPs = append(peer.AllowedIPs, net.IPNet{IP: address, Mask: net.CIDRMask(bits, width)})
						return attributes.Err()
					})
				}
				return nil
			})
		}
	}
	return peer, decoder.Err()
}

func parseAmneziaKey(data []byte, target *wgtypes.Key) error {
	key, err := wgtypes.NewKey(data)
	if err != nil {
		return err
	}
	*target = key
	return nil
}

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
	if !latest.IsZero() {
		observation.Details["latest_handshake"] = latest.UTC().Format(time.RFC3339)
	}
	return observation, nil
}
