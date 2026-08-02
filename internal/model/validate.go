package model

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var (
	namePattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)
	interfacePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
)

func Validate(t *Tunnel) error {
	if t == nil {
		return errors.New("tunnel is required")
	}
	if t.SchemaVersion != SchemaVersion {
		return fmt.Errorf("schema_version must be %d", SchemaVersion)
	}
	if !ValidID(t.ID) {
		return errors.New("id must be a lowercase UUID")
	}
	if t.Generation == 0 {
		return errors.New("generation must be positive")
	}
	if t.CreatedAt.IsZero() || t.UpdatedAt.IsZero() || t.UpdatedAt.Before(t.CreatedAt) {
		return errors.New("created_at and updated_at must be valid ordered timestamps")
	}
	if len(t.Name) == 0 || len(t.Name) > 64 || !namePattern.MatchString(t.Name) {
		return errors.New("name must be 1-64 characters using letters, digits, dot, underscore, or dash")
	}
	if t.Kind != KindSRv6 {
		if err := validateInterface(t.Interface); err != nil {
			return err
		}
	} else if t.Interface != "" {
		return errors.New("srv6 records must not set interface")
	}
	if err := validateSpecChoice(t); err != nil {
		return err
	}

	var kindErr error
	switch t.Kind {
	case KindGRE:
		kindErr = validateGRE(t.Spec.GRE)
	case KindVXLAN:
		kindErr = validateVXLAN(t.Spec.VXLAN)
	case KindWireGuard:
		kindErr = validateWireGuard(t.Spec.WireGuard)
	case KindAmneziaWG:
		kindErr = validateAmneziaWG(t.Spec.AmneziaWG)
	case KindXFRMStatic:
		kindErr = validateXFRMStatic(t.Spec.XFRMStatic)
	case KindXFRMIKEv2:
		kindErr = validateXFRMIKEv2(t.Spec.XFRMIKEv2)
	case KindSRv6:
		kindErr = validateSRv6(t.Spec.SRv6)
	default:
		kindErr = fmt.Errorf("unsupported tunnel kind %q", t.Kind)
	}
	if kindErr != nil {
		return kindErr
	}
	return validateTunnelBabel(t)
}

func validateSpecChoice(t *Tunnel) error {
	count := 0
	for _, set := range []bool{
		t.Spec.GRE != nil,
		t.Spec.VXLAN != nil,
		t.Spec.WireGuard != nil,
		t.Spec.AmneziaWG != nil,
		t.Spec.XFRMStatic != nil,
		t.Spec.XFRMIKEv2 != nil,
		t.Spec.SRv6 != nil,
	} {
		if set {
			count++
		}
	}
	if count != 1 {
		return errors.New("spec must contain exactly one tunnel kind")
	}
	matches := map[Kind]bool{
		KindGRE:        t.Spec.GRE != nil,
		KindVXLAN:      t.Spec.VXLAN != nil,
		KindWireGuard:  t.Spec.WireGuard != nil,
		KindAmneziaWG:  t.Spec.AmneziaWG != nil,
		KindXFRMStatic: t.Spec.XFRMStatic != nil,
		KindXFRMIKEv2:  t.Spec.XFRMIKEv2 != nil,
		KindSRv6:       t.Spec.SRv6 != nil,
	}
	if !matches[t.Kind] {
		return fmt.Errorf("spec does not match kind %q", t.Kind)
	}
	return nil
}

func validateInterface(name string) error {
	if len(name) == 0 || len(name) > 15 || !interfacePattern.MatchString(name) {
		return errors.New("interface must be 1-15 characters using letters, digits, dot, underscore, or dash")
	}
	return nil
}

func validateMTU(mtu int) error {
	if mtu < 68 || mtu > 65535 {
		return errors.New("mtu must be between 68 and 65535")
	}
	return nil
}

func validateInterfaceAddresses(addresses []netip.Prefix) error {
	if len(addresses) > MaxInterfaceAddresses {
		return fmt.Errorf("addresses exceeds %d entries", MaxInterfaceAddresses)
	}
	seen := make(map[netip.Prefix]struct{}, len(addresses))
	for _, prefix := range addresses {
		if !prefix.IsValid() {
			return errors.New("addresses contains an invalid prefix")
		}
		if _, ok := seen[prefix]; ok {
			return fmt.Errorf("duplicate address %s", prefix)
		}
		seen[prefix] = struct{}{}
	}
	return nil
}

func validateNetworks(networks []netip.Prefix) error {
	seen := make(map[netip.Prefix]struct{}, len(networks))
	for _, prefix := range networks {
		if !prefix.IsValid() {
			return errors.New("contains an invalid prefix")
		}
		prefix = prefix.Masked()
		if _, ok := seen[prefix]; ok {
			return fmt.Errorf("duplicate network %s", prefix)
		}
		seen[prefix] = struct{}{}
	}
	return nil
}

func validateGRE(spec *GRESpec) error {
	if err := validateUnderlayPair(spec.Local, spec.Remote); err != nil {
		return err
	}
	if err := validateInterfaceAddresses(spec.Addresses); err != nil {
		return err
	}
	return validateMTU(spec.MTU)
}

func validateVXLAN(spec *VXLANSpec) error {
	if spec.VNI < 1 || spec.VNI > 16777215 {
		return errors.New("vni must be between 1 and 16777215")
	}
	if err := validateInterface(spec.UnderlayInterface); err != nil {
		return fmt.Errorf("underlay_interface: %w", err)
	}
	if err := validateUnderlayPair(spec.Local, spec.Remote); err != nil {
		return err
	}
	if spec.DestinationPort < 1 || spec.DestinationPort > 65535 {
		return errors.New("destination_port must be between 1 and 65535")
	}
	if err := validateInterfaceAddresses(spec.Addresses); err != nil {
		return err
	}
	return validateMTU(spec.MTU)
}

func validateUnderlayPair(local, remote netip.Addr) error {
	if !local.IsValid() || local.IsUnspecified() || !remote.IsValid() || remote.IsUnspecified() {
		return errors.New("local and remote underlay addresses must be specified")
	}
	if local.BitLen() != remote.BitLen() {
		return errors.New("local and remote underlay addresses must use the same family")
	}
	return nil
}

func validateWireGuard(spec *WireGuardSpec) error {
	if len(spec.Peers) > MaxWireGuardPeers {
		return fmt.Errorf("peers exceeds %d entries", MaxWireGuardPeers)
	}
	totalAllowedIPs := 0
	for i := range spec.Peers {
		count := len(spec.Peers[i].AllowedIPs)
		if count > MaxAllowedIPsPerPeer {
			return fmt.Errorf("peers[%d].allowed_ips exceeds %d entries", i, MaxAllowedIPsPerPeer)
		}
		totalAllowedIPs += count
		if totalAllowedIPs > MaxAllowedIPsPerTunnel {
			return fmt.Errorf("peer allowed_ips exceeds %d total entries", MaxAllowedIPsPerTunnel)
		}
	}
	if spec.PrivateKey == "" {
		return errors.New("private_key is required")
	}
	if _, err := wgtypes.ParseKey(spec.PrivateKey); err != nil {
		return fmt.Errorf("private_key: %w", err)
	}
	publicKey, err := wgtypes.ParseKey(spec.PublicKey)
	if err != nil {
		return fmt.Errorf("public_key: %w", err)
	}
	privateKey, _ := wgtypes.ParseKey(spec.PrivateKey)
	if publicKey != privateKey.PublicKey() {
		return errors.New("public_key does not match private_key")
	}
	if spec.ListenPort < 0 || spec.ListenPort > 65535 {
		return errors.New("listen_port must be between 0 and 65535")
	}
	if spec.FirewallMark < 0 || int64(spec.FirewallMark) > 2147483647 {
		return errors.New("firewall_mark must be between 0 and 2147483647")
	}
	if err := validateInterfaceAddresses(spec.Addresses); err != nil {
		return err
	}
	if err := validateMTU(spec.MTU); err != nil {
		return err
	}
	if spec.RouteTable < 0 || int64(spec.RouteTable) > 2147483647 {
		return errors.New("route_table must be between 0 and 2147483647")
	}
	seen := make(map[string]struct{}, len(spec.Peers))
	for i := range spec.Peers {
		peer := &spec.Peers[i]
		if _, err := wgtypes.ParseKey(peer.PublicKey); err != nil {
			return fmt.Errorf("peers[%d].public_key: %w", i, err)
		}
		if _, ok := seen[peer.PublicKey]; ok {
			return fmt.Errorf("duplicate peer public key at peers[%d]", i)
		}
		seen[peer.PublicKey] = struct{}{}
		if peer.PresharedKey != "" {
			if _, err := wgtypes.ParseKey(peer.PresharedKey); err != nil {
				return fmt.Errorf("peers[%d].preshared_key: %w", i, err)
			}
		}
		if peer.Endpoint != "" {
			if err := validateEndpoint(peer.Endpoint); err != nil {
				return fmt.Errorf("peers[%d].endpoint: %w", i, err)
			}
		}
		if peer.Keepalive < 0 || peer.Keepalive > 65535 {
			return fmt.Errorf("peers[%d].keepalive must be between 0 and 65535", i)
		}
		if err := validateNetworks(peer.AllowedIPs); err != nil {
			return fmt.Errorf("peers[%d].allowed_ips: %w", i, err)
		}
	}
	return nil
}

func validateEndpoint(endpoint string) error {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return errors.New("must be host:port, with brackets around IPv6")
	}
	if strings.TrimSpace(host) == "" {
		return errors.New("host is required")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return errors.New("port must be between 1 and 65535")
	}
	return nil
}

func validateAmneziaWG(spec *AmneziaWGSpec) error {
	if err := validateWireGuard(&spec.WireGuardSpec); err != nil {
		return err
	}
	if spec.JunkPacketCount < 1 || spec.JunkPacketCount > 128 {
		return errors.New("jc must be between 1 and 128")
	}
	if spec.JunkPacketMinSize < 1 || spec.JunkPacketMinSize > 1280 {
		return errors.New("jmin must be between 1 and 1280")
	}
	if spec.JunkPacketMaxSize < spec.JunkPacketMinSize || spec.JunkPacketMaxSize > 1280 {
		return errors.New("jmax must be between jmin and 1280")
	}
	if spec.InitPacketJunkSize < 0 || spec.InitPacketJunkSize > 1280 || spec.ResponsePacketJunkSize < 0 || spec.ResponsePacketJunkSize > 1280 {
		return errors.New("s1 and s2 must be between 0 and 1280")
	}
	for name, value := range map[string]string{
		"h1": spec.InitMagicHeader,
		"h2": spec.ResponseMagicHeader,
		"h3": spec.UnderloadMagicHeader,
		"h4": spec.TransportMagicHeader,
	} {
		if err := validateMagicHeader(value); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	if spec.InitMagicHeader == spec.ResponseMagicHeader ||
		spec.InitMagicHeader == spec.UnderloadMagicHeader ||
		spec.InitMagicHeader == spec.TransportMagicHeader ||
		spec.ResponseMagicHeader == spec.UnderloadMagicHeader ||
		spec.ResponseMagicHeader == spec.TransportMagicHeader ||
		spec.UnderloadMagicHeader == spec.TransportMagicHeader {
		return errors.New("h1, h2, h3, and h4 must be distinct")
	}
	return nil
}

func validateMagicHeader(value string) error {
	if value == "" || strings.ContainsRune(value, '\x00') || len(value) > 255 {
		return errors.New("must be a non-empty value of at most 255 bytes without NUL")
	}
	return nil
}

const (
	MaxBabelNeighbours    = 64
	MaxBabelBandwidthMbps = 400000
)

// validateTunnelBabel validates the optional per-tunnel Babel switch.
func validateTunnelBabel(t *Tunnel) error {
	spec := t.Spec.Babel
	if spec == nil {
		return nil
	}
	if t.Kind == KindSRv6 {
		return errors.New("srv6 records cannot participate in Babel")
	}
	if spec.BandwidthMbps < 0 || spec.BandwidthMbps > MaxBabelBandwidthMbps {
		return fmt.Errorf("bandwidth_mbps must be between 0 and %d", MaxBabelBandwidthMbps)
	}
	if len(spec.Neighbours) > MaxBabelNeighbours {
		return fmt.Errorf("neighbours exceeds %d entries", MaxBabelNeighbours)
	}
	seen := make(map[netip.Addr]struct{}, len(spec.Neighbours))
	for _, addr := range spec.Neighbours {
		if !addr.IsValid() || addr.IsUnspecified() {
			return errors.New("neighbours contains an invalid address")
		}
		if _, ok := seen[addr]; ok {
			return fmt.Errorf("duplicate neighbour %s", addr)
		}
		seen[addr] = struct{}{}
	}
	if t.Kind == KindWireGuard || t.Kind == KindAmneziaWG {
		peers := t.Spec.WireGuard.Peers
		if t.Kind == KindAmneziaWG && t.Spec.AmneziaWG != nil {
			peers = t.Spec.AmneziaWG.Peers
		}
		multicast := spec.Multicast
		if multicast == nil {
			enabled := len(peers) <= 1
			multicast = &enabled
		}
		if *multicast {
			if !peerAllowedIPsCoverBabelMulticast(peers) {
				return errors.New("Babel multicast on a WireGuard tunnel requires at least one peer AllowedIPs to cover ff02::1:6 (for example ::/0 or ff02::/16)")
			}
		}
	}
	return nil
}

func peerAllowedIPsCoverBabelMulticast(peers []WireGuardPeer) bool {
	group := netip.MustParseAddr("ff02::1:6")
	for _, peer := range peers {
		for _, allowed := range peer.AllowedIPs {
			if allowed.Contains(group) {
				return true
			}
		}
	}
	return false
}
