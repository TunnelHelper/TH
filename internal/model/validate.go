package model

import (
	"encoding/hex"
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
	if t.Kind != KindSRv6 && t.Kind != KindBabel {
		if err := validateInterface(t.Interface); err != nil {
			return err
		}
	} else if t.Interface != "" {
		return errors.New("srv6 and babel records must not set interface")
	}
	if err := validateSpecChoice(t); err != nil {
		return err
	}

	switch t.Kind {
	case KindGRE:
		return validateGRE(t.Spec.GRE)
	case KindVXLAN:
		return validateVXLAN(t.Spec.VXLAN)
	case KindWireGuard:
		return validateWireGuard(t.Spec.WireGuard)
	case KindAmneziaWG:
		return validateAmneziaWG(t.Spec.AmneziaWG)
	case KindXFRMStatic:
		return validateXFRMStatic(t.Spec.XFRMStatic)
	case KindXFRMIKEv2:
		return validateXFRMIKEv2(t.Spec.XFRMIKEv2)
	case KindSRv6:
		return validateSRv6(t.Spec.SRv6)
	case KindBabel:
		return validateBabel(t.Spec.Babel)
	default:
		return fmt.Errorf("unsupported tunnel kind %q", t.Kind)
	}
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
		t.Spec.Babel != nil,
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
		KindBabel:      t.Spec.Babel != nil,
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
	MaxBabelInterfaces     = 8
	MaxBabelAdvertised     = 256
	MaxBabelMaxPaths       = 8
	MaxBabelMultipathSlack = 65534
)

func validateBabel(spec *BabelSpec) error {
	if spec == nil {
		return errors.New("babel spec is required")
	}
	if len(spec.Interfaces) == 0 {
		return errors.New("interfaces must contain at least one interface")
	}
	if len(spec.Interfaces) > MaxBabelInterfaces {
		return fmt.Errorf("interfaces exceeds %d entries", MaxBabelInterfaces)
	}
	seenInterfaces := make(map[string]struct{}, len(spec.Interfaces))
	for _, name := range spec.Interfaces {
		if err := validateInterface(name); err != nil {
			return fmt.Errorf("interfaces: %w", err)
		}
		if _, ok := seenInterfaces[name]; ok {
			return fmt.Errorf("duplicate interface %q", name)
		}
		seenInterfaces[name] = struct{}{}
	}

	for name, neighbours := range spec.StaticNeighbours {
		if _, ok := seenInterfaces[name]; !ok {
			return fmt.Errorf("static_neighbours references unknown interface %q", name)
		}
		if len(neighbours) > MaxBabelInterfaces*64 {
			return fmt.Errorf("static_neighbours for %q exceeds limit", name)
		}
		seen := make(map[netip.Addr]struct{}, len(neighbours))
		for _, addr := range neighbours {
			if !addr.IsValid() || addr.IsUnspecified() {
				return fmt.Errorf("static_neighbours[%q] contains an invalid address", name)
			}
			if _, ok := seen[addr]; ok {
				return fmt.Errorf("duplicate static neighbour %s on %q", addr, name)
			}
			seen[addr] = struct{}{}
		}
	}

	if spec.UnicastHelloSeconds < 0 || spec.UnicastHelloSeconds > 3600 {
		return errors.New("unicast_hello_seconds must be between 0 and 3600")
	}
	if spec.RouteTable < 0 || int64(spec.RouteTable) > 2147483647 {
		return errors.New("route_table must be between 0 and 2147483647")
	}
	if err := validateNetworks(spec.AdvertisedPrefixes); err != nil {
		return fmt.Errorf("advertised_prefixes: %w", err)
	}
	if len(spec.AdvertisedPrefixes) > MaxBabelAdvertised {
		return fmt.Errorf("advertised_prefixes exceeds %d entries", MaxBabelAdvertised)
	}
	if spec.MaxPaths < 0 || spec.MaxPaths > MaxBabelMaxPaths {
		return fmt.Errorf("max_paths must be between 0 and %d", MaxBabelMaxPaths)
	}
	if spec.MultipathSlack < 0 || spec.MultipathSlack > MaxBabelMultipathSlack {
		return fmt.Errorf("multipath_slack must be between 0 and %d", MaxBabelMultipathSlack)
	}
	if spec.StrictNeighbours && spec.Multicast {
		return errors.New("strict_neighbours requires multicast to be disabled")
	}
	if spec.StrictNeighbours && len(spec.StaticNeighbours) == 0 {
		return errors.New("strict_neighbours requires at least one static neighbour")
	}
	if spec.RouterID != "" {
		if len(spec.RouterID) != 16 {
			return errors.New("router_id must be exactly 16 lowercase hex characters")
		}
		decoded, err := hex.DecodeString(spec.RouterID)
		if err != nil {
			return errors.New("router_id must be 16 hex characters")
		}
		if isAllZeros(decoded) {
			return errors.New("router_id must not be all zeroes")
		}
		if isAllOnes(decoded) {
			return errors.New("router_id must not be all ones")
		}
	}
	return nil
}

func isAllZeros(b []byte) bool {
	for _, value := range b {
		if value != 0 {
			return false
		}
	}
	return true
}

func isAllOnes(b []byte) bool {
	for _, value := range b {
		if value != 0xff {
			return false
		}
	}
	return true
}
