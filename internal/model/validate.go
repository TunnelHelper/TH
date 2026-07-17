package model

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
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

func validateXFRMStatic(spec *XFRMStaticSpec) error {
	if err := validateInterface(spec.UnderlayInterface); err != nil {
		return fmt.Errorf("underlay_interface: %w", err)
	}
	if err := validateUnderlayPair(spec.Local, spec.Remote); err != nil {
		return err
	}
	if err := validateInterfaceAddresses(spec.Addresses); err != nil {
		return err
	}
	if err := validateMTU(spec.MTU); err != nil {
		return err
	}
	if spec.IfID == 0 || spec.ReqID == 0 || spec.SPIInbound < 256 || spec.SPIOutbound < 256 {
		return errors.New("if_id, req_id, and SPIs must be non-zero; SPIs must be at least 256")
	}
	switch spec.Algorithm {
	case XFRMAESGCM:
		if err := validateHexBytes(spec.EncryptionKeyIn, 20); err != nil {
			return fmt.Errorf("encryption_key_in: %w", err)
		}
		if err := validateHexBytes(spec.EncryptionKeyOut, 20); err != nil {
			return fmt.Errorf("encryption_key_out: %w", err)
		}
		if spec.AuthenticationKeyIn != "" || spec.AuthenticationKeyOut != "" {
			return errors.New("authentication keys must be empty for AES-GCM")
		}
	case XFRMAESCBCSHA256:
		for name, value := range map[string]string{
			"encryption_key_in":      spec.EncryptionKeyIn,
			"encryption_key_out":     spec.EncryptionKeyOut,
			"authentication_key_in":  spec.AuthenticationKeyIn,
			"authentication_key_out": spec.AuthenticationKeyOut,
		} {
			if err := validateHexBytes(value, 32); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		}
	default:
		return fmt.Errorf("unsupported XFRM algorithm %q", spec.Algorithm)
	}
	return nil
}

func validateHexBytes(value string, size int) error {
	value = strings.TrimPrefix(value, "0x")
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return errors.New("must be hexadecimal")
	}
	if len(decoded) != size {
		return fmt.Errorf("must contain %d bytes", size)
	}
	return nil
}

func validateXFRMIKEv2(spec *XFRMIKEv2Spec) error {
	if err := validateInterface(spec.UnderlayInterface); err != nil {
		return fmt.Errorf("underlay_interface: %w", err)
	}
	if err := validateIKEAddress(spec.LocalAddress); err != nil {
		return fmt.Errorf("local_address: %w", err)
	}
	if err := validateIKEAddress(spec.RemoteAddress); err != nil {
		return fmt.Errorf("remote_address: %w", err)
	}
	if strings.TrimSpace(spec.LocalID) == "" || strings.TrimSpace(spec.RemoteID) == "" {
		return errors.New("local_id and remote_id are required")
	}
	for name, value := range map[string]string{"local_id": spec.LocalID, "remote_id": spec.RemoteID} {
		if len(value) > 255 || strings.ContainsRune(value, '\x00') {
			return fmt.Errorf("%s must be at most 255 bytes without NUL", name)
		}
	}
	if err := validateInterfaceAddresses(spec.Addresses); err != nil {
		return err
	}
	if err := validateMTU(spec.MTU); err != nil {
		return err
	}
	if spec.IfID == 0 || spec.ReqID == 0 {
		return errors.New("if_id and req_id must be non-zero")
	}
	switch spec.AuthMethod {
	case IKEAuthPSK:
		if len(spec.PSK) < 16 {
			return errors.New("psk must be at least 16 bytes")
		}
		if spec.RPKAlgorithm != "" || spec.LocalPrivateKey != "" || spec.LocalPublicKey != "" || spec.RemotePublicKey != "" {
			return errors.New("RPK fields must be empty when auth_method is psk")
		}
	case IKEAuthRPK:
		if spec.PSK != "" {
			return errors.New("psk must be empty when auth_method is rpk")
		}
		if spec.RPKAlgorithm == "" || spec.LocalPrivateKey == "" || spec.LocalPublicKey == "" || spec.RemotePublicKey == "" {
			return errors.New("RPK algorithm and local/remote key material are required")
		}
		if spec.RPKAlgorithm != "ecdsa" {
			return errors.New("rpk_algorithm must be ecdsa")
		}
		localPublic, err := parseECDSAPublicKey(spec.LocalPublicKey)
		if err != nil {
			return fmt.Errorf("local_public_key: %w", err)
		}
		if _, err := parseECDSAPublicKey(spec.RemotePublicKey); err != nil {
			return fmt.Errorf("remote_public_key: %w", err)
		}
		block, _ := pem.Decode([]byte(spec.LocalPrivateKey))
		if block == nil {
			return errors.New("local_private_key must be a PEM PKCS#8 ECDSA key")
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("local_private_key: %w", err)
		}
		privateKey, ok := parsed.(*ecdsa.PrivateKey)
		if !ok {
			return errors.New("local_private_key must contain an ECDSA key")
		}
		if !privateKey.PublicKey.Equal(localPublic) {
			return errors.New("local_public_key does not match local_private_key")
		}
	default:
		return fmt.Errorf("unsupported auth_method %q", spec.AuthMethod)
	}
	if strings.TrimSpace(spec.IKEProposal) == "" || strings.TrimSpace(spec.ESPProposal) == "" {
		return errors.New("ike_proposal and esp_proposal are required")
	}
	for name, value := range map[string]string{"ike_proposal": spec.IKEProposal, "esp_proposal": spec.ESPProposal} {
		if len(value) > 512 || strings.ContainsAny(value, "\x00\r\n") {
			return fmt.Errorf("%s must be at most 512 bytes on one line", name)
		}
	}
	if spec.StartAction != "trap" && spec.StartAction != "start" && spec.StartAction != "none" {
		return errors.New("start_action must be trap, start, or none")
	}
	return nil
}

func parseECDSAPublicKey(value string) (*ecdsa.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, errors.New("must be base64 DER")
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, errors.New("must contain a DER public key")
	}
	publicKey, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("must contain an ECDSA public key")
	}
	return publicKey, nil
}

func validateIKEAddress(value string) error {
	value = strings.TrimSpace(value)
	if value == "%any" || value == "%any4" || value == "%any6" {
		return nil
	}
	if _, err := netip.ParseAddr(value); err != nil {
		return errors.New("must be an IP address or %any")
	}
	return nil
}

func validateSRv6(spec *SRv6Spec) error {
	u, err := url.Parse(spec.BaseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return errors.New("base_url must be an absolute HTTP or HTTPS URL")
	}
	if err := validateInterface(spec.UnderlayInterface); err != nil {
		return fmt.Errorf("underlay_interface: %w", err)
	}
	if spec.Table < 1 || spec.Table > 2147483647 {
		return errors.New("table must be between 1 and 2147483647")
	}
	if spec.RefreshIntervalSeconds < 60 || spec.RefreshIntervalSeconds > 604800 {
		return errors.New("refresh_interval_seconds must be between 60 and 604800")
	}
	if len(spec.Sources) == 0 {
		return errors.New("at least one SRv6 source is required")
	}
	seen := make(map[string]struct{}, len(spec.Sources))
	for i, source := range spec.Sources {
		if len(source.Name) == 0 || len(source.Name) > 64 || !namePattern.MatchString(source.Name) {
			return fmt.Errorf("sources[%d].name is invalid", i)
		}
		if _, ok := seen[source.Name]; ok {
			return fmt.Errorf("duplicate source name %q", source.Name)
		}
		seen[source.Name] = struct{}{}
		if source.SIDv4 == nil && source.SIDv6 == nil {
			return fmt.Errorf("sources[%d] requires sid_v4 or sid_v6", i)
		}
		for _, sid := range []*netip.Addr{source.SIDv4, source.SIDv6} {
			if sid != nil && (!sid.IsValid() || !sid.Is6() || sid.IsUnspecified()) {
				return fmt.Errorf("sources[%d] SIDs must be specified IPv6 addresses", i)
			}
		}
		if err := validateMTU(source.MTU); err != nil {
			return fmt.Errorf("sources[%d]: %w", i, err)
		}
	}
	return nil
}
