package model

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
)

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
	if len(spec.Sources) > MaxSRv6Sources {
		return fmt.Errorf("sources exceeds %d entries", MaxSRv6Sources)
	}
	if err := validateInterface(spec.UnderlayInterface); err != nil {
		return fmt.Errorf("underlay_interface: %w", err)
	}
	if spec.Table < 1 || spec.Table > 2147483647 {
		return errors.New("table must be between 1 and 2147483647")
	}
	if spec.RulePriority < SRv6RulePriorityMin || spec.RulePriority > SRv6RulePriorityMax {
		return fmt.Errorf("rule_priority must be between %d and %d", SRv6RulePriorityMin, SRv6RulePriorityMax)
	}
	if spec.RefreshIntervalSeconds < 60 || spec.RefreshIntervalSeconds > 604800 {
		return errors.New("refresh_interval_seconds must be between 60 and 604800")
	}
	if len(spec.Sources) == 0 {
		return errors.New("at least one SRv6 source is required")
	}
	seen := make(map[string]struct{}, len(spec.Sources))
	priorities := make(map[int]struct{}, len(spec.Sources))
	for i, source := range spec.Sources {
		if len(source.Name) == 0 || len(source.Name) > 64 || !namePattern.MatchString(source.Name) {
			return fmt.Errorf("sources[%d].name is invalid", i)
		}
		if _, ok := seen[source.Name]; ok {
			return fmt.Errorf("duplicate source name %q", source.Name)
		}
		seen[source.Name] = struct{}{}
		switch source.Family {
		case SRv6FamilyIPv4, SRv6FamilyIPv6:
		default:
			return fmt.Errorf("sources[%d].family must be ipv4 or ipv6", i)
		}
		if err := validateSRv6FeedURL(source.PrefixURL); err != nil {
			return fmt.Errorf("sources[%d].prefix_url: %w", i, err)
		}
		if !source.SID.IsValid() || !source.SID.Is6() || source.SID.IsUnspecified() {
			return fmt.Errorf("sources[%d].sid must be a specified IPv6 address", i)
		}
		if source.Priority < SRv6RulePriorityMin || source.Priority > SRv6RulePriorityMax {
			return fmt.Errorf("sources[%d].priority must be between %d and %d", i, SRv6RulePriorityMin, SRv6RulePriorityMax)
		}
		if _, exists := priorities[source.Priority]; exists {
			return fmt.Errorf("duplicate source priority %d", source.Priority)
		}
		priorities[source.Priority] = struct{}{}
		if err := validateMTU(source.MTU); err != nil {
			return fmt.Errorf("sources[%d]: %w", i, err)
		}
	}
	return nil
}

func validateSRv6FeedURL(value string) error {
	if value != strings.TrimSpace(value) {
		return errors.New("must not contain leading or trailing whitespace")
	}
	u, err := url.Parse(value)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return errors.New("must be an absolute HTTP or HTTPS URL")
	}
	return nil
}
