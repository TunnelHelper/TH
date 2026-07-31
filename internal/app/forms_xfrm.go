package app

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/TunnelHelper/TH/internal/model"
	"github.com/TunnelHelper/TH/internal/ui"
)

func collectStaticXFRM(prompts *prompts, record *model.Tunnel, creating bool) error {
	spec := record.Spec.XFRMStatic
	if spec == nil {
		spec = &model.XFRMStaticSpec{MTU: 1400, Algorithm: model.XFRMAESGCM}
		record.Spec = model.Spec{XFRMStatic: spec}
	}
	local, remote := validAddrText(spec.Local), validAddrText(spec.Remote)
	addresses, err := addressesDefault(prompts, formatPrefixes(spec.Addresses))
	if err != nil {
		return err
	}
	mtu := defaultIntText(spec.MTU, 1400)
	ifID, reqID := strconv.FormatUint(uint64(spec.IfID), 10), strconv.FormatUint(uint64(spec.ReqID), 10)

	if err := prompts.input("Remote underlay IP", &remote, validateAddrInput); err != nil {
		return err
	}
	detected := findUnderlayDefaults(remote)
	if spec.UnderlayInterface == "" {
		spec.UnderlayInterface = detected.Interface
	}
	if local == "" {
		local = detected.Local
	}
	if err := prompts.input("Underlay interface", &spec.UnderlayInterface, validateInterfaceInput); err != nil {
		return err
	}
	if err := prompts.input("Local underlay IP", &local, validateAddrInput); err != nil {
		return err
	}
	if err := prompts.input("Interface addresses", &addresses, validateInterfacePrefixesInput); err != nil {
		return err
	}
	if err := prompts.input("MTU (68-65535)", &mtu, validateInt(68, 65535)); err != nil {
		return err
	}
	if creating {
		if err := prompts.input("XFRM if_id (0 = automatic)", &ifID, validateUint32(true)); err != nil {
			return err
		}
		if err := prompts.input("XFRM reqid (0 = automatic)", &reqID, validateUint32(true)); err != nil {
			return err
		}
	}
	algorithm := string(spec.Algorithm)
	if err := selectXFRMAlgorithm(prompts, &algorithm); err != nil {
		return err
	}
	spec.Algorithm = model.XFRMAlgorithm(algorithm)
	if creating {
		if err := collectStaticXFRMPairing(prompts, spec); err != nil {
			return err
		}
	}
	spec.Local, _ = netip.ParseAddr(local)
	spec.Remote, _ = netip.ParseAddr(remote)
	spec.Addresses, _ = parsePrefixes(addresses)
	spec.MTU = parseInt(mtu)
	spec.IfID = parseUint32(ifID)
	spec.ReqID = parseUint32(reqID)
	return nil
}

func collectStaticXFRMPairing(prompts *prompts, spec *model.XFRMStaticSpec) error {
	mode := "generate"
	if err := prompts.selectValue("Pairing material", []ui.Option{
		{Label: "Generate a new local pair", Value: "generate"},
		{Label: "Paste the peer's pair (directions are reversed locally)", Value: "paste"},
	}, &mode); err != nil {
		return err
	}
	clearStaticXFRMKeys(spec)
	spec.SPIInbound, spec.SPIOutbound = 0, 0
	if mode == "generate" {
		return nil
	}
	spiPair := ""
	if err := prompts.input("Peer SPI pair (inbound,outbound; decimal or 0xhex)", &spiPair, validateUint32Pair); err != nil {
		return err
	}
	peerIn, peerOut, _ := parseUint32Pair(spiPair)
	spec.SPIInbound, spec.SPIOutbound = peerOut, peerIn
	encBytes := 20
	if spec.Algorithm == model.XFRMAESCBCSHA256 {
		encBytes = 32
	}
	encPair := ""
	if err := prompts.secret("Peer encryption keys (inbound,outbound)", &encPair, validateHexPair(encBytes)); err != nil {
		return err
	}
	peerKeyIn, peerKeyOut := parsePair(encPair)
	spec.EncryptionKeyIn, spec.EncryptionKeyOut = peerKeyOut, peerKeyIn
	if spec.Algorithm == model.XFRMAESCBCSHA256 {
		authPair := ""
		if err := prompts.secret("Peer authentication keys (inbound,outbound)", &authPair, validateHexPair(32)); err != nil {
			return err
		}
		peerAuthIn, peerAuthOut := parsePair(authPair)
		spec.AuthenticationKeyIn, spec.AuthenticationKeyOut = peerAuthOut, peerAuthIn
	}
	prompts.ui.Info("Peer inbound values were assigned to local outbound; peer outbound values were assigned to local inbound")
	return nil
}

func collectIKEv2(prompts *prompts, record *model.Tunnel, creating bool) error {
	spec := record.Spec.XFRMIKEv2
	if spec == nil {
		spec = &model.XFRMIKEv2Spec{
			MTU:         1400,
			AuthMethod:  model.IKEAuthPSK,
			IKEProposal: "aes128gcm16-prfsha256-curve25519",
			ESPProposal: "aes128gcm16",
			StartAction: "trap",
		}
		record.Spec = model.Spec{XFRMIKEv2: spec}
	}
	addresses, err := addressesDefault(prompts, formatPrefixes(spec.Addresses))
	if err != nil {
		return err
	}
	mtu := defaultIntText(spec.MTU, 1400)
	ifID, reqID := strconv.FormatUint(uint64(spec.IfID), 10), strconv.FormatUint(uint64(spec.ReqID), 10)
	if err := prompts.input("Remote underlay address", &spec.RemoteAddress, validateIKEAddrInput); err != nil {
		return err
	}
	detected := findUnderlayDefaults(spec.RemoteAddress)
	if spec.UnderlayInterface == "" {
		spec.UnderlayInterface = detected.Interface
	}
	if spec.LocalAddress == "" {
		spec.LocalAddress = detected.Local
	}
	if err := prompts.input("Underlay interface", &spec.UnderlayInterface, validateInterfaceInput); err != nil {
		return err
	}
	if err := prompts.input("Local underlay address", &spec.LocalAddress, validateIKEAddrInput); err != nil {
		return err
	}
	if spec.LocalID == "" {
		spec.LocalID = spec.LocalAddress
	}
	if spec.RemoteID == "" {
		spec.RemoteID = spec.RemoteAddress
	}
	if err := prompts.input("Local IKE identity", &spec.LocalID, required); err != nil {
		return err
	}
	if err := prompts.input("Remote IKE identity", &spec.RemoteID, required); err != nil {
		return err
	}
	if err := prompts.input("Interface addresses", &addresses, validateInterfacePrefixesInput); err != nil {
		return err
	}
	if err := prompts.input("MTU (68-65535)", &mtu, validateInt(68, 65535)); err != nil {
		return err
	}
	if creating {
		if err := prompts.input("XFRM if_id (0 = automatic)", &ifID, validateUint32(true)); err != nil {
			return err
		}
		if err := prompts.input("XFRM reqid (0 = automatic)", &reqID, validateUint32(true)); err != nil {
			return err
		}
	}
	auth := string(spec.AuthMethod)
	if err := selectIKEAuth(prompts, &auth); err != nil {
		return err
	}
	previousAuth := spec.AuthMethod
	spec.AuthMethod = model.IKEAuthMethod(auth)
	if creating || previousAuth != spec.AuthMethod {
		clearIKECredentials(spec)
		if err := replaceIKECredentials(prompts, spec); err != nil {
			return err
		}
	}
	if err := collectIKEProposals(prompts, spec); err != nil {
		return err
	}
	encapsulation, err := prompts.toggle("UDP encapsulation", spec.Encapsulation)
	if err != nil {
		return err
	}
	if err := selectIKEStartAction(prompts, &spec.StartAction); err != nil {
		return err
	}
	spec.Addresses, _ = parsePrefixes(addresses)
	spec.MTU = parseInt(mtu)
	spec.IfID = parseUint32(ifID)
	spec.ReqID = parseUint32(reqID)
	spec.Encapsulation = encapsulation
	return nil
}

func showLocalRPK(prompts *prompts, publicKey string) {
	prompts.ui.Ok("Local raw public key: " + publicKey)
	prompts.ui.Dim("Share this key with the peer before entering its public key.")
}

func validAddrText(address netip.Addr) string {
	if !address.IsValid() {
		return ""
	}
	return address.String()
}

func defaultIntText(value, fallback int) string {
	if value == 0 {
		value = fallback
	}
	return strconv.Itoa(value)
}

func validateUint32(allowZero bool) func(string) error {
	return func(value string) error {
		number, err := strconv.ParseUint(strings.TrimSpace(value), 0, 32)
		if err != nil {
			return errors.New("must be a 32-bit unsigned integer")
		}
		if number == 0 && !allowZero {
			return errors.New("must be non-zero")
		}
		return nil
	}
}

func parseUint32(value string) uint32 {
	number, _ := strconv.ParseUint(strings.TrimSpace(value), 0, 32)
	return uint32(number)
}

func validateUint32Pair(value string) error {
	left, right := parsePair(value)
	if left == "" || right == "" {
		return errors.New("must contain two comma-separated values")
	}
	if err := validateSPI(left); err != nil {
		return fmt.Errorf("inbound SPI: %w", err)
	}
	if err := validateSPI(right); err != nil {
		return fmt.Errorf("outbound SPI: %w", err)
	}
	return nil
}

func validateSPI(value string) error {
	if err := validateUint32(false)(value); err != nil {
		return err
	}
	if parseUint32(value) < 256 {
		return errors.New("must be at least 256")
	}
	return nil
}

func parseUint32Pair(value string) (uint32, uint32, error) {
	if err := validateUint32Pair(value); err != nil {
		return 0, 0, err
	}
	left, right := parsePair(value)
	return parseUint32(left), parseUint32(right), nil
}

func validateHexInput(size int) func(string) error {
	return func(value string) error {
		value = strings.TrimPrefix(strings.TrimSpace(value), "0x")
		data, err := hex.DecodeString(value)
		if err != nil {
			return errors.New("must be hexadecimal")
		}
		if len(data) != size {
			return fmt.Errorf("must contain %d bytes", size)
		}
		return nil
	}
}

func validateHexPair(size int) func(string) error {
	return func(value string) error {
		left, right := parsePair(value)
		if left == "" || right == "" {
			return errors.New("must contain two comma-separated keys")
		}
		if err := validateHexInput(size)(left); err != nil {
			return fmt.Errorf("inbound key: %w", err)
		}
		if err := validateHexInput(size)(right); err != nil {
			return fmt.Errorf("outbound key: %w", err)
		}
		return nil
	}
}

func parsePair(value string) (string, string) {
	parts := strings.Split(strings.TrimSpace(value), ",")
	if len(parts) != 2 {
		return "", ""
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
}

func validateRPKInput(value string) error {
	_, err := normalizeRPK(value)
	return err
}

func normalizeRPK(value string) (string, error) {
	value = strings.TrimSpace(value)
	if block, _ := pem.Decode([]byte(value)); block != nil {
		value = base64.StdEncoding.EncodeToString(block.Bytes)
	}
	data, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(data) == 0 {
		return "", errors.New("raw public key must be base64 DER or PEM")
	}
	return base64.StdEncoding.EncodeToString(data), nil
}
