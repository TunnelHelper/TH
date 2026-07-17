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

	"github.com/sudogeeker/tunnel-helper/internal/model"
	"github.com/sudogeeker/tunnel-helper/internal/ui"
)

func collectStaticXFRM(prompts *prompts, record *model.Tunnel, creating bool) error {
	spec := record.Spec.XFRMStatic
	if spec == nil {
		spec = &model.XFRMStaticSpec{MTU: 1400, Algorithm: model.XFRMAESGCM}
		record.Spec = model.Spec{XFRMStatic: spec}
	}
	if spec.UnderlayInterface == "" {
		spec.UnderlayInterface = "eth0"
	}
	local, remote := spec.Local.String(), spec.Remote.String()
	if !spec.Local.IsValid() {
		local = "192.0.2.1"
	}
	if !spec.Remote.IsValid() {
		remote = "192.0.2.2"
	}
	addresses := formatPrefixes(spec.Addresses)
	mtu := strconv.Itoa(spec.MTU)
	ifID, reqID := strconv.FormatUint(uint64(spec.IfID), 10), strconv.FormatUint(uint64(spec.ReqID), 10)
	spiIn, spiOut := strconv.FormatUint(uint64(spec.SPIInbound), 10), strconv.FormatUint(uint64(spec.SPIOutbound), 10)
	if err := prompts.input("Underlay interface", &spec.UnderlayInterface, validateInterfaceInput); err != nil {
		return err
	}
	if err := prompts.input("Local underlay IP", &local, validateAddrInput); err != nil {
		return err
	}
	if err := prompts.input("Remote underlay IP", &remote, validateAddrInput); err != nil {
		return err
	}
	if err := prompts.input("Interface addresses", &addresses, validatePrefixesInput); err != nil {
		return err
	}
	if err := prompts.input("MTU", &mtu, validateInt(68, 65535)); err != nil {
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
	spiLabel := "Inbound SPI"
	spiValidator := validateUint32(false)
	if creating {
		spiLabel = "Inbound SPI (0 = automatic)"
		spiValidator = validateUint32(true)
	}
	if err := prompts.input(spiLabel, &spiIn, spiValidator); err != nil {
		return err
	}
	spiLabel = "Outbound SPI"
	if creating {
		spiLabel = "Outbound SPI (0 = automatic)"
	}
	if err := prompts.input(spiLabel, &spiOut, spiValidator); err != nil {
		return err
	}
	algorithm := string(spec.Algorithm)
	if err := prompts.selectValue("Algorithm", []ui.Option{
		{Label: "AES-GCM-128", Value: string(model.XFRMAESGCM)},
		{Label: "AES-CBC-256 + HMAC-SHA256", Value: string(model.XFRMAESCBCSHA256)},
	}, &algorithm); err != nil {
		return err
	}
	previousAlgorithm := spec.Algorithm
	spec.Algorithm = model.XFRMAlgorithm(algorithm)
	if previousAlgorithm != "" && previousAlgorithm != spec.Algorithm {
		spec.EncryptionKeyIn = ""
		spec.EncryptionKeyOut = ""
		spec.AuthenticationKeyIn = ""
		spec.AuthenticationKeyOut = ""
	}
	if creating {
		generate, err := prompts.confirm("Generate key material", true)
		if err != nil {
			return err
		}
		if !generate {
			encBytes := 20
			if spec.Algorithm == model.XFRMAESCBCSHA256 {
				encBytes = 32
			}
			if err := prompts.secret("Inbound encryption key", &spec.EncryptionKeyIn, validateHexInput(encBytes)); err != nil {
				return err
			}
			if err := prompts.secret("Outbound encryption key", &spec.EncryptionKeyOut, validateHexInput(encBytes)); err != nil {
				return err
			}
			if spec.Algorithm == model.XFRMAESCBCSHA256 {
				if err := prompts.secret("Inbound authentication key", &spec.AuthenticationKeyIn, validateHexInput(32)); err != nil {
					return err
				}
				if err := prompts.secret("Outbound authentication key", &spec.AuthenticationKeyOut, validateHexInput(32)); err != nil {
					return err
				}
			}
		}
	}
	spec.Local, _ = netip.ParseAddr(local)
	spec.Remote, _ = netip.ParseAddr(remote)
	spec.Addresses, _ = parsePrefixes(addresses)
	spec.MTU = parseInt(mtu)
	spec.IfID = parseUint32(ifID)
	spec.ReqID = parseUint32(reqID)
	spec.SPIInbound = parseUint32(spiIn)
	spec.SPIOutbound = parseUint32(spiOut)
	return nil
}

func collectIKEv2(prompts *prompts, record *model.Tunnel, creating bool) error {
	spec := record.Spec.XFRMIKEv2
	if spec == nil {
		spec = &model.XFRMIKEv2Spec{
			UnderlayInterface: "eth0",
			LocalAddress:      "%any",
			RemoteAddress:     "%any",
			MTU:               1400,
			AuthMethod:        model.IKEAuthPSK,
			IKEProposal:       "aes128gcm16-prfsha256-curve25519",
			ESPProposal:       "aes128gcm16",
			StartAction:       "trap",
		}
		record.Spec = model.Spec{XFRMIKEv2: spec}
	}
	addresses := formatPrefixes(spec.Addresses)
	mtu := strconv.Itoa(spec.MTU)
	ifID, reqID := strconv.FormatUint(uint64(spec.IfID), 10), strconv.FormatUint(uint64(spec.ReqID), 10)
	if err := prompts.input("Underlay interface", &spec.UnderlayInterface, validateInterfaceInput); err != nil {
		return err
	}
	if err := prompts.input("Local underlay address", &spec.LocalAddress, validateIKEAddrInput); err != nil {
		return err
	}
	if err := prompts.input("Remote underlay address", &spec.RemoteAddress, validateIKEAddrInput); err != nil {
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
	if err := prompts.input("Interface addresses", &addresses, validatePrefixesInput); err != nil {
		return err
	}
	if err := prompts.input("MTU", &mtu, validateInt(68, 65535)); err != nil {
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
	if err := prompts.selectValue("Authentication", []ui.Option{
		{Label: "Pre-shared key", Value: string(model.IKEAuthPSK)},
		{Label: "Raw public key", Value: string(model.IKEAuthRPK)},
	}, &auth); err != nil {
		return err
	}
	spec.AuthMethod = model.IKEAuthMethod(auth)
	if spec.AuthMethod == model.IKEAuthPSK {
		if err := prompts.secret("PSK (blank = generate or keep)", &spec.PSK, func(value string) error {
			if value != "" && len(value) < 16 {
				return errors.New("PSK must contain at least 16 bytes")
			}
			return nil
		}); err != nil {
			return err
		}
	} else {
		if err := prompts.input("Remote raw public key", &spec.RemotePublicKey, validateRPKInput); err != nil {
			return err
		}
		normalized, err := normalizeRPK(spec.RemotePublicKey)
		if err != nil {
			return err
		}
		spec.RemotePublicKey = normalized
	}
	if err := prompts.input("IKE proposal", &spec.IKEProposal, required); err != nil {
		return err
	}
	if err := prompts.input("ESP proposal", &spec.ESPProposal, required); err != nil {
		return err
	}
	encapsulation, err := prompts.confirm("UDP encapsulation", spec.Encapsulation)
	if err != nil {
		return err
	}
	startAction := spec.StartAction
	if err := prompts.selectValue("Start action", []ui.Option{
		{Label: "Install trap policy", Value: "trap"},
		{Label: "Initiate connection", Value: "start"},
		{Label: "Load only", Value: "none"},
	}, &startAction); err != nil {
		return err
	}
	spec.Addresses, _ = parsePrefixes(addresses)
	spec.MTU = parseInt(mtu)
	spec.IfID = parseUint32(ifID)
	spec.ReqID = parseUint32(reqID)
	spec.Encapsulation = encapsulation
	spec.StartAction = startAction
	return nil
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
