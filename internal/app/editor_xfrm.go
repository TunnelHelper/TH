package app

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"

	"github.com/TunnelHelper/TH/internal/model"
	"github.com/TunnelHelper/TH/internal/ui"
)

func staticXFRMEditOptions(spec *model.XFRMStaticSpec) []ui.Option {
	return []ui.Option{
		{Label: "Remote underlay: " + spec.Remote.String(), Value: "remote"},
		{Label: "Local underlay: " + spec.Local.String(), Value: "local"},
		{Label: "Underlay interface: " + spec.UnderlayInterface, Value: "underlay"},
		{Label: "Interface addresses: " + formatPrefixes(spec.Addresses), Value: "addresses"},
		{Label: fmt.Sprintf("MTU: %d", spec.MTU), Value: "mtu"},
		{Label: fmt.Sprintf("Inbound SPI: 0x%x", spec.SPIInbound), Value: "spi-in"},
		{Label: fmt.Sprintf("Outbound SPI: 0x%x", spec.SPIOutbound), Value: "spi-out"},
		{Label: "Algorithm: " + string(spec.Algorithm), Value: "algorithm"},
		{Label: "Replace key material", Value: "keys"},
	}
}

func ikeEditOptions(spec *model.XFRMIKEv2Spec) []ui.Option {
	return []ui.Option{
		{Label: "Remote underlay: " + spec.RemoteAddress, Value: "remote"},
		{Label: "Local underlay: " + spec.LocalAddress, Value: "local"},
		{Label: "Underlay interface: " + spec.UnderlayInterface, Value: "underlay"},
		{Label: "Local identity: " + spec.LocalID, Value: "local-id"},
		{Label: "Remote identity: " + spec.RemoteID, Value: "remote-id"},
		{Label: "Interface addresses: " + formatPrefixes(spec.Addresses), Value: "addresses"},
		{Label: fmt.Sprintf("MTU: %d", spec.MTU), Value: "mtu"},
		{Label: "Authentication: " + string(spec.AuthMethod), Value: "auth"},
		{Label: "Replace authentication material", Value: "auth-material"},
		{Label: "IKE / ESP proposals", Value: "proposals"},
		{Label: "UDP encapsulation: " + enabledState(spec.Encapsulation), Value: "encapsulation"},
		{Label: "Start action: " + spec.StartAction, Value: "start"},
	}
}

func editXFRMField(prompts *prompts, record *model.Tunnel, field string) error {
	if record.Kind == model.KindXFRMStatic {
		return editStaticXFRMField(prompts, record.Spec.XFRMStatic, field)
	}
	return editIKEField(prompts, record.Spec.XFRMIKEv2, field)
}

func editStaticXFRMField(prompts *prompts, spec *model.XFRMStaticSpec, field string) error {
	switch field {
	case "remote", "local":
		value := spec.Remote.String()
		label := "Remote underlay IP"
		if field == "local" {
			value, label = spec.Local.String(), "Local underlay IP"
		}
		if err := prompts.input(label, &value, validateAddrInput); err != nil {
			return err
		}
		address, _ := netip.ParseAddr(value)
		if field == "remote" {
			spec.Remote = address
		} else {
			spec.Local = address
		}
	case "underlay":
		return prompts.input("Underlay interface", &spec.UnderlayInterface, validateInterfaceInput)
	case "addresses":
		value := formatPrefixes(spec.Addresses)
		if err := prompts.input("Interface addresses", &value, validateInterfacePrefixesInput); err != nil {
			return err
		}
		spec.Addresses, _ = parsePrefixes(value)
	case "mtu":
		return editInt(prompts, "MTU (68-65535)", &spec.MTU, 68, 65535)
	case "spi-in", "spi-out":
		value := strconv.FormatUint(uint64(spec.SPIInbound), 10)
		label := "Inbound SPI"
		if field == "spi-out" {
			value, label = strconv.FormatUint(uint64(spec.SPIOutbound), 10), "Outbound SPI"
		}
		if err := prompts.input(label, &value, validateSPI); err != nil {
			return err
		}
		if field == "spi-in" {
			spec.SPIInbound = parseUint32(value)
		} else {
			spec.SPIOutbound = parseUint32(value)
		}
	case "algorithm":
		algorithm := string(spec.Algorithm)
		if err := selectXFRMAlgorithm(prompts, &algorithm); err != nil {
			return err
		}
		if next := model.XFRMAlgorithm(algorithm); next != spec.Algorithm {
			spec.Algorithm = next
			clearStaticXFRMKeys(spec)
			prompts.ui.Info("New key material will be generated when changes are saved")
		}
	case "keys":
		return replaceStaticXFRMKeys(prompts, spec)
	}
	return nil
}

func editIKEField(prompts *prompts, spec *model.XFRMIKEv2Spec, field string) error {
	switch field {
	case "remote", "local":
		target, label := &spec.RemoteAddress, "Remote underlay address"
		if field == "local" {
			target, label = &spec.LocalAddress, "Local underlay address"
		}
		return prompts.input(label, target, validateIKEAddrInput)
	case "underlay":
		return prompts.input("Underlay interface", &spec.UnderlayInterface, validateInterfaceInput)
	case "local-id":
		return prompts.input("Local IKE identity", &spec.LocalID, required)
	case "remote-id":
		return prompts.input("Remote IKE identity", &spec.RemoteID, required)
	case "addresses":
		value := formatPrefixes(spec.Addresses)
		if err := prompts.input("Interface addresses", &value, validateInterfacePrefixesInput); err != nil {
			return err
		}
		spec.Addresses, _ = parsePrefixes(value)
	case "mtu":
		return editInt(prompts, "MTU (68-65535)", &spec.MTU, 68, 65535)
	case "auth":
		auth := string(spec.AuthMethod)
		if err := selectIKEAuth(prompts, &auth); err != nil {
			return err
		}
		if next := model.IKEAuthMethod(auth); next != spec.AuthMethod {
			spec.AuthMethod = next
			clearIKECredentials(spec)
			return replaceIKECredentials(prompts, spec)
		}
	case "auth-material":
		return replaceIKECredentials(prompts, spec)
	case "proposals":
		return collectIKEProposals(prompts, spec)
	case "encapsulation":
		value, err := prompts.toggle("UDP encapsulation", spec.Encapsulation)
		if err != nil {
			return err
		}
		spec.Encapsulation = value
	case "start":
		return selectIKEStartAction(prompts, &spec.StartAction)
	}
	return nil
}

func selectXFRMAlgorithm(prompts *prompts, algorithm *string) error {
	return prompts.selectValue("Algorithm", []ui.Option{
		{Label: "AES-GCM-128", Value: string(model.XFRMAESGCM)},
		{Label: "AES-CBC-256 + HMAC-SHA256", Value: string(model.XFRMAESCBCSHA256)},
	}, algorithm)
}

func clearStaticXFRMKeys(spec *model.XFRMStaticSpec) {
	spec.EncryptionKeyIn, spec.EncryptionKeyOut = "", ""
	spec.AuthenticationKeyIn, spec.AuthenticationKeyOut = "", ""
}

func replaceStaticXFRMKeys(prompts *prompts, spec *model.XFRMStaticSpec) error {
	encBytes := 20
	if spec.Algorithm == model.XFRMAESCBCSHA256 {
		encBytes = 32
	}
	values := []*string{&spec.EncryptionKeyIn, &spec.EncryptionKeyOut}
	labels := []string{"Inbound encryption key", "Outbound encryption key"}
	if spec.Algorithm == model.XFRMAESCBCSHA256 {
		values = append(values, &spec.AuthenticationKeyIn, &spec.AuthenticationKeyOut)
		labels = append(labels, "Inbound authentication key", "Outbound authentication key")
	}
	for index, target := range values {
		size := encBytes
		if index >= 2 {
			size = 32
		}
		*target = ""
		if err := prompts.secret(labels[index], target, validateHexInput(size)); err != nil {
			return err
		}
	}
	return nil
}

func selectIKEAuth(prompts *prompts, auth *string) error {
	return prompts.selectValue("Authentication", []ui.Option{
		{Label: "Pre-shared key", Value: string(model.IKEAuthPSK)},
		{Label: "Raw public key", Value: string(model.IKEAuthRPK)},
	}, auth)
}

func clearIKECredentials(spec *model.XFRMIKEv2Spec) {
	spec.PSK = ""
	spec.LocalPrivateKey, spec.LocalPublicKey, spec.RemotePublicKey = "", "", ""
}

func replaceIKECredentials(prompts *prompts, spec *model.XFRMIKEv2Spec) error {
	if spec.AuthMethod == model.IKEAuthPSK {
		value := ""
		if err := prompts.secret("New PSK (blank = generate)", &value, func(value string) error {
			if value != "" && len(value) < 16 {
				return errors.New("PSK must contain at least 16 bytes")
			}
			return nil
		}); err != nil {
			return err
		}
		spec.PSK = value
		if err := model.GenerateIKECredentials(spec); err != nil {
			return err
		}
		prompts.ui.Ok("New PSK: " + spec.PSK)
		return nil
	}
	spec.LocalPrivateKey, spec.LocalPublicKey = "", ""
	if err := model.GenerateIKECredentials(spec); err != nil {
		return err
	}
	showLocalRPK(prompts, spec.LocalPublicKey)
	if err := prompts.input("Remote raw public key", &spec.RemotePublicKey, validateRPKInput); err != nil {
		return err
	}
	normalized, err := normalizeRPK(spec.RemotePublicKey)
	if err != nil {
		return err
	}
	spec.RemotePublicKey = normalized
	return nil
}

func collectIKEProposals(prompts *prompts, spec *model.XFRMIKEv2Spec) error {
	profile := "recommended"
	if err := prompts.selectValue("Cryptographic profile", []ui.Option{
		{Label: "Recommended: AES-128-GCM / Curve25519", Value: "recommended"},
		{Label: "AES-256-GCM / Curve25519", Value: "aes256"},
		{Label: "Custom proposals", Value: "custom"},
	}, &profile); err != nil {
		return err
	}
	switch profile {
	case "recommended":
		spec.IKEProposal, spec.ESPProposal = "aes128gcm16-prfsha256-curve25519", "aes128gcm16"
	case "aes256":
		spec.IKEProposal, spec.ESPProposal = "aes256gcm16-prfsha384-curve25519", "aes256gcm16"
	case "custom":
		if err := prompts.input("IKE proposal", &spec.IKEProposal, required); err != nil {
			return err
		}
		return prompts.input("ESP proposal", &spec.ESPProposal, required)
	}
	return nil
}

func selectIKEStartAction(prompts *prompts, action *string) error {
	return prompts.selectValue("Start action", []ui.Option{
		{Label: "Install trap policy", Value: "trap"},
		{Label: "Initiate connection", Value: "start"},
		{Label: "Load only", Value: "none"},
	}, action)
}
