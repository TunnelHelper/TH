package app

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/TunnelHelper/TH/internal/model"
	"github.com/TunnelHelper/TH/internal/ui"
)

func collectTunnel(prompts *prompts, kind model.Kind, existing *model.Tunnel, suggestedName string, managed []model.TunnelView) (model.Tunnel, error) {
	var record model.Tunnel
	if existing != nil {
		copy, err := model.Clone(*existing)
		if err != nil {
			return model.Tunnel{}, err
		}
		record = copy
	} else {
		record = model.Tunnel{Kind: kind, Enabled: true}
	}
	if record.Kind == "" {
		record.Kind = kind
	}
	if record.Name == "" {
		record.Name = suggestedName
		if record.Name == "" {
			record.Name = defaultTunnelName(kind)
		}
	}
	creating := existing == nil
	if creating {
		prompts.section(tunnelKindTitle(kind), "Configure the tunnel first; activation is chosen after review.")
	}
	namePrompt := "Tunnel name"
	namePrefix := ""
	if creating && kind != model.KindSRv6 {
		namePrefix = interfacePrefix(kind)
	}
	if err := prompts.inputWithPrefix(namePrompt, namePrefix, &record.Name, func(value string) error {
		if err := validateNameInput(value); err != nil {
			return err
		}
		if namePrefix != "" {
			if err := validateInterfaceNameLength(namePrefix, value); err != nil {
				return err
			}
		}
		if creating {
			return validateNewTunnelIdentity(kind, prefixedTunnelName(kind, value), managed)
		}
		return nil
	}); err != nil {
		return model.Tunnel{}, err
	}
	if creating {
		record.Name = prefixedTunnelName(kind, record.Name)
	}
	if creating && kind != model.KindSRv6 {
		record.Interface = interfaceName(kind, record.Name)
		prompts.ui.Info("Interface: " + record.Interface)
	}

	var err error
	switch kind {
	case model.KindGRE:
		err = collectGRE(prompts, &record)
	case model.KindVXLAN:
		err = collectVXLAN(prompts, &record)
	case model.KindWireGuard:
		err = collectWireGuard(prompts, &record)
	case model.KindAmneziaWG:
		err = collectAmneziaWG(prompts, &record)
	case model.KindXFRMStatic:
		err = collectStaticXFRM(prompts, &record, creating)
	case model.KindXFRMIKEv2:
		err = collectIKEv2(prompts, &record, creating)
	case model.KindSRv6:
		err = collectSRv6(prompts, &record, creating)
	default:
		err = fmt.Errorf("unsupported tunnel kind %q", kind)
	}
	if err == nil && creating && kind != model.KindSRv6 {
		enableBabel := "No"
		if err := prompts.selectValue("Babel routing (RFC 8966)", []ui.Option{
			{Label: "On", Value: "Yes"},
			{Label: "Off", Value: "No"},
		}, &enableBabel); err != nil {
			return model.Tunnel{}, err
		}
		if enableBabel == "Yes" {
			record.Spec.Babel = &model.BabelTunnelConfig{Enabled: true}
			bandwidth := "1000"
			if err := prompts.input("Babel bandwidth (Mbps, drives ECMP weights)", &bandwidth, validateNonNegativeIntInput); err != nil {
				return model.Tunnel{}, err
			}
			bandwidthMbps, parseErr := strconv.Atoi(strings.TrimSpace(bandwidth))
			if parseErr != nil {
				return model.Tunnel{}, parseErr
			}
			record.Spec.Babel.BandwidthMbps = bandwidthMbps
		}
	}
	return record, err
}

func defaultTunnelName(kind model.Kind) string {
	if kind == model.KindSRv6 {
		return "srv6"
	}
	if kind == model.KindXFRMStatic {
		return "static1"
	}
	return "prod1"
}

func interfacePrefix(kind model.Kind) string {
	return model.TunnelNamePrefix(kind)
}

func interfaceName(kind model.Kind, name string) string {
	return prefixedTunnelName(kind, name)
}

func prefixedTunnelName(kind model.Kind, name string) string {
	return model.PrefixedTunnelName(kind, name)
}

func tunnelKindTitle(kind model.Kind) string {
	switch kind {
	case model.KindGRE:
		return "GRE tunnel"
	case model.KindVXLAN:
		return "VXLAN tunnel"
	case model.KindWireGuard:
		return "WireGuard tunnel"
	case model.KindAmneziaWG:
		return "AmneziaWG tunnel"
	case model.KindXFRMStatic:
		return "Static XFRM tunnel"
	case model.KindXFRMIKEv2:
		return "IKEv2 XFRM tunnel"
	case model.KindSRv6:
		return "SRv6 routes"
	default:
		return string(kind)
	}
}

func collectGRE(prompts *prompts, record *model.Tunnel) error {
	spec := record.Spec.GRE
	if spec == nil {
		spec = &model.GRESpec{MTU: 1450, TTL: 255}
		record.Spec = model.Spec{GRE: spec}
	}
	local, remote := spec.Local.String(), spec.Remote.String()
	if !spec.Local.IsValid() {
		local = ""
	}
	if !spec.Remote.IsValid() {
		remote = ""
	}
	addresses, err := addressesDefault(prompts, formatPrefixes(spec.Addresses))
	if err != nil {
		return err
	}
	mtu, ttl := strconv.Itoa(spec.MTU), strconv.Itoa(int(spec.TTL))
	if spec.MTU == 0 {
		mtu = "1450"
	}
	if spec.TTL == 0 {
		ttl = "255"
	}
	if err := prompts.input("Remote underlay IP", &remote, validateAddrInput); err != nil {
		return err
	}
	if detected := findUnderlayDefaults(remote); !spec.Local.IsValid() && detected.Local != "" {
		local = detected.Local
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
	if err := prompts.input("TTL (1-255)", &ttl, validateInt(1, 255)); err != nil {
		return err
	}
	spec.Local, _ = netip.ParseAddr(local)
	spec.Remote, _ = netip.ParseAddr(remote)
	spec.Addresses, _ = parsePrefixes(addresses)
	spec.MTU, spec.TTL = parseInt(mtu), uint8(parseInt(ttl))
	return nil
}

func collectVXLAN(prompts *prompts, record *model.Tunnel) error {
	spec := record.Spec.VXLAN
	if spec == nil {
		spec = &model.VXLANSpec{VNI: 100, DestinationPort: 4789, MTU: 1450}
		record.Spec = model.Spec{VXLAN: spec}
	}
	local, remote := spec.Local.String(), spec.Remote.String()
	if !spec.Local.IsValid() {
		local = ""
	}
	if !spec.Remote.IsValid() {
		remote = ""
	}
	vni, port, mtu := strconv.Itoa(spec.VNI), strconv.Itoa(spec.DestinationPort), strconv.Itoa(spec.MTU)
	addresses, err := addressesDefault(prompts, formatPrefixes(spec.Addresses))
	if err != nil {
		return err
	}
	if err := prompts.input("VNI", &vni, validateInt(1, 16777215)); err != nil {
		return err
	}
	if err := prompts.input("Remote underlay IP", &remote, validateAddrInput); err != nil {
		return err
	}
	detected := findUnderlayDefaults(remote)
	if spec.UnderlayInterface == "" {
		spec.UnderlayInterface = detected.Interface
	}
	if !spec.Local.IsValid() && detected.Local != "" {
		local = detected.Local
	}
	if err := prompts.input("Underlay interface", &spec.UnderlayInterface, validateInterfaceInput); err != nil {
		return err
	}
	if err := prompts.input("Local underlay IP", &local, validateAddrInput); err != nil {
		return err
	}
	if err := prompts.input("Destination port (1-65535)", &port, validateInt(1, 65535)); err != nil {
		return err
	}
	learning, err := prompts.toggle("MAC learning", spec.Learning)
	if err != nil {
		return err
	}
	if err := prompts.input("Interface addresses", &addresses, validateInterfacePrefixesInput); err != nil {
		return err
	}
	if err := prompts.input("MTU (68-65535)", &mtu, validateInt(68, 65535)); err != nil {
		return err
	}
	spec.VNI, spec.DestinationPort, spec.MTU = parseInt(vni), parseInt(port), parseInt(mtu)
	spec.Local, _ = netip.ParseAddr(local)
	spec.Remote, _ = netip.ParseAddr(remote)
	spec.Learning = learning
	spec.Addresses, _ = parsePrefixes(addresses)
	return nil
}

func parseOptionalAddr(value string) (*netip.Addr, error) {
	if value == "" {
		return nil, nil
	}
	address, err := netip.ParseAddr(value)
	if err != nil {
		return nil, err
	}
	return &address, nil
}

func validateOptionalIPv6(value string) error {
	if value == "" {
		return nil
	}
	address, err := netip.ParseAddr(value)
	if err != nil {
		return err
	}
	if !address.Is6() || address.IsUnspecified() {
		return errors.New("must be a specified IPv6 address")
	}
	return nil
}
