package app

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"

	"github.com/TunnelHelper/TH/internal/model"
)

func collectTunnel(prompts *prompts, kind model.Kind, existing *model.Tunnel) (model.Tunnel, error) {
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
	defaults := map[model.Kind][2]string{
		model.KindGRE:        {"gre", "gre0"},
		model.KindVXLAN:      {"vxlan", "vxlan0"},
		model.KindWireGuard:  {"wireguard", "wg0"},
		model.KindAmneziaWG:  {"amneziawg", "awg0"},
		model.KindXFRMStatic: {"xfrm-static", "xfrm0"},
		model.KindXFRMIKEv2:  {"xfrm-ikev2", "xfrm0"},
		model.KindSRv6:       {"srv6", ""},
	}
	if record.Name == "" {
		record.Name = defaults[kind][0]
	}
	if record.Interface == "" && kind != model.KindSRv6 {
		record.Interface = defaults[kind][1]
	}
	if err := prompts.input("Name", &record.Name, validateNameInput); err != nil {
		return model.Tunnel{}, err
	}
	if kind != model.KindSRv6 && existing == nil {
		if err := prompts.input("Interface", &record.Interface, validateInterfaceInput); err != nil {
			return model.Tunnel{}, err
		}
	}
	enabled, err := prompts.confirm("Enabled", record.Enabled)
	if err != nil {
		return model.Tunnel{}, err
	}
	record.Enabled = enabled

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
		err = collectStaticXFRM(prompts, &record, existing == nil)
	case model.KindXFRMIKEv2:
		err = collectIKEv2(prompts, &record, existing == nil)
	case model.KindSRv6:
		err = collectSRv6(prompts, &record, existing == nil)
	default:
		err = fmt.Errorf("unsupported tunnel kind %q", kind)
	}
	return record, err
}

func collectGRE(prompts *prompts, record *model.Tunnel) error {
	spec := record.Spec.GRE
	if spec == nil {
		spec = &model.GRESpec{MTU: 1450, TTL: 255}
		record.Spec = model.Spec{GRE: spec}
	}
	local, remote := spec.Local.String(), spec.Remote.String()
	if !spec.Local.IsValid() {
		local = "192.0.2.1"
	}
	if !spec.Remote.IsValid() {
		remote = "192.0.2.2"
	}
	addresses := formatPrefixes(spec.Addresses)
	mtu, ttl := strconv.Itoa(spec.MTU), strconv.Itoa(int(spec.TTL))
	if spec.MTU == 0 {
		mtu = "1450"
	}
	if spec.TTL == 0 {
		ttl = "255"
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
	if err := prompts.input("TTL", &ttl, validateInt(1, 255)); err != nil {
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
	vni, port, mtu := strconv.Itoa(spec.VNI), strconv.Itoa(spec.DestinationPort), strconv.Itoa(spec.MTU)
	addresses := formatPrefixes(spec.Addresses)
	if err := prompts.input("Underlay interface", &spec.UnderlayInterface, validateInterfaceInput); err != nil {
		return err
	}
	if err := prompts.input("VNI", &vni, validateInt(1, 16777215)); err != nil {
		return err
	}
	if err := prompts.input("Local underlay IP", &local, validateAddrInput); err != nil {
		return err
	}
	if err := prompts.input("Remote underlay IP", &remote, validateAddrInput); err != nil {
		return err
	}
	if err := prompts.input("Destination port", &port, validateInt(1, 65535)); err != nil {
		return err
	}
	learning, err := prompts.confirm("MAC learning", spec.Learning)
	if err != nil {
		return err
	}
	if err := prompts.input("Interface addresses", &addresses, validatePrefixesInput); err != nil {
		return err
	}
	if err := prompts.input("MTU", &mtu, validateInt(68, 65535)); err != nil {
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
