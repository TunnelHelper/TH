package app

import (
	"fmt"
	"net/netip"
	"strconv"

	"github.com/TunnelHelper/TH/internal/model"
	"github.com/TunnelHelper/TH/internal/ui"
)

func greEditOptions(spec *model.GRESpec) []ui.Option {
	return []ui.Option{
		{Label: "Remote underlay: " + spec.Remote.String(), Value: "remote"},
		{Label: "Local underlay: " + spec.Local.String(), Value: "local"},
		{Label: "Interface addresses: " + formatPrefixes(spec.Addresses), Value: "addresses"},
		{Label: fmt.Sprintf("MTU: %d", spec.MTU), Value: "mtu"},
		{Label: fmt.Sprintf("TTL: %d", spec.TTL), Value: "ttl"},
	}
}

func vxlanEditOptions(spec *model.VXLANSpec) []ui.Option {
	return []ui.Option{
		{Label: fmt.Sprintf("VNI: %d", spec.VNI), Value: "vni"},
		{Label: "Remote underlay: " + spec.Remote.String(), Value: "remote"},
		{Label: "Local underlay: " + spec.Local.String(), Value: "local"},
		{Label: "Underlay interface: " + spec.UnderlayInterface, Value: "underlay"},
		{Label: fmt.Sprintf("Destination port: %d", spec.DestinationPort), Value: "port"},
		{Label: "MAC learning: " + enabledState(spec.Learning), Value: "learning"},
		{Label: "Interface addresses: " + formatPrefixes(spec.Addresses), Value: "addresses"},
		{Label: fmt.Sprintf("MTU: %d", spec.MTU), Value: "mtu"},
	}
}

func enabledState(enabled bool) string {
	if enabled {
		return "enabled"
	}
	return "disabled"
}

func editBasicTunnelField(prompts *prompts, record *model.Tunnel, field string) error {
	if record.Kind == model.KindGRE {
		return editGREField(prompts, record.Spec.GRE, field)
	}
	return editVXLANField(prompts, record.Spec.VXLAN, field)
}

func editGREField(prompts *prompts, spec *model.GRESpec, field string) error {
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
	case "addresses":
		value := formatPrefixes(spec.Addresses)
		if err := prompts.input("Interface addresses", &value, validateInterfacePrefixesInput); err != nil {
			return err
		}
		spec.Addresses, _ = parsePrefixes(value)
	case "mtu":
		return editInt(prompts, "MTU (68-65535)", &spec.MTU, 68, 65535)
	case "ttl":
		value := int(spec.TTL)
		if err := editInt(prompts, "TTL (1-255)", &value, 1, 255); err != nil {
			return err
		}
		spec.TTL = uint8(value)
	}
	return nil
}

func editVXLANField(prompts *prompts, spec *model.VXLANSpec, field string) error {
	switch field {
	case "vni":
		return editInt(prompts, "VNI (1-16777215)", &spec.VNI, 1, 16777215)
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
	case "port":
		return editInt(prompts, "Destination port (1-65535)", &spec.DestinationPort, 1, 65535)
	case "learning":
		value, err := prompts.toggle("MAC learning", spec.Learning)
		if err != nil {
			return err
		}
		spec.Learning = value
	case "addresses":
		value := formatPrefixes(spec.Addresses)
		if err := prompts.input("Interface addresses", &value, validateInterfacePrefixesInput); err != nil {
			return err
		}
		spec.Addresses, _ = parsePrefixes(value)
	case "mtu":
		return editInt(prompts, "MTU (68-65535)", &spec.MTU, 68, 65535)
	}
	return nil
}

func editInt(prompts *prompts, label string, target *int, minimum, maximum int) error {
	value := strconv.Itoa(*target)
	if err := prompts.input(label, &value, validateInt(minimum, maximum)); err != nil {
		return err
	}
	*target = parseInt(value)
	return nil
}
