package app

import (
	"fmt"

	"github.com/TunnelHelper/TH/internal/model"
	"github.com/TunnelHelper/TH/internal/ui"
)

func editTunnel(prompts *prompts, current model.Tunnel) (model.Tunnel, bool, error) {
	updated, err := model.Clone(current)
	if err != nil {
		return model.Tunnel{}, false, err
	}
	prompts.section("Edit "+current.Name, "Choose individual fields. Nothing is sent until Save changes is selected.")
	for {
		options := []ui.Option{{Label: "Name: " + updated.Name, Value: "name"}}
		options = append(options, tunnelEditOptions(updated)...)
		options = append(options,
			ui.Option{Label: "Save changes", Value: "save"},
			ui.Option{Label: "Discard changes", Value: "discard"},
		)
		choice := "save"
		if err := prompts.selectValue("Field to edit", options, &choice); err != nil {
			return model.Tunnel{}, false, err
		}
		switch choice {
		case "save":
			showTunnelSummary(prompts.ui, updated)
			return updated, true, nil
		case "discard":
			return current, false, nil
		case "name":
			if err := prompts.input("Tunnel name", &updated.Name, validateNameInput); err != nil {
				return model.Tunnel{}, false, err
			}
		default:
			if err := editTunnelField(prompts, &updated, choice); err != nil {
				return model.Tunnel{}, false, err
			}
		}
	}
}

func tunnelEditOptions(record model.Tunnel) []ui.Option {
	switch record.Kind {
	case model.KindGRE:
		return greEditOptions(record.Spec.GRE)
	case model.KindVXLAN:
		return vxlanEditOptions(record.Spec.VXLAN)
	case model.KindWireGuard:
		return wireGuardEditOptions(record.Spec.WireGuard, false)
	case model.KindAmneziaWG:
		return wireGuardEditOptions(&record.Spec.AmneziaWG.WireGuardSpec, true)
	case model.KindXFRMStatic:
		return staticXFRMEditOptions(record.Spec.XFRMStatic)
	case model.KindXFRMIKEv2:
		return ikeEditOptions(record.Spec.XFRMIKEv2)
	case model.KindSRv6:
		return srv6EditOptions(record.Spec.SRv6)
	default:
		return nil
	}
}

func editTunnelField(prompts *prompts, record *model.Tunnel, field string) error {
	switch record.Kind {
	case model.KindGRE, model.KindVXLAN:
		return editBasicTunnelField(prompts, record, field)
	case model.KindWireGuard, model.KindAmneziaWG:
		return editWireGuardField(prompts, record, field)
	case model.KindXFRMStatic, model.KindXFRMIKEv2:
		return editXFRMField(prompts, record, field)
	case model.KindSRv6:
		return editSRv6Field(prompts, record, field)
	default:
		return fmt.Errorf("unsupported tunnel kind %q", record.Kind)
	}
}
