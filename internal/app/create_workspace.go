package app

import (
	"context"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/TunnelHelper/TH/internal/control"
	"github.com/TunnelHelper/TH/internal/model"
	"github.com/TunnelHelper/TH/internal/ui"
	tea "github.com/charmbracelet/bubbletea"
)

func runCreateWorkspace(client *control.Client, timeout time.Duration, output *ui.UI, kind model.Kind, suggestedName string, views []model.TunnelView) error {
	if !output.TTY {
		return errors.New("tunnel creation requires a terminal")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	workspace := newCreateWorkspaceModel(ctx, client, timeout, kind, suggestedName, views)
	program := tea.NewProgram(workspace, tea.WithInput(output.Input), tea.WithOutput(output.Out))
	_, err := program.Run()
	return err
}

func newCreateWorkspaceModel(ctx context.Context, client *control.Client, timeout time.Duration, kind model.Kind, suggestedName string, views []model.TunnelView) manageWorkspaceModel {
	draft := newTunnelWorkspaceDraft(kind, suggestedName)
	return manageWorkspaceModel{
		ctx: ctx, client: client, timeout: timeout,
		creating: true, page: workspaceEdit, views: append([]model.TunnelView(nil), views...),
		view: model.TunnelView{Tunnel: draft}, draft: draft,
		peerIndex: -1, sourceIndex: -1,
	}
}

func newTunnelWorkspaceDraft(kind model.Kind, suggestedName string) model.Tunnel {
	name := prefixedTunnelName(kind, suggestedName)
	if strings.TrimSpace(name) == "" {
		name = prefixedTunnelName(kind, defaultTunnelName(kind))
	}
	draft := model.Tunnel{Kind: kind, Name: name, Enabled: true}
	if kind != model.KindSRv6 {
		draft.Interface = interfaceName(kind, name)
	}
	underlay := defaultUnderlayDefaults()
	addresses, _ := parsePrefixes(strings.TrimSpace(os.Getenv("TUNNEL_INSIDE_ADDR")))
	switch kind {
	case model.KindGRE:
		draft.Spec.GRE = &model.GRESpec{Addresses: addresses, MTU: 1450, TTL: 255}
	case model.KindVXLAN:
		draft.Spec.VXLAN = &model.VXLANSpec{
			UnderlayInterface: underlay.Interface, Addresses: addresses,
			VNI: 100, DestinationPort: 4789, MTU: 1450,
		}
	case model.KindWireGuard:
		draft.Spec.WireGuard = &model.WireGuardSpec{Addresses: addresses, MTU: 1420}
	case model.KindAmneziaWG:
		draft.Spec.AmneziaWG = &model.AmneziaWGSpec{
			WireGuardSpec:   model.WireGuardSpec{Addresses: addresses, MTU: 1420},
			JunkPacketCount: 4, JunkPacketMinSize: 40, JunkPacketMaxSize: 1200,
		}
	case model.KindXFRMStatic:
		draft.Spec.XFRMStatic = &model.XFRMStaticSpec{
			UnderlayInterface: underlay.Interface, Addresses: addresses,
			MTU: 1400, Algorithm: model.XFRMAESGCM,
		}
	case model.KindXFRMIKEv2:
		draft.Spec.XFRMIKEv2 = &model.XFRMIKEv2Spec{
			UnderlayInterface: underlay.Interface, LocalAddress: underlay.Local, Addresses: addresses,
			MTU: 1400, AuthMethod: model.IKEAuthPSK,
			IKEProposal: "aes128gcm16-prfsha256-curve25519", ESPProposal: "aes128gcm16", StartAction: "trap",
		}
	case model.KindSRv6:
		draft.Spec.SRv6 = &model.SRv6Spec{
			UnderlayInterface: underlay.Interface, Table: 100, RefreshIntervalSeconds: 3600,
		}
	}
	return draft
}
