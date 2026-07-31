package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/TunnelHelper/TH/internal/control"
	"github.com/TunnelHelper/TH/internal/core"
	"github.com/TunnelHelper/TH/internal/model"
	"github.com/TunnelHelper/TH/internal/ui"
	"github.com/TunnelHelper/TH/internal/version"
)

const tuiHealthTimeout = time.Second

type tuiApp struct {
	client  *control.Client
	timeout time.Duration
	ui      *ui.UI
	prompts *prompts
	health  map[model.Kind]core.BackendHealth
}

func runTUI(client *control.Client, timeout time.Duration) error {
	output := ui.New(os.Stdout, os.Stderr, os.Stdin)
	app := &tuiApp{client: client, timeout: timeout, ui: output, prompts: newPrompts(output)}
	if err := app.loadHealth(); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		output.Warn("thd unavailable")
	}
	for {
		choice := "manage"
		output.Title("TH")
		output.Dim(version.Current().Label())
		err := app.prompts.selectValue("Action", app.mainMenuOptions(), &choice)
		if errors.Is(err, ErrAborted) || choice == "exit" {
			return nil
		}
		if err != nil {
			return err
		}
		if choice == "manage" {
			if err := runManageWorkspace(app.client, app.timeout, output, ""); err != nil && !errors.Is(err, ErrAborted) {
				output.Warn(err.Error())
			}
			continue
		}
		if choice == "watch" {
			if err := runDashboard(app.client, app.timeout, output); err != nil && !errors.Is(err, ErrAborted) {
				output.Warn(err.Error())
			}
			continue
		}
		kind := model.Kind(choice)
		if item, unavailable := app.unavailable(kind); unavailable {
			output.Warn(shortUnavailableWarning(kind, item))
			continue
		}
		if err := app.create(kind); err != nil && !errors.Is(err, ErrAborted) {
			output.Warn(err.Error())
		}
	}
}

func (a *tuiApp) context() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), a.timeout)
}

func (a *tuiApp) loadHealth() error {
	timeout := min(a.timeout, tuiHealthTimeout)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	response, err := a.client.Health(ctx)
	if err != nil {
		return err
	}
	a.health = response.Backends
	return nil
}

func (a *tuiApp) mainMenuOptions() []ui.Option {
	options := []ui.Option{
		{Label: "Manage tunnels", Value: "manage"},
		{Label: "Live status", Value: "watch"},
		{Label: "Create WireGuard", Value: string(model.KindWireGuard)},
		{Label: "Create AmneziaWG", Value: string(model.KindAmneziaWG)},
		{Label: "Create VXLAN", Value: string(model.KindVXLAN)},
		{Label: "Create GRE", Value: string(model.KindGRE)},
		{Label: "Create IKEv2 XFRM", Value: string(model.KindXFRMIKEv2)},
		{Label: "Create static XFRM", Value: string(model.KindXFRMStatic)},
		{Label: "Create SRv6", Value: string(model.KindSRv6)},
		{Label: "Exit", Value: "exit"},
	}
	for i := range options {
		_, options[i].Dimmed = a.unavailable(model.Kind(options[i].Value))
	}
	return options
}

func (a *tuiApp) unavailable(kind model.Kind) (core.BackendHealth, bool) {
	item, ok := a.health[kind]
	return item, ok && !item.Available
}

func shortUnavailableWarning(kind model.Kind, _ core.BackendHealth) string {
	switch kind {
	case model.KindWireGuard:
		return "WireGuard unavailable: kernel support not detected"
	case model.KindAmneziaWG:
		return "AmneziaWG unavailable: generic-netlink family not found"
	case model.KindXFRMIKEv2:
		return "IKEv2 XFRM unavailable: strongSwan VICI not detected"
	default:
		return fmt.Sprintf("%s unavailable", kind)
	}
}

func (a *tuiApp) create(kind model.Kind) error {
	ctx, cancel := a.context()
	views, err := a.client.List(ctx)
	cancel()
	if err != nil {
		return err
	}
	if kind == model.KindSRv6 {
		if handled, err := a.offerExistingSRv6(views); handled || err != nil {
			return err
		}
	}
	record, err := collectTunnel(a.prompts, kind, nil, suggestedTunnelName(kind, views), views)
	if err != nil {
		return err
	}
	if err := model.PrepareNew(&record, time.Now()); err != nil {
		return err
	}
	if record.Kind == model.KindXFRMStatic {
		showStaticXFRMPairing(a.ui, record.Spec.XFRMStatic)
	}
	showTunnelSummary(a.ui, record)
	action := "enable"
	if err := a.prompts.selectValue("Create tunnel", createActionOptions(), &action); err != nil {
		return err
	}
	if action == "back" {
		return nil
	}
	record.Enabled = action == "enable"
	ctx, cancel = a.context()
	view, err := a.client.Create(ctx, record)
	cancel()
	if err != nil {
		return err
	}
	ctx, cancel = a.context()
	reconciled, reconcileErr := a.client.Reconcile(ctx, view.Tunnel.ID)
	cancel()
	if reconcileErr != nil {
		a.ui.Warn(fmt.Sprintf("Saved %s (%s), but applying it failed: %v", view.Tunnel.Name, view.Tunnel.ID, reconcileErr))
		return nil
	}
	view = reconciled
	if view.Status.Phase == model.PhaseError {
		a.ui.Warn(fmt.Sprintf("Saved %s (%s), but it did not become ready", view.Tunnel.Name, view.Tunnel.ID))
	} else {
		a.ui.Ok(fmt.Sprintf("Created %s (%s): %s", view.Tunnel.Name, view.Tunnel.ID, view.Status.Phase))
	}
	showCreatedMaterial(a.ui, record, view)
	return nil
}

func createActionOptions() []ui.Option {
	return []ui.Option{
		{Label: "Create and enable", Value: "enable"},
		{Label: "Create disabled", Value: "disable"},
		{Label: "Back without creating", Value: "back"},
	}
}

func suggestedTunnelName(kind model.Kind, views []model.TunnelView) string {
	base := defaultTunnelName(kind)
	used := make(map[string]bool, len(views))
	for _, view := range views {
		used[view.Tunnel.Name] = true
	}
	if !used[base] {
		return base
	}
	for suffix := 2; ; suffix++ {
		candidate := base + strconv.Itoa(suffix)
		if !used[candidate] {
			return candidate
		}
	}
}

func (a *tuiApp) offerExistingSRv6(views []model.TunnelView) (bool, error) {
	for _, view := range views {
		if view.Tunnel.Kind != model.KindSRv6 {
			continue
		}
		choice := "manage"
		if err := a.prompts.selectValue("SRv6 is already configured", []ui.Option{
			{Label: "Manage " + view.Tunnel.Name, Value: "manage"},
			{Label: "Create another SRv6 configuration", Value: "create"},
			{Label: "Back", Value: "back"},
		}, &choice); err != nil {
			return true, err
		}
		switch choice {
		case "manage":
			return true, runManageWorkspace(a.client, a.timeout, a.ui, view.Tunnel.ID)
		case "back":
			return true, nil
		default:
			return false, nil
		}
	}
	return false, nil
}

func replacementSecretsRequired(current, next model.Tunnel) bool {
	if current.Kind != next.Kind {
		return false
	}
	switch current.Kind {
	case model.KindXFRMStatic:
		return current.Spec.XFRMStatic.Algorithm != next.Spec.XFRMStatic.Algorithm
	case model.KindXFRMIKEv2:
		return current.Spec.XFRMIKEv2.AuthMethod != next.Spec.XFRMIKEv2.AuthMethod
	default:
		return false
	}
}

func showStatus(output *ui.UI, view model.TunnelView) {
	fmt.Fprintf(output.Out, "%s [%s]\n", view.Tunnel.Name, view.Tunnel.Kind)
	fmt.Fprintf(output.Out, "ID: %s\n", view.Tunnel.ID)
	if view.Tunnel.Interface != "" {
		fmt.Fprintf(output.Out, "Interface: %s\n", view.Tunnel.Interface)
	}
	fmt.Fprintf(output.Out, "State: %s\n", enabledState(view.Tunnel.Enabled))
	fmt.Fprintf(output.Out, "Generation: %d / observed %d\n", view.Tunnel.Generation, view.Status.ObservedGeneration)
	fmt.Fprintf(output.Out, "Phase: %s\n", view.Status.Phase)
	summarizedDetails := map[string]bool{"counter_source": true}
	if linkLocal := view.Status.Details["ipv6_link_local"]; linkLocal != "" {
		fmt.Fprintf(output.Out, "IPv6 LLA: %s\n", linkLocal)
		summarizedDetails["ipv6_link_local"] = true
	}
	if _, ok := view.Status.Details["link_receive_bytes"]; ok {
		fmt.Fprintf(output.Out, "Interface link: rx=%s tx=%s\n",
			detailBytes(view, "link_receive_bytes"), detailBytes(view, "link_transmit_bytes"))
		summarizedDetails["link_receive_bytes"] = true
		summarizedDetails["link_transmit_bytes"] = true
	}
	transferLabel := ""
	switch view.Status.Details["counter_source"] {
	case "wireguard":
		transferLabel = "WireGuard peer transfer total"
	case "amneziawg":
		transferLabel = "AmneziaWG peer transfer total"
	}
	if transferLabel != "" {
		fmt.Fprintf(output.Out, "%s: rx=%s tx=%s\n", transferLabel,
			detailBytes(view, "receive_bytes"), detailBytes(view, "transmit_bytes"))
		summarizedDetails["receive_bytes"] = true
		summarizedDetails["transmit_bytes"] = true
	} else if view.Status.Details["counter_source"] == "link" {
		summarizedDetails["receive_bytes"] = true
		summarizedDetails["transmit_bytes"] = true
	}
	if value := view.Status.Details["latest_handshake"]; value != "" {
		if stamp, err := time.Parse(time.RFC3339, value); err == nil {
			fmt.Fprintf(output.Out, "Latest handshake: %s\n", formatHandshakeTime(stamp))
			summarizedDetails["latest_handshake"] = true
		}
	}
	detailKeys := make([]string, 0, len(view.Status.Details))
	for key := range view.Status.Details {
		if summarizedDetails[key] {
			continue
		}
		detailKeys = append(detailKeys, key)
	}
	sort.Strings(detailKeys)
	for _, key := range detailKeys {
		value := view.Status.Details[key]
		fmt.Fprintf(output.Out, "%s: %s\n", statusDetailLabel(key), value)
	}
	for _, condition := range view.Status.Conditions {
		if condition.Message != "" {
			output.Warn(condition.Message)
		}
	}
	for _, peer := range view.Status.Peers {
		handshake := "never"
		if peer.LastHandshakeTime != nil {
			handshake = formatHandshakeTime(*peer.LastHandshakeTime)
		}
		endpoint := peer.Endpoint
		if endpoint == "" {
			endpoint = "-"
		}
		fmt.Fprintf(output.Out, "Peer %s\n", fit(peer.PublicKey, 16))
		fmt.Fprintf(output.Out, "  Endpoint: %s\n", endpoint)
		fmt.Fprintf(output.Out, "  Handshake: %s\n", handshake)
		fmt.Fprintf(output.Out, "  Transfer: rx=%s tx=%s\n", formatBytes(peer.ReceiveBytes), formatBytes(peer.TransmitBytes))
	}
}

func statusDetailLabel(key string) string {
	labels := map[string]string{
		"cache":           "Route cache",
		"ike_sas":         "IKE SAs",
		"link_type":       "Link type",
		"listen_port":     "Listen port",
		"managed_routes":  "Managed routes",
		"mtu":             "MTU",
		"peers":           "Peers",
		"public_key":      "Public key",
		"vici_connection": "VICI connection",
		"xfrm_policies":   "XFRM policies",
		"xfrm_states":     "XFRM states",
	}
	if label := labels[key]; label != "" {
		return label
	}
	label := strings.ReplaceAll(key, "_", " ")
	if label == "" {
		return key
	}
	return strings.ToUpper(label[:1]) + label[1:]
}

func showCreatedMaterial(output *ui.UI, record model.Tunnel, view model.TunnelView) {
	switch record.Kind {
	case model.KindWireGuard:
		showWireGuardPeerReference(output, record.Spec.WireGuard, "")
	case model.KindAmneziaWG:
		spec := record.Spec.AmneziaWG
		showWireGuardPeerReference(output, &spec.WireGuardSpec, formatAmneziaParameters(spec))
	case model.KindXFRMStatic:
		showStaticXFRMPairing(output, record.Spec.XFRMStatic)
	case model.KindXFRMIKEv2:
		spec := record.Spec.XFRMIKEv2
		if spec.AuthMethod == model.IKEAuthPSK {
			fmt.Fprintf(output.Out, "PSK: %s\n", spec.PSK)
		} else {
			fmt.Fprintf(output.Out, "Local raw public key: %s\n", spec.LocalPublicKey)
		}
	}
	if view.Status.Phase == model.PhaseError {
		for _, condition := range view.Status.Conditions {
			if condition.Message != "" {
				output.Warn(condition.Message)
			}
		}
	}
}
