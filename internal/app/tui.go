package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"time"

	"github.com/TunnelHelper/TH/internal/control"
	"github.com/TunnelHelper/TH/internal/core"
	"github.com/TunnelHelper/TH/internal/model"
	"github.com/TunnelHelper/TH/internal/ui"
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
		output.Title("TH V2")
		err := app.prompts.selectValue("Action", app.mainMenuOptions(), &choice)
		if errors.Is(err, ErrAborted) || choice == "exit" {
			return nil
		}
		if err != nil {
			return err
		}
		if choice == "manage" {
			if err := app.manage(); err != nil && !errors.Is(err, ErrAborted) {
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
		a.ui.HR()
		showStaticXFRMPairing(a.ui, record.Spec.XFRMStatic)
		a.ui.HR()
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
			return true, a.manageOne(view)
		case "back":
			return true, nil
		default:
			return false, nil
		}
	}
	return false, nil
}

func (a *tuiApp) manage() error {
	for {
		ctx, cancel := a.context()
		views, err := a.client.List(ctx)
		cancel()
		if err != nil {
			return err
		}
		if len(views) == 0 {
			choice := "back"
			return a.prompts.selectValue("Managed tunnels", []ui.Option{{Label: "No tunnels yet - Back", Value: "back"}}, &choice)
		}
		options := make([]ui.Option, 0, len(views)+1)
		for i, view := range views {
			state := string(view.Status.Phase)
			if !view.Tunnel.Enabled {
				state = "disabled"
			}
			options = append(options, ui.Option{
				Label: fmt.Sprintf("[%s] %s (%s)", state, view.Tunnel.Name, view.Tunnel.Kind),
				Value: strconv.Itoa(i),
			})
		}
		options = append(options, ui.Option{Label: "Back", Value: "back"})
		choice := "0"
		if err := a.prompts.selectValue("Managed tunnels", options, &choice); err != nil {
			return err
		}
		if choice == "back" {
			return nil
		}
		index, _ := strconv.Atoi(choice)
		if index < 0 || index >= len(views) {
			continue
		}
		if err := a.manageOne(views[index]); err != nil && !errors.Is(err, ErrAborted) {
			a.ui.Warn(err.Error())
		}
	}
}

func (a *tuiApp) manageOne(view model.TunnelView) error {
	for {
		showStatus(a.ui, view)
		toggleLabel := "Enable"
		if view.Tunnel.Enabled {
			toggleLabel = "Disable"
		}
		choice := "status"
		if err := a.prompts.selectValue("Tunnel action", []ui.Option{
			{Label: "Refresh status", Value: "status"},
			{Label: toggleLabel, Value: "toggle"},
			{Label: "Edit", Value: "edit"},
			{Label: "Reconcile", Value: "reconcile"},
			{Label: "Delete", Value: "delete"},
			{Label: "Back", Value: "back"},
		}, &choice); err != nil {
			return err
		}
		if choice == "back" {
			return nil
		}
		ctx, cancel := a.context()
		var err error
		switch choice {
		case "status":
			view, err = a.client.Get(ctx, view.Tunnel.ID)
		case "toggle":
			action := "Disabled"
			if !view.Tunnel.Enabled {
				action = "Enabled"
			}
			view, err = a.client.SetEnabled(ctx, view, !view.Tunnel.Enabled)
			cancel()
			if err == nil {
				view, err = a.reconcileMutation(view, action)
			}
		case "reconcile":
			view, err = a.client.Reconcile(ctx, view.Tunnel.ID)
		case "edit":
			cancel()
			current := view.Tunnel
			updated, saved, collectErr := editTunnel(a.prompts, current)
			if collectErr != nil {
				return collectErr
			}
			if !saved {
				continue
			}
			generatedReplacement := replacementSecretsRequired(view.Tunnel, updated)
			if generatedReplacement {
				if prepareErr := model.PrepareUpdateWithGeneratedSecrets(&updated, &view.Tunnel, time.Now()); prepareErr != nil {
					return prepareErr
				}
				// The client API carries the current generation as its precondition;
				// the daemon assigns the next generation itself.
				updated.Generation = view.Tunnel.Generation
			}
			ctx, cancel = a.context()
			view, err = a.client.Update(ctx, model.TunnelView{Tunnel: updated})
			cancel()
			if err == nil {
				view, err = a.reconcileMutation(view, "Updated")
			}
			if err == nil && generatedReplacement {
				showCreatedMaterial(a.ui, updated, view)
			}
		case "delete":
			cancel()
			target := view.Tunnel.Name
			if view.Tunnel.Interface != "" {
				target += " (" + view.Tunnel.Interface + ")"
			}
			message := fmt.Sprintf("Delete %s and remove its managed network state", target)
			confirmed, confirmErr := a.prompts.confirm(message, false)
			if confirmErr != nil {
				return confirmErr
			}
			if !confirmed {
				continue
			}
			ctx, cancel = a.context()
			err = a.client.Delete(ctx, view)
			cancel()
			if err == nil {
				a.ui.Ok("Tunnel deleted")
				return nil
			}
			return err
		}
		cancel()
		if err != nil {
			return err
		}
	}
}

func (a *tuiApp) reconcileMutation(saved model.TunnelView, action string) (model.TunnelView, error) {
	ctx, cancel := a.context()
	defer cancel()
	view, err := a.client.Reconcile(ctx, saved.Tunnel.ID)
	if err != nil {
		a.ui.Warn(fmt.Sprintf("%s configuration was saved, but applying it failed: %v", action, err))
		return saved, nil
	}
	if view.Status.Phase == model.PhaseError {
		a.ui.Warn(fmt.Sprintf("%s configuration was saved, but the tunnel is in error state", action))
		return view, nil
	}
	a.ui.Ok(fmt.Sprintf("%s %s: %s", action, view.Tunnel.Name, view.Status.Phase))
	return view, nil
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
	output.HR()
	fmt.Fprintf(output.Out, "%s [%s]\n", view.Tunnel.Name, view.Tunnel.Kind)
	fmt.Fprintf(output.Out, "ID: %s\n", view.Tunnel.ID)
	if view.Tunnel.Interface != "" {
		fmt.Fprintf(output.Out, "Interface: %s\n", view.Tunnel.Interface)
	}
	fmt.Fprintf(output.Out, "Enabled: %t\n", view.Tunnel.Enabled)
	fmt.Fprintf(output.Out, "Generation: %d / observed %d\n", view.Tunnel.Generation, view.Status.ObservedGeneration)
	fmt.Fprintf(output.Out, "Phase: %s\n", view.Status.Phase)
	detailKeys := make([]string, 0, len(view.Status.Details))
	for key := range view.Status.Details {
		detailKeys = append(detailKeys, key)
	}
	sort.Strings(detailKeys)
	for _, key := range detailKeys {
		value := view.Status.Details[key]
		fmt.Fprintf(output.Out, "%s: %s\n", key, value)
	}
	for _, condition := range view.Status.Conditions {
		if condition.Message != "" {
			output.Warn(condition.Message)
		}
	}
	for _, peer := range view.Status.Peers {
		handshake := "never"
		if peer.LastHandshakeTime != nil {
			handshake = formatDuration(time.Since(*peer.LastHandshakeTime))
		}
		fmt.Fprintf(output.Out, "Peer %s: endpoint=%s handshake=%s rx=%s tx=%s\n",
			fit(peer.PublicKey, 16), peer.Endpoint, handshake, formatBytes(peer.ReceiveBytes), formatBytes(peer.TransmitBytes))
	}
	output.HR()
}

func showCreatedMaterial(output *ui.UI, record model.Tunnel, view model.TunnelView) {
	output.HR()
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
	output.HR()
}
