package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"time"

	"github.com/sudogeeker/tunnel-helper/internal/control"
	"github.com/sudogeeker/tunnel-helper/internal/model"
	"github.com/sudogeeker/tunnel-helper/internal/ui"
)

type tuiApp struct {
	client  *control.Client
	timeout time.Duration
	ui      *ui.UI
	prompts *prompts
}

func runTUI(client *control.Client, timeout time.Duration) error {
	output := ui.New(os.Stdout, os.Stderr, os.Stdin)
	app := &tuiApp{client: client, timeout: timeout, ui: output, prompts: newPrompts(output)}
	if err := app.showHealthWarnings(); err != nil {
		output.Warn(err.Error())
	}
	for {
		choice := "manage"
		output.Title("tunnel-helper V2")
		err := app.prompts.selectValue("Action", []ui.Option{
			{Label: "Manage tunnels", Value: "manage"},
			{Label: "Create GRE", Value: string(model.KindGRE)},
			{Label: "Create VXLAN", Value: string(model.KindVXLAN)},
			{Label: "Create WireGuard", Value: string(model.KindWireGuard)},
			{Label: "Create AmneziaWG", Value: string(model.KindAmneziaWG)},
			{Label: "Create static XFRM", Value: string(model.KindXFRMStatic)},
			{Label: "Create IKEv2 XFRM", Value: string(model.KindXFRMIKEv2)},
			{Label: "Create SRv6", Value: string(model.KindSRv6)},
			{Label: "Exit", Value: "exit"},
		}, &choice)
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
		if err := app.create(model.Kind(choice)); err != nil && !errors.Is(err, ErrAborted) {
			output.Warn(err.Error())
		}
	}
}

func (a *tuiApp) context() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), a.timeout)
}

func (a *tuiApp) showHealthWarnings() error {
	ctx, cancel := a.context()
	defer cancel()
	health, err := a.client.Health(ctx)
	if err != nil {
		return err
	}
	for _, kind := range model.Kinds {
		item, ok := health[kind]
		if !ok {
			continue
		}
		if !item.Available {
			a.ui.Warn(fmt.Sprintf("%s unavailable: %s", kind, item.Message))
		}
	}
	return nil
}

func (a *tuiApp) create(kind model.Kind) error {
	record, err := collectTunnel(a.prompts, kind, nil)
	if err != nil {
		return err
	}
	if err := model.PrepareNew(&record, time.Now()); err != nil {
		return err
	}
	ctx, cancel := a.context()
	defer cancel()
	view, err := a.client.Create(ctx, record)
	if err != nil {
		return err
	}
	a.ui.Ok(fmt.Sprintf("Created %s (%s)", view.Tunnel.Name, view.Tunnel.ID))
	showCreatedMaterial(a.ui, record, view)
	return nil
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
			a.ui.Warn("No managed tunnels")
			return nil
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
			view, err = a.client.SetEnabled(ctx, view, !view.Tunnel.Enabled)
		case "reconcile":
			view, err = a.client.Reconcile(ctx, view.Tunnel.ID)
		case "edit":
			cancel()
			current := view.Tunnel
			updated, collectErr := collectTunnel(a.prompts, current.Kind, &current)
			if collectErr != nil {
				return collectErr
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
			if err == nil && generatedReplacement {
				showCreatedMaterial(a.ui, updated, view)
			}
		case "delete":
			cancel()
			confirmed, confirmErr := a.prompts.confirm("Delete this tunnel", false)
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
	output.HR()
}

func showCreatedMaterial(output *ui.UI, record model.Tunnel, view model.TunnelView) {
	output.HR()
	switch record.Kind {
	case model.KindWireGuard:
		fmt.Fprintf(output.Out, "Public key: %s\n", record.Spec.WireGuard.PublicKey)
	case model.KindAmneziaWG:
		spec := record.Spec.AmneziaWG
		fmt.Fprintf(output.Out, "Public key: %s\n", spec.PublicKey)
		fmt.Fprintf(output.Out, "Obfuscation: %d,%d,%d,%d,%d,%s,%s,%s,%s\n",
			spec.JunkPacketCount, spec.JunkPacketMinSize, spec.JunkPacketMaxSize,
			spec.InitPacketJunkSize, spec.ResponsePacketJunkSize,
			spec.InitMagicHeader, spec.ResponseMagicHeader, spec.UnderloadMagicHeader, spec.TransportMagicHeader)
	case model.KindXFRMStatic:
		spec := record.Spec.XFRMStatic
		fmt.Fprintf(output.Out, "Inbound SPI: 0x%x\nOutbound SPI: 0x%x\n", spec.SPIInbound, spec.SPIOutbound)
		fmt.Fprintf(output.Out, "Inbound encryption key: %s\nOutbound encryption key: %s\n", spec.EncryptionKeyIn, spec.EncryptionKeyOut)
		if spec.AuthenticationKeyIn != "" {
			fmt.Fprintf(output.Out, "Inbound authentication key: %s\nOutbound authentication key: %s\n", spec.AuthenticationKeyIn, spec.AuthenticationKeyOut)
		}
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
