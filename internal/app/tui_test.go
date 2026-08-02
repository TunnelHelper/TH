package app

import (
	"strings"
	"testing"

	"github.com/TunnelHelper/TH/internal/core"
	"github.com/TunnelHelper/TH/internal/model"
)

func TestMainMenuDimsUnavailableBackends(t *testing.T) {
	app := &tuiApp{health: map[model.Kind]core.BackendHealth{
		model.KindWireGuard: {Available: true},
		model.KindAmneziaWG: {Available: false, Message: "low-level error"},
		model.KindXFRMIKEv2: {Available: false, Message: "low-level error"},
	}}

	options := app.mainMenuOptions()
	for _, test := range []struct {
		kind   model.Kind
		dimmed bool
	}{
		{kind: model.KindWireGuard, dimmed: false},
		{kind: model.KindAmneziaWG, dimmed: true},
		{kind: model.KindXFRMIKEv2, dimmed: true},
	} {
		t.Run(string(test.kind), func(t *testing.T) {
			for _, option := range options {
				if option.Value == string(test.kind) {
					if option.Dimmed != test.dimmed {
						t.Fatalf("Dimmed = %t, want %t", option.Dimmed, test.dimmed)
					}
					if option.Disabled != test.dimmed {
						t.Fatalf("Disabled = %t, want %t", option.Disabled, test.dimmed)
					}
					if test.dimmed && !strings.Contains(option.Label, "unavailable") {
						t.Fatalf("unavailable option has no text status: %q", option.Label)
					}
					return
				}
			}
			t.Fatalf("missing menu option for %s", test.kind)
		})
	}
}

func TestMainMenuDefaultsToManagementWorkflow(t *testing.T) {
	options := (&tuiApp{}).mainMenuOptions()
	if len(options) < 2 || options[0].Value != "manage" || options[1].Value != "watch" {
		t.Fatalf("main menu order = %+v", options)
	}
	if len(options) < 4 || options[2].Value != string(model.KindWireGuard) || options[3].Value != string(model.KindAmneziaWG) {
		t.Fatalf("V1 creation order was not retained: %+v", options)
	}
	foundSettings := false
	for _, option := range options {
		if option.Value == "settings" && option.Label == "Settings" {
			foundSettings = true
		}
	}
	if !foundSettings {
		t.Fatalf("main menu must expose a single Settings entry: %+v", options)
	}
}

func TestAmneziaUnavailableWarningHidesLowLevelNetlinkError(t *testing.T) {
	message := shortUnavailableWarning(model.KindAmneziaWG, core.BackendHealth{
		Message: "resolve amneziawg generic-netlink family: netlink receive: no such file or directory",
	})
	if message != "AmneziaWG unavailable: generic-netlink family not found" {
		t.Fatalf("warning = %q", message)
	}
	if strings.Contains(message, "netlink receive") || strings.Contains(message, "no such file") {
		t.Fatalf("warning exposes low-level error: %q", message)
	}
}
