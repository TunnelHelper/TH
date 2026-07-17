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
					return
				}
			}
			t.Fatalf("missing menu option for %s", test.kind)
		})
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
