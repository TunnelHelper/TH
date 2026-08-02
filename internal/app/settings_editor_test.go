package app

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TunnelHelper/TH/internal/config"
	"github.com/TunnelHelper/TH/internal/control"
	"github.com/TunnelHelper/TH/internal/core"
	tea "github.com/charmbracelet/bubbletea"
	ansi "github.com/charmbracelet/x/ansi"
)

func settingsEditorFixture() settingsModel {
	settings := config.Defaults()
	settings.Babel.RouterID = "0011223344556677"
	settings.Babel.WeightBandwidthExponent = 2
	settings.Babel.WeightRTTExponent = 1
	settings.Mptcp.Enabled = true
	settings.Mptcp.Scheduler = "roundrobin"
	return settingsModel{
		ctx: context.Background(), timeout: time.Second,
		page: settingsMain, original: settings, draft: settings,
		mptcp: core.MptcpHealth{Supported: true, Enabled: true, Status: "enabled", Endpoints: 2},
	}
}

func settingsFieldIndex(fields []workspaceField, id string) int {
	for index, field := range fields {
		if field.ID == id {
			return index + 1
		}
	}
	return 0
}

func TestSettingsFieldsCoverEverySetting(t *testing.T) {
	fields := settingsFields(settingsEditorFixture().draft, settingsEditorFixture().babel.RouterID)
	for _, id := range []string{
		"babel.router_id", "babel.delay_metric", "babel.route_table",
		"babel.unicast_hello_seconds", "babel.max_paths", "babel.slack", "babel.k_penalty",
		"babel.advertise_sources", "babel.advertise_prefixes", "babel.include", "babel.exclude",
		"babel.external_interfaces", "mptcp.enabled", "mptcp.scheduler",
	} {
		if settingsFieldIndex(fields, id) == 0 {
			t.Errorf("settings field %q is missing: %+v", id, fields)
		}
	}

	scheduler := fields[settingsFieldIndex(fields, "mptcp.scheduler")-1]
	if scheduler.Value != "roundrobin" {
		t.Fatalf("scheduler value = %q, want roundrobin", scheduler.Value)
	}
	if len(scheduler.Buttons) != 1+len(config.KnownMPTCPSchedulers) {
		t.Fatalf("scheduler buttons = %+v", scheduler.Buttons)
	}

	delay := fields[settingsFieldIndex(fields, "babel.delay_metric")-1]
	if delay.Value != "On" {
		t.Fatalf("default delay metric value = %q, want On", delay.Value)
	}
}

func TestSettingsToggleAndChoices(t *testing.T) {
	model := settingsEditorFixture()

	if err := model.toggleSettingsField("mptcp.enabled"); err != nil {
		t.Fatal(err)
	}
	if model.draft.Mptcp.Enabled {
		t.Fatal("MPTCP toggle must flip the enabled flag")
	}

	if err := model.applySettingsChoice("settings:babel.delay_metric", "Off"); err != nil {
		t.Fatal(err)
	}
	if model.draft.Babel.DelayMetric == nil || *model.draft.Babel.DelayMetric {
		t.Fatalf("delay metric choice did not apply: %+v", model.draft.Babel.DelayMetric)
	}

	if err := model.applySettingsChoice("settings:mptcp.scheduler", "default"); err != nil {
		t.Fatal(err)
	}
	if model.draft.Mptcp.Scheduler != "default" {
		t.Fatalf("scheduler choice did not apply: %q", model.draft.Mptcp.Scheduler)
	}
}

func TestSettingsInputs(t *testing.T) {
	model := settingsEditorFixture()

	if err := model.applySettingsInput("settings:babel.router_id", []string{"aabbccddeeff0011"}); err != nil {
		t.Fatal(err)
	}
	if model.draft.Babel.RouterID != "aabbccddeeff0011" {
		t.Fatalf("router id = %q", model.draft.Babel.RouterID)
	}

	if err := model.applySettingsInput("settings:babel.advertise_prefixes", []string{"10.0.0.0/8, 2001:db8::/32"}); err != nil {
		t.Fatal(err)
	}
	if len(model.draft.Babel.Advertise.AdvertisedPrefixes) != 2 {
		t.Fatalf("advertised prefixes = %+v", model.draft.Babel.Advertise.AdvertisedPrefixes)
	}
}

func TestSettingsChangesDiff(t *testing.T) {
	before := config.Defaults()
	after := config.Defaults()
	after.Babel.RouterID = "0011223344556677"
	after.Mptcp.Enabled = true
	changes := settingsChanges(before, after)
	if len(changes) != 2 {
		t.Fatalf("changes = %+v, want router id and mptcp enabled", changes)
	}
	if !workspaceHasChange(changes, "Router") || !workspaceHasChange(changes, "Mptcp") {
		t.Fatalf("changes = %+v", changes)
	}
	if len(settingsChanges(before, before)) != 0 {
		t.Fatal("identical settings must produce no changes")
	}
}

func TestExternalInterfaceEditorFlow(t *testing.T) {
	model := settingsEditorFixture()
	model.draft.Babel.Interfaces = map[string]config.BabelExternalInterface{
		"ext0": {BandwidthMbps: 100, Multicast: true},
	}
	model.original = model.draft

	// Add a unicast interface through the name overlay and field edits.
	if err := model.applySettingsInput("add-interface-name", []string{"ext1"}); err != nil {
		t.Fatal(err)
	}
	if model.page != settingsInterface || !model.ifaceAdding || model.ifaceName != "ext1" {
		t.Fatalf("add flow = page %v adding %t name %q", model.page, model.ifaceAdding, model.ifaceName)
	}
	if err := model.applySettingsInput("settings:iface.bandwidth", []string{"50"}); err != nil {
		t.Fatal(err)
	}
	if err := model.applySettingsInput("settings:iface.neighbours", []string{"fe80::1"}); err != nil {
		t.Fatal(err)
	}
	model.commitInterface()
	if model.draft.Babel.Interfaces["ext1"].BandwidthMbps != 50 || model.draft.Babel.Interfaces["ext1"].Multicast {
		t.Fatalf("committed interface = %+v", model.draft.Babel.Interfaces["ext1"])
	}

	// Toggling multicast clears neighbours.
	model.openInterface("ext1")
	if err := model.toggleSettingsField("iface.multicast"); err != nil {
		t.Fatal(err)
	}
	if model.ifaceDraft.Multicast != true || len(model.ifaceDraft.Neighbours) != 0 {
		t.Fatalf("multicast toggle must clear neighbours: %+v", model.ifaceDraft)
	}

	// Removing an interface deletes it from the draft.
	model.ifaceName = "ext0"
	command, err := model.applySettingsConfirm("remove-interface")
	if err != nil || command != nil {
		t.Fatalf("remove-interface = %v, %v", command, err)
	}
	if _, exists := model.draft.Babel.Interfaces["ext0"]; exists {
		t.Fatal("removed interface still present")
	}
	if len(model.draft.Babel.Interfaces) != 1 {
		t.Fatalf("interfaces after removal = %+v", model.draft.Babel.Interfaces)
	}
}

func TestSettingsSaveFlow(t *testing.T) {
	var (
		lock     sync.Mutex
		saved    config.Settings
		saveSeen bool
	)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/settings", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(control.DaemonSettings{Babel: config.Defaults().Babel})
	})
	mux.HandleFunc("PUT /v1/settings", func(writer http.ResponseWriter, request *http.Request) {
		var payload control.DaemonSettings
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		lock.Lock()
		saved = config.Defaults()
		saved.Babel = payload.Babel
		saved.Mptcp = payload.Mptcp
		saveSeen = true
		lock.Unlock()
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(payload)
	})
	mux.HandleFunc("GET /v1/health", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(control.HealthResponse{
			APIVersion: control.APIVersion,
			Mptcp:      core.MptcpHealth{Supported: true, Enabled: true, Status: "enabled", Endpoints: 1},
		})
	})

	socketPath := filepath.Join(t.TempDir(), "settings.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: mux}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		shutdownContext, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownContext)
	})

	client := control.NewClient(socketPath, time.Second)
	t.Cleanup(client.CloseIdleConnections)
	model := newSettingsModel(context.Background(), client, time.Second)

	// Load settings and health.
	loaded, _ := model.Update(settingsLoadMsg{
		settings: config.Defaults(),
		mptcp:    core.MptcpHealth{Supported: true, Enabled: true, Status: "enabled", Endpoints: 1},
	})
	model = loaded.(settingsModel)
	if err := model.applySettingsInput("settings:babel.router_id", []string{"0011223344556677"}); err != nil {
		t.Fatal(err)
	}
	afterKey, _ := model.updateMain(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("s")})
	model = afterKey.(settingsModel)
	if model.overlay == nil || model.overlay.Kind != workspaceOverlayConfirm {
		t.Fatal("pressing s must open the save confirmation")
	}
	if len(settingsChanges(model.original, model.draft)) != 1 {
		t.Fatalf("expected one pending change, got %+v", settingsChanges(model.original, model.draft))
	}

	// Confirm and run the save command.
	command, err := model.applySettingsConfirm("save-settings")
	if err != nil {
		t.Fatal(err)
	}
	if command == nil {
		t.Fatal("save must return a command")
	}
	message := command().(settingsSaveMsg)
	if message.err != nil {
		t.Fatal(message.err)
	}
	lock.Lock()
	defer lock.Unlock()
	if !saveSeen {
		t.Fatal("PUT /v1/settings was not called")
	}
	if saved.Babel.RouterID != "0011223344556677" {
		t.Fatalf("saved router id = %q", saved.Babel.RouterID)
	}
}

func TestSettingsViewsRespectTerminalWidth(t *testing.T) {
	model := settingsEditorFixture()
	model.width, model.height = 120, 40
	views := []string{model.mainView(120)}
	model.draft.Babel.Interfaces = map[string]config.BabelExternalInterface{
		"tun-ext1": {BandwidthMbps: 10, Neighbours: []netip.Addr{netip.MustParseAddr("fe80::1")}},
	}
	model.page = settingsInterfaces
	views = append(views, model.interfacesView(120))
	model.page = settingsInterface
	model.ifaceName = "tun-ext1"
	model.ifaceDraft = model.draft.Babel.Interfaces["tun-ext1"]
	views = append(views, model.interfaceEditorView(120))
	for _, view := range views {
		for _, line := range strings.Split(view, "\n") {
			if got := ansi.StringWidth(line); got > 120 {
				t.Fatalf("line exceeds width 120 by %d cells:\n%s", got-120, line)
			}
		}
	}
}

func TestSettingsMainViewRendersEveryFieldWithoutWindow(t *testing.T) {
	model := settingsEditorFixture()
	view := model.mainView(120)
	for _, field := range settingsFields(model.draft, model.babel.RouterID) {
		if !strings.Contains(view, field.Label) {
			t.Fatalf("settings view hides field %q behind a height window:\n%s", field.Label, view)
		}
	}
}

func TestSettingsMainViewShowsBabelHeaderAndAutoRouterIDInField(t *testing.T) {
	model := settingsEditorFixture()
	model.draft.Babel.RouterID = ""
	model.original.Babel.RouterID = ""
	model.babel = core.BabelHealth{RouterID: "0011223344556677"}
	view := model.mainView(120)
	for _, expected := range []string{"Babel", "Router ID", "0011223344556677 (auto)", "MPTCP"} {
		if !strings.Contains(view, expected) {
			t.Fatalf("settings view does not contain %q:\n%s", expected, view)
		}
	}
	if strings.Contains(view, "Router ID (auto):") {
		t.Fatalf("settings view must not duplicate the auto router id on a separate line:\n%s", view)
	}

	fields := settingsFields(model.draft, model.babel.RouterID)
	routerID := fields[settingsFieldIndex(fields, "babel.router_id")-1]
	if routerID.EditValue != "0011223344556677" {
		t.Fatalf("auto router id must be editable as the effective value, got %q", routerID.EditValue)
	}
}

func TestSettingsEditClearsStaleSavedNotice(t *testing.T) {
	model := settingsEditorFixture()
	model.notice = "Settings saved"
	if err := model.applySettingsChoice("settings:babel.delay_metric", "Off"); err != nil {
		t.Fatal(err)
	}
	if model.notice != "" {
		t.Fatalf("editing after a save must clear the stale notice, got %q", model.notice)
	}
	if err := model.toggleSettingsField("mptcp.enabled"); err != nil {
		t.Fatal(err)
	}
	if model.notice != "" {
		t.Fatalf("toggling after a save must clear the stale notice, got %q", model.notice)
	}
	if err := model.applySettingsInput("settings:babel.router_id", []string{"0011223344556677"}); err != nil {
		t.Fatal(err)
	}
	if model.notice != "" {
		t.Fatalf("editing input after a save must clear the stale notice, got %q", model.notice)
	}
}

func TestSettingsEditorChangesScroll(t *testing.T) {
	model := settingsEditorFixture()
	model.original = config.Defaults()
	model.draft = config.Defaults()
	model.draft.Babel.RouterID = "0011223344556677"
	model.draft.Babel.MultipathSlack = 128
	model.draft.Mptcp.Enabled = true
	model.fieldSelected = len(settingsFields(model.draft, model.babel.RouterID)) - 1

	updated, _ := model.updateMain(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("j")})
	model = updated.(settingsModel)
	if !model.changesFocus {
		t.Fatal("down on the last setting must move focus to the pending changes")
	}
	updated, _ = model.updateMain(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("j")})
	model = updated.(settingsModel)
	if model.changeSelected != 1 {
		t.Fatalf("down must scroll into the changes, selected = %d", model.changeSelected)
	}
	if !strings.Contains(model.mainView(120), "Pending changes") {
		t.Fatalf("settings view must render the pending changes:\n%s", model.mainView(120))
	}
}

func TestValidateBalanceInput(t *testing.T) {
	for _, ok := range []string{"-2", "0", "1.5", "2"} {
		if err := validateBalanceInput(ok); err != nil {
			t.Errorf("%q must be accepted: %v", ok, err)
		}
	}
	for _, bad := range []string{"-2.1", "2.5", "abc", ""} {
		if err := validateBalanceInput(bad); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
}
