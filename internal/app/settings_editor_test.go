package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
		page: settingsMain, original: cloneSettings(settings), draft: cloneSettings(settings),
		loaded: true,
		mptcp:  core.MptcpHealth{Supported: true, Enabled: true, Status: "enabled", Endpoints: 2},
	}
}

func TestSettingsDraftDoesNotMutateAuthoritativeSnapshot(t *testing.T) {
	settings := config.Defaults()
	settings.Babel.Interfaces = map[string]config.BabelExternalInterface{
		"ext0": {Multicast: false, Neighbours: []netip.Addr{netip.MustParseAddr("fe80::1")}},
	}
	settings.Babel.Advertise.Include = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	model := newSettingsModel(context.Background(), nil, time.Second)
	updated, _ := model.Update(settingsLoadMsg{settings: settings})
	model = updated.(settingsModel)

	delete(model.draft.Babel.Interfaces, "ext0")
	model.draft.Babel.Advertise.Include[0] = netip.MustParsePrefix("192.0.2.0/24")
	if _, ok := model.original.Babel.Interfaces["ext0"]; !ok {
		t.Fatal("editing the draft mutated the authoritative interface map")
	}
	if got := model.original.Babel.Advertise.Include[0]; got != netip.MustParsePrefix("10.0.0.0/8") {
		t.Fatalf("editing the draft mutated the authoritative include list: %s", got)
	}

	if _, err := model.applySettingsConfirm("discard-settings"); err != nil {
		t.Fatal(err)
	}
	if _, ok := model.draft.Babel.Interfaces["ext0"]; !ok {
		t.Fatal("discard did not restore the authoritative interface map")
	}
	if got := model.draft.Babel.Advertise.Include[0]; got != netip.MustParsePrefix("10.0.0.0/8") {
		t.Fatalf("discard did not restore the authoritative include list: %s", got)
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
		"babel.unicast_hello_seconds", "babel.delay_probe_ms", "babel.delay_max_age_ms", "babel.delay_tau_ms",
		"babel.max_paths", "babel.slack", "babel.k_penalty", "babel.bandwidth_exponent", "babel.rtt_exponent", "babel.jitter_exponent",
		"babel.advertise_sources", "babel.advertise_prefixes", "babel.include", "babel.exclude",
		"babel.external_interfaces", "babel.live_metrics", "mptcp.enabled", "mptcp.scheduler",
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

func TestSettingsInputOverlayAcceptsTyping(t *testing.T) {
	model := settingsEditorFixture()
	model.fieldSelected = settingsFieldIndex(settingsFields(model.draft, model.babel.RouterID), "babel.include") - 1

	opened, _ := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model = opened.(settingsModel)
	if model.overlay == nil || model.overlay.Kind != workspaceOverlayList {
		t.Fatal("opening a prefix-list field must open the structured list editor")
	}
	adding, _ := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model = adding.(settingsModel)
	if !model.input.Focused() {
		t.Fatal("adding a list item must focus its input")
	}

	typed, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("10.0.0.0/8")})
	model = typed.(settingsModel)
	kept, _ := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model = kept.(settingsModel)
	applied, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("s")})
	model = applied.(settingsModel)
	if model.overlay != nil {
		t.Fatal("applying the list must close the overlay")
	}
	want := netip.MustParsePrefix("10.0.0.0/8")
	if len(model.draft.Babel.Advertise.Include) != 1 || model.draft.Babel.Advertise.Include[0] != want {
		t.Fatalf("include filter = %+v, want [%s]", model.draft.Babel.Advertise.Include, want)
	}
}

func TestSettingsMainKeepsIncludeFilterVisibleInSmallTerminal(t *testing.T) {
	model := settingsEditorFixture()
	model.width, model.height = 72, 14
	model.fieldSelected = settingsFieldIndex(settingsFields(model.draft, model.babel.RouterID), "babel.include") - 1
	view := model.mainView(model.width)
	if !strings.Contains(view, "Include filter") || !strings.Contains(view, "above") || !strings.Contains(view, "below") {
		t.Fatalf("selected include filter is not visible in the field window:\n%s", view)
	}
	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model = updated.(settingsModel)
	if model.overlay == nil || model.overlay.Kind != workspaceOverlayList {
		t.Fatalf("visible include filter did not open its list editor: %+v", model.overlay)
	}
}

func TestSettingsListInputResizesWithTerminal(t *testing.T) {
	model := settingsEditorFixture()
	model.width = 120
	model.beginList("settings:babel.include", "Include filter", "", "Prefix", nil, validatePrefixItem, nil)
	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model = updated.(settingsModel)
	updated, _ = model.Update(tea.WindowSizeMsg{Width: 24, Height: 20})
	model = updated.(settingsModel)
	if model.input.Width > 18 {
		t.Fatalf("resized list input width = %d, want <= 18", model.input.Width)
	}
}

func TestSettingsBlocksEditingUntilSettingsLoad(t *testing.T) {
	model := newSettingsModel(context.Background(), nil, time.Second)
	updated, command := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model = updated.(settingsModel)
	if command != nil || model.overlay != nil {
		t.Fatal("settings editor accepted input before the daemon settings loaded")
	}
	if !strings.Contains(model.View(), "Loading settings") {
		t.Fatalf("initial view does not expose loading state:\n%s", model.View())
	}
}

func TestSettingsHealthFailureKeepsAuthoritativeSettingsEditable(t *testing.T) {
	model := newSettingsModel(context.Background(), nil, time.Second)
	settings := config.Defaults()
	settings.Babel.RouterID = "0011223344556677"
	updated, _ := model.Update(settingsLoadMsg{settings: settings, healthErr: errors.New("health unavailable")})
	model = updated.(settingsModel)
	if !model.loaded || model.draft.Babel.RouterID != settings.Babel.RouterID {
		t.Fatalf("health failure discarded loaded settings: loaded=%t draft=%+v", model.loaded, model.draft.Babel)
	}
	if !strings.Contains(model.View(), "Health unavailable") {
		t.Fatalf("health warning is not visible:\n%s", model.View())
	}
}

func TestSettingsReloadFailureKeepsCurrentDraft(t *testing.T) {
	model := settingsEditorFixture()
	before := model.draft
	model.loading = true
	updated, _ := model.Update(settingsLoadMsg{err: errors.New("reload failed")})
	model = updated.(settingsModel)
	if !model.loaded || model.draft.Babel.RouterID != before.Babel.RouterID {
		t.Fatalf("reload failure replaced the current settings: loaded=%t draft=%+v", model.loaded, model.draft)
	}
}

func TestSettingsSearchTreatsLettersAsFilterInput(t *testing.T) {
	model := settingsEditorFixture()
	model.beginSearch("add-interface-select", "Add interface", "", []workspaceButton{
		{Label: "jack0  up", Value: "jack0"},
		{Label: "eth0  up", Value: "eth0"},
	})
	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("jk")})
	model = updated.(settingsModel)
	if got := model.input.Value(); got != "jk" {
		t.Fatalf("search input = %q, want jk", got)
	}
	if buttons := workspaceFilteredButtons(model.overlay.Buttons, model.input.Value()); len(buttons) != 0 {
		t.Fatalf("filter jk unexpectedly matched %+v", buttons)
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

func TestSettingsValidatesDraftBeforeConfirmation(t *testing.T) {
	model := settingsEditorFixture()
	model.draft.Babel.Interfaces = map[string]config.BabelExternalInterface{
		"ext0": {Multicast: false},
	}
	updated, command := model.updateMain(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("s")})
	model = updated.(settingsModel)
	if command != nil || model.overlay != nil || model.err == nil {
		t.Fatalf("invalid settings reached confirmation: overlay=%+v err=%v", model.overlay, model.err)
	}
	if len(settingsChanges(model.original, model.draft)) == 0 {
		t.Fatal("diff omitted the newly added empty interface object")
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
	if err := model.toggleSettingsField("iface.multicast"); err != nil {
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

func TestRemovingLastSelectedInterfaceClampsSelection(t *testing.T) {
	model := settingsEditorFixture()
	model.page = settingsInterfaces
	model.draft.Babel.Interfaces = map[string]config.BabelExternalInterface{
		"ext0": {Multicast: true},
		"ext1": {Multicast: true},
	}
	model.ifaceSelected = 1
	model.ifaceName = "ext1"
	if _, err := model.applySettingsConfirm("remove-interface"); err != nil {
		t.Fatal(err)
	}
	if model.ifaceSelected != 0 {
		t.Fatalf("selection after removing last interface = %d, want 0", model.ifaceSelected)
	}
	updated, _ := model.updateInterfaceList(tea.KeyMsg{Type: tea.KeyEnter})
	model = updated.(settingsModel)
	if model.page != settingsInterface || model.ifaceName != "ext0" {
		t.Fatalf("enter after removal opened page=%d interface=%q", model.page, model.ifaceName)
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
	for _, width := range []int{24, 40, 72, 120} {
		model := settingsEditorFixture()
		model.width, model.height = width, 40
		views := []string{model.mainView(width)}
		model.draft.Babel.Interfaces = map[string]config.BabelExternalInterface{
			"tun-ext1": {BandwidthMbps: 10, Neighbours: []netip.Addr{netip.MustParseAddr("fe80::1")}},
		}
		model.page = settingsInterfaces
		views = append(views, model.interfacesView(width))
		model.page = settingsInterface
		model.ifaceName = "tun-ext1"
		model.ifaceDraft = model.draft.Babel.Interfaces["tun-ext1"]
		views = append(views, model.interfaceEditorView(width))
		model.beginList("settings:babel.include", "Include filter", strings.Repeat("long description ", 8), "Prefix", []string{"10.0.0.0/8"}, validatePrefixItem, nil)
		views = append(views, model.View())
		model.beginSearch("add-interface-select", "Add external Babel interface", "Filter system interfaces", []workspaceButton{{Label: strings.Repeat("interface-name-", 5), Value: "eth0"}})
		views = append(views, model.View())
		for _, view := range views {
			for _, line := range strings.Split(view, "\n") {
				if got := ansi.StringWidth(line); got > width {
					t.Fatalf("line exceeds width %d by %d cells:\n%s", width, got-width, line)
				}
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

func TestSettingsLiveMetricsViewShowsDelayAndWeights(t *testing.T) {
	model := settingsEditorFixture()
	model.babel = core.BabelHealth{
		RouterID:           "0011223344556677",
		OriginatedPrefixes: []string{"10.1.0.0/24"},
		Neighbours: []core.BabelNeighbourHealth{{
			Interface: "wg0", Address: "::ffff:10.44.0.2", RTTMicros: 12_000, JitterMicros: 2_000,
			MinRTTMicros: 10_000, AgeMillis: 500, Samples: 9, Confidence: 0.9, Fresh: true,
		}},
		Routes: []core.BabelRouteHealth{{
			Prefix: "10.0.0.0/24", Interface: "wg0", NextHop: "::ffff:10.44.0.2", Metric: 120,
			PreferredSource: "10.1.0.1",
			BottleneckMbps:  100, RTTMicros: 12_000, JitterMicros: 2_000, AgeMillis: 500,
			Score: 1.25, InstalledWeight: 200, DesiredWeight: 180,
		}},
	}
	fields := settingsFields(model.draft, model.babel.RouterID)
	field := fields[settingsFieldIndex(fields, "babel.live_metrics")-1]
	if err := model.activateSettingsField(field); err != nil {
		t.Fatal(err)
	}
	if model.page != settingsMetrics {
		t.Fatal("live metrics field did not open the metrics page")
	}
	view := model.metricsView(120)
	for _, expected := range []string{"10.1.0.0/24", "wg0", "10.44.0.2", "RTT 12ms", "jitter 2ms", "10.0.0.0/24", "src 10.1.0.1", "weight 200 -> 180"} {
		if !strings.Contains(view, expected) {
			t.Fatalf("metrics view missing %q:\n%s", expected, view)
		}
	}
	if strings.Contains(view, "::ffff:") {
		t.Fatalf("metrics view exposed an IPv4-mapped address:\n%s", view)
	}
}

func TestSettingsAdvertisedPrefixListCanClearLastItem(t *testing.T) {
	model := settingsEditorFixture()
	model.draft.Babel.Advertise.AdvertisedPrefixes = []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")}
	model.original = cloneSettings(model.draft)
	model.beginList("settings:babel.advertise_prefixes", "Advertised prefixes", "", "Prefix",
		[]string{"2001:db8::/32"}, validatePrefixItem, nil)

	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("d")})
	model = updated.(settingsModel)
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("s")})
	model = updated.(settingsModel)
	if model.overlay != nil || len(model.draft.Babel.Advertise.AdvertisedPrefixes) != 0 {
		t.Fatalf("last advertised prefix was not cleared: overlay=%+v prefixes=%v", model.overlay, model.draft.Babel.Advertise.AdvertisedPrefixes)
	}
}

func TestStandaloneBabelMetricsReturnsToMainMenu(t *testing.T) {
	model := settingsEditorFixture()
	model.page = settingsMetrics
	model.metricsOnly = true
	_, command := model.updateMetrics(tea.KeyMsg{Type: tea.KeyEsc})
	if command == nil {
		t.Fatal("standalone Babel status did not quit on escape")
	}
}

func TestSettingsLiveMetricsViewScrollsToAllRoutes(t *testing.T) {
	model := settingsEditorFixture()
	model.page = settingsMetrics
	model.width, model.height = 72, 12
	for i := 0; i < 12; i++ {
		model.babel.Routes = append(model.babel.Routes, core.BabelRouteHealth{
			Prefix: fmt.Sprintf("10.0.%d.0/24", i), Interface: "wg0", NextHop: "fe80::1",
			Metric: 100, BottleneckMbps: 100, RTTMicros: 10_000,
			JitterMicros: 1000, DesiredWeight: 256,
		})
	}
	first := model.metricsView(model.width)
	if model.metricsOffset != 0 || strings.Contains(first, "10.0.11.0/24") {
		t.Fatalf("initial metrics viewport is not at the top:\n%s", first)
	}
	updated, _ := model.updateMetrics(tea.KeyMsg{Type: tea.KeyEnd})
	model = updated.(settingsModel)
	last := model.metricsView(model.width)
	if !strings.Contains(last, "10.0.11.0/24") || model.metricsOffset != model.metricsMaxOffset() {
		t.Fatalf("end did not expose the final route at offset %d/%d:\n%s", model.metricsOffset, model.metricsMaxOffset(), last)
	}
	updated, _ = model.Update(tea.WindowSizeMsg{Width: 72, Height: 40})
	model = updated.(settingsModel)
	if model.metricsOffset > model.metricsMaxOffset() {
		t.Fatalf("resize left metrics offset outside range: %d > %d", model.metricsOffset, model.metricsMaxOffset())
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
	for _, bad := range []string{"-2.1", "2.5", "abc", "", "NaN", "Inf", "-Inf"} {
		if err := validateBalanceInput(bad); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
}
