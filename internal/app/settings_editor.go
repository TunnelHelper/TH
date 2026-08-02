package app

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/TunnelHelper/TH/internal/config"
	"github.com/TunnelHelper/TH/internal/control"
	"github.com/TunnelHelper/TH/internal/core"
	"github.com/TunnelHelper/TH/internal/ui"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

type settingsPage uint8

const (
	settingsMain settingsPage = iota
	settingsInterfaces
	settingsInterface
)

type settingsLoadMsg struct {
	settings  config.Settings
	babel     core.BabelHealth
	mptcp     core.MptcpHealth
	err       error
	healthErr error
}

type settingsSaveMsg struct{ err error }

// settingsModel is the unified daemon-settings editor: one page listing
// every operator-editable setting (Babel and MPTCP sections), with
// navigation, per-field edit dialogs, an external-interface sub-editor,
// and a diff-before-save flow.
type settingsModel struct {
	ctx     context.Context
	client  *control.Client
	timeout time.Duration

	page     settingsPage
	original config.Settings
	draft    config.Settings
	babel    core.BabelHealth
	mptcp    core.MptcpHealth

	fieldSelected  int
	changeSelected int
	changesFocus   bool
	ifaceSelected  int
	ifaceAdding    bool
	ifaceName      string
	ifaceDraft     config.BabelExternalInterface

	width     int
	height    int
	loaded    bool
	loading   bool
	busy      string
	err       error
	healthErr error
	notice    string
	overlay   *workspaceOverlay
	input     textinput.Model
}

func runSettingsEditor(client *control.Client, timeout time.Duration, output *ui.UI) error {
	if !output.TTY {
		return errors.New("settings editing requires a terminal")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	model := newSettingsModel(ctx, client, timeout)
	program := tea.NewProgram(model, tea.WithInput(output.Input), tea.WithOutput(output.Out))
	_, err := program.Run()
	return err
}

func newSettingsModel(ctx context.Context, client *control.Client, timeout time.Duration) settingsModel {
	return settingsModel{
		ctx: ctx, client: client, timeout: timeout,
		page: settingsMain, loading: true,
	}
}

func (m settingsModel) Init() tea.Cmd {
	return m.load()
}

func (m settingsModel) load() tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(m.ctx, m.timeout)
		defer cancel()
		settings, settingsErr := m.client.Settings(ctx)
		if settingsErr != nil {
			return settingsLoadMsg{err: settingsErr}
		}
		health, healthErr := m.client.Health(ctx)
		if healthErr != nil {
			return settingsLoadMsg{settings: settings, healthErr: healthErr}
		}
		return settingsLoadMsg{settings: settings, babel: health.Babel, mptcp: health.Mptcp}
	}
}

func (m settingsModel) save() tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(m.ctx, m.timeout)
		defer cancel()
		return settingsSaveMsg{err: m.client.UpdateSettings(ctx, m.draft)}
	}
}

func (m settingsModel) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	if size, ok := message.(tea.WindowSizeMsg); ok {
		m.width, m.height = size.Width, size.Height
		m.resizeInput()
		return m, nil
	}
	if key, ok := message.(tea.KeyMsg); ok && key.String() == "ctrl+c" {
		return m, tea.Quit
	}

	switch message := message.(type) {
	case settingsLoadMsg:
		m.loading = false
		m.busy = ""
		m.err = message.err
		if message.err != nil {
			return m, nil
		}
		m.loaded = true
		m.original = cloneSettings(message.settings)
		m.draft = cloneSettings(message.settings)
		m.babel = message.babel
		m.mptcp = message.mptcp
		m.healthErr = message.healthErr
		return m, nil
	case settingsSaveMsg:
		m.busy = ""
		m.err = message.err
		if message.err != nil {
			return m, nil
		}
		m.original = cloneSettings(m.draft)
		m.notice = "Settings saved"
		m.fieldSelected = 0
		m.loading = true
		m.busy = "Refreshing settings"
		return m, m.load()
	}
	if !m.loaded {
		key, ok := message.(tea.KeyMsg)
		if !ok {
			return m, nil
		}
		switch key.String() {
		case "q", "esc":
			return m, tea.Quit
		case "r":
			if !m.loading {
				m.loading = true
				m.err = nil
				return m, m.load()
			}
		}
		return m, nil
	}

	if m.overlay != nil {
		return m.updateOverlay(message)
	}
	if m.busy != "" {
		return m, nil
	}
	key, ok := message.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	m.err = nil
	switch m.page {
	case settingsMain:
		return m.updateMain(key)
	case settingsInterfaces:
		return m.updateInterfaceList(key)
	case settingsInterface:
		return m.updateInterfaceEditor(key)
	default:
		return m, nil
	}
}

func (m settingsModel) updateMain(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	fields := settingsFields(m.draft, m.babel.RouterID)
	changes := settingsChanges(m.original, m.draft)
	if m.changesFocus && len(changes) > 0 {
		switch key.String() {
		case "up", "k":
			if m.changeSelected > 0 {
				m.changeSelected--
			} else {
				m.changesFocus = false
			}
			return m, nil
		case "down", "j":
			if m.changeSelected+1 < len(changes) {
				m.changeSelected++
			}
			return m, nil
		case "esc":
			m.changesFocus = false
			return m, nil
		case "enter", " ":
			change := changes[min(m.changeSelected, len(changes)-1)]
			m.beginInfo("Pending change", "Complete values for the selected pending change.", workspaceChangeDetailLines(change)...)
			return m, nil
		}
	}
	switch key.String() {
	case "q", "esc":
		if len(settingsChanges(m.original, m.draft)) > 0 {
			m.beginConfirm("discard-settings", "Unsaved changes", "Discard all pending settings changes?", "Discard changes", "Keep editing", true)
			return m, nil
		}
		return m, tea.Quit
	case "up", "k":
		if m.fieldSelected > 0 {
			m.fieldSelected--
		}
	case "down", "j":
		if m.fieldSelected+1 < len(fields) {
			m.fieldSelected++
		} else if len(changes) > 0 {
			m.changesFocus = true
			m.changeSelected = min(m.changeSelected, len(changes)-1)
		}
	case "enter", " ":
		if err := m.activateSettingsField(fields[m.fieldSelected]); err != nil {
			m.err = err
		}
	case "s", "ctrl+s":
		changes := settingsChanges(m.original, m.draft)
		if err := m.draft.Validate(); err != nil {
			m.err = err
			return m, nil
		}
		if len(changes) == 0 {
			m.notice = "No changes to save"
			return m, nil
		}
		m.beginConfirm("save-settings", "Save settings", fmt.Sprintf("Apply %d pending change(s)?", len(changes)), "Save changes", "Keep editing", false)
	case "r":
		if len(changes) > 0 {
			m.beginConfirm("refresh-settings", "Reload settings", "Discard pending changes and reload settings from the daemon?", "Discard and reload", "Keep editing", true)
			return m, nil
		}
		m.loading = true
		m.busy = "Refreshing settings"
		return m, m.load()
	}
	return m, nil
}

func (m settingsModel) updateInterfaceList(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	names := sortedInterfaceNames(m.draft.Babel.Interfaces)
	if len(names) == 0 {
		m.ifaceSelected = 0
	} else {
		m.ifaceSelected = min(m.ifaceSelected, len(names)-1)
	}
	switch key.String() {
	case "q", "esc":
		m.page = settingsMain
	case "up", "k":
		if m.ifaceSelected > 0 {
			m.ifaceSelected--
		}
	case "down", "j":
		if m.ifaceSelected+1 < len(names) {
			m.ifaceSelected++
		}
	case "enter", " ":
		if len(names) > 0 {
			m.openInterface(names[m.ifaceSelected])
		}
	case "a":
		buttons, err := discoverExternalInterfaceButtons(m.draft.Babel.Interfaces)
		if err != nil {
			m.err = err
		} else if len(buttons) == 0 {
			m.notice = "No unconfigured system interfaces found"
		} else {
			m.beginSearch("add-interface-select", "Add external Babel interface", "Type to filter system interfaces, then select one.", buttons)
		}
	case "n":
		m.beginInput("add-interface-name", "Enter external Babel interface", "Use this when the interface will be created after TH is configured.", workspaceInputStep{
			Label: "Interface name (1-15 chars)", Value: "", Validator: validateInterfaceInput,
		})
	case "d":
		if len(names) > 0 {
			m.ifaceName = names[m.ifaceSelected]
			m.beginConfirm("remove-interface", "Remove external interface", "Remove "+m.ifaceName+" from the Babel configuration?", "Remove", "Cancel", true)
		}
	}
	return m, nil
}

func (m settingsModel) updateInterfaceEditor(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	fields := externalInterfaceFields(m.ifaceName, m.ifaceDraft)
	switch key.String() {
	case "q", "esc":
		// Commit the draft; only a brand-new untouched interface is dropped.
		if !(m.ifaceAdding && zeroExternalInterface(m.ifaceDraft)) {
			m.commitInterface()
		}
		m.page = settingsInterfaces
	case "up", "k":
		if m.fieldSelected > 0 {
			m.fieldSelected--
		}
	case "down", "j":
		if m.fieldSelected+1 < len(fields) {
			m.fieldSelected++
		}
	case "enter", " ":
		if err := m.activateSettingsField(fields[m.fieldSelected]); err != nil {
			m.err = err
		}
	}
	return m, nil
}

func (m *settingsModel) openInterface(name string) {
	m.ifaceName = name
	m.ifaceAdding = false
	m.ifaceDraft = m.draft.Babel.Interfaces[name]
	m.fieldSelected = 0
	m.page = settingsInterface
}

func (m *settingsModel) commitInterface() {
	if m.draft.Babel.Interfaces == nil {
		m.draft.Babel.Interfaces = make(map[string]config.BabelExternalInterface)
	}
	m.draft.Babel.Interfaces[m.ifaceName] = m.ifaceDraft
	for index, name := range sortedInterfaceNames(m.draft.Babel.Interfaces) {
		if name == m.ifaceName {
			m.ifaceSelected = index
			break
		}
	}
}

func (m *settingsModel) activateSettingsField(field workspaceField) error {
	switch field.Kind {
	case workspaceFieldInput:
		if itemLabel, itemValidator, ok := workspaceListField(field); ok {
			m.beginList("settings:"+field.ID, field.Label, field.Description, itemLabel, splitNonEmpty(field.EditValue), itemValidator, workspaceWholeListValidator(field.Validator))
			return nil
		}
		m.beginInput("settings:"+field.ID, field.Label, field.Description, workspaceInputStep{
			Label: field.Label, Value: field.EditValue, Validator: field.Validator,
		})
	case workspaceFieldToggle:
		return m.toggleSettingsField(field.ID)
	case workspaceFieldChoice:
		m.beginChoice("settings:"+field.ID, field.Label, field.Description, field.Buttons, field.Selected)
	case workspaceFieldNavigate:
		switch field.ID {
		case "babel.external_interfaces":
			m.ifaceSelected = 0
			m.page = settingsInterfaces
		default:
			return fmt.Errorf("unsupported settings field %q", field.ID)
		}
	default:
		return fmt.Errorf("unsupported settings field %q", field.ID)
	}
	return nil
}

func (m *settingsModel) toggleSettingsField(id string) error {
	m.notice = ""
	switch id {
	case "mptcp.enabled":
		m.draft.Mptcp.Enabled = !m.draft.Mptcp.Enabled
	case "iface.multicast":
		m.ifaceDraft.Multicast = !m.ifaceDraft.Multicast
		if m.ifaceDraft.Multicast {
			m.ifaceDraft.Neighbours = nil
		}
	default:
		return fmt.Errorf("unsupported toggle field %q", id)
	}
	return nil
}

func (m *settingsModel) applySettingsInput(action string, values []string) error {
	m.notice = ""
	if action == "add-interface-name" {
		name := values[0]
		if name == "" {
			return errors.New("interface name is required")
		}
		for existing := range m.draft.Babel.Interfaces {
			if existing == name {
				return fmt.Errorf("interface %q is already configured", name)
			}
		}
		m.ifaceName = name
		m.ifaceAdding = true
		m.ifaceDraft = config.BabelExternalInterface{Multicast: true}
		m.fieldSelected = 0
		m.page = settingsInterface
		return nil
	}
	if !strings.HasPrefix(action, "settings:") {
		return fmt.Errorf("unsupported settings action %q", action)
	}
	id := strings.TrimPrefix(action, "settings:")
	value := values[0]
	babel := &m.draft.Babel
	switch id {
	case "babel.router_id":
		babel.RouterID = value
	case "babel.route_table":
		babel.RouteTable = parseInt(value)
	case "babel.unicast_hello_seconds":
		babel.UnicastHelloSeconds = parseInt(value)
	case "babel.max_paths":
		babel.MultipathMaxPaths = parseInt(value)
	case "babel.slack":
		babel.MultipathSlack = parseInt(value)
	case "babel.k_penalty":
		parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
		if err != nil || parsed < 0 || math.IsNaN(parsed) || math.IsInf(parsed, 0) {
			return errors.New("penalty must be a non-negative number")
		}
		babel.WeightBottleneckPenalty = parsed
	case "babel.advertise_sources":
		babel.Advertise.SourceInterfaces = splitNonEmpty(value)
	case "babel.advertise_prefixes":
		babel.Advertise.AdvertisedPrefixes = parsePrefixList(value)
	case "babel.include":
		babel.Advertise.Include = parsePrefixList(value)
	case "babel.exclude":
		babel.Advertise.Exclude = parsePrefixList(value)
	case "iface.bandwidth":
		m.ifaceDraft.BandwidthMbps = parseInt(value)
	case "iface.neighbours":
		m.ifaceDraft.Neighbours = parseNeighbourList(value)
	default:
		return fmt.Errorf("unsupported settings field %q", id)
	}
	return nil
}

func (m *settingsModel) applySettingsChoice(action, value string) error {
	m.notice = ""
	if action == "add-interface-select" {
		if err := validateInterfaceInput(value); err != nil {
			return err
		}
		if _, exists := m.draft.Babel.Interfaces[value]; exists {
			return fmt.Errorf("interface %q is already configured", value)
		}
		m.ifaceName = value
		m.ifaceAdding = true
		m.ifaceDraft = config.BabelExternalInterface{Multicast: true}
		m.fieldSelected = 0
		m.page = settingsInterface
		return nil
	}
	if !strings.HasPrefix(action, "settings:") {
		return fmt.Errorf("unsupported settings action %q", action)
	}
	id := strings.TrimPrefix(action, "settings:")
	switch id {
	case "babel.delay_metric":
		m.draft.Babel.DelayMetric = boolPtr(value == "On")
	case "mptcp.scheduler":
		m.draft.Mptcp.Scheduler = value
	default:
		return fmt.Errorf("unsupported settings choice %q", id)
	}
	return nil
}

func (m *settingsModel) applySettingsConfirm(action string) (tea.Cmd, error) {
	switch action {
	case "save-settings":
		m.busy = "Saving settings"
		return m.save(), nil
	case "discard-settings":
		m.draft = cloneSettings(m.original)
		m.notice = ""
		return nil, nil
	case "remove-interface":
		delete(m.draft.Babel.Interfaces, m.ifaceName)
		m.ifaceSelected = min(m.ifaceSelected, max(0, len(m.draft.Babel.Interfaces)-1))
		m.page = settingsInterfaces
		return nil, nil
	case "refresh-settings":
		m.loading = true
		m.busy = "Refreshing settings"
		m.err = nil
		return m.load(), nil
	default:
		return nil, fmt.Errorf("unsupported settings action %q", action)
	}
}

func cloneSettings(settings config.Settings) config.Settings {
	cloned := settings
	if settings.Babel.DelayMetric != nil {
		delayMetric := *settings.Babel.DelayMetric
		cloned.Babel.DelayMetric = &delayMetric
	}
	cloned.Babel.Advertise.SourceInterfaces = append([]string(nil), settings.Babel.Advertise.SourceInterfaces...)
	cloned.Babel.Advertise.AdvertisedPrefixes = append([]netip.Prefix(nil), settings.Babel.Advertise.AdvertisedPrefixes...)
	cloned.Babel.Advertise.Include = append([]netip.Prefix(nil), settings.Babel.Advertise.Include...)
	cloned.Babel.Advertise.Exclude = append([]netip.Prefix(nil), settings.Babel.Advertise.Exclude...)
	if settings.Babel.Interfaces != nil {
		cloned.Babel.Interfaces = make(map[string]config.BabelExternalInterface, len(settings.Babel.Interfaces))
		for name, iface := range settings.Babel.Interfaces {
			iface.Neighbours = append([]netip.Addr(nil), iface.Neighbours...)
			cloned.Babel.Interfaces[name] = iface
		}
	}
	return cloned
}

// settingsFields lists every operator-editable setting as an editor field.
// effectiveRouterID is the router ID the running speaker actually uses; when
// the configuration leaves router_id empty, that effective value is shown
// directly in the field (marked as auto) instead of a bare "none".
func settingsFields(settings config.Settings, effectiveRouterID string) []workspaceField {
	babel := settings.Babel
	delay := "On"
	delaySelected := 0
	if !babel.DelayMetricEnabled() {
		delay, delaySelected = "Off", 1
	}
	scheduler := settings.Mptcp.Scheduler
	schedulerSelected := 0
	schedulerButtons := []workspaceButton{{Label: "Leave system default", Value: ""}}
	for _, name := range config.KnownMPTCPSchedulers {
		schedulerButtons = append(schedulerButtons, workspaceButton{Label: name, Value: name})
	}
	for index, button := range schedulerButtons {
		if button.Value == scheduler {
			schedulerSelected = index
		}
	}
	if scheduler == "" {
		scheduler = "Leave system default"
	}

	routerID := babel.RouterID
	routerIDAuto := false
	if strings.TrimSpace(routerID) == "" && effectiveRouterID != "" {
		routerID = effectiveRouterID
		routerIDAuto = true
	}
	routerIDField := workspaceTextField("babel.router_id", "Router ID", routerID, validateBabelRouterIDInput)
	if routerIDAuto {
		routerIDField.Value = routerID + " (auto)"
		routerIDField.EditValue = routerID
	}
	fields := []workspaceField{
		withFieldDescription(routerIDField,
			"16 lowercase hex characters; empty generates a stable ID at startup."),
		withFieldDescription(workspaceChoiceField("babel.delay_metric", "Delay cost", delay, []workspaceButton{
			{Label: "On", Value: "On"}, {Label: "Off", Value: "Off"},
		}, delaySelected), "RFC 9616 delay-based cost: route cost derived from measured RTT."),
		withFieldDescription(workspaceTextField("babel.route_table", "Route table", strconv.Itoa(babel.RouteTable), validateInt(0, math.MaxInt32)),
			"Kernel table for Babel routes; 0 = main table."),
		withFieldDescription(workspaceTextField("babel.unicast_hello_seconds", "Hello interval", strconv.Itoa(babel.UnicastHelloSeconds), validateInt(0, 3600)),
			"Unicast Hello interval in seconds; 0 = default 4."),
		withFieldDescription(workspaceTextField("babel.max_paths", "Max paths", strconv.Itoa(babel.MultipathMaxPaths), validateInt(0, 8)),
			"Maximum number of Babel next hops per prefix; 0 = default 4."),
		withFieldDescription(workspaceTextField("babel.slack", "Path slack", strconv.Itoa(babel.MultipathSlack), validateInt(0, 65534)),
			"Extra cost window for additional multipath candidates; 0 = equal cost only."),
		withFieldDescription(workspaceTextField("babel.k_penalty", "Bottleneck K", strconv.FormatFloat(babel.WeightBottleneckPenalty, 'g', -1, 64), validateNonNegativeFloatInput),
			"K / bottleneck_bw added to the route metric; 0 = delay-only primary path."),
		withFieldDescription(workspaceTextField("babel.advertise_sources", "Advertise sources", strings.Join(babel.Advertise.SourceInterfaces, ","), validateInterfaceListInput),
			"Interfaces whose addresses are advertised; default is lo."),
		withFieldDescription(workspaceTextField("babel.advertise_prefixes", "Advertised prefixes", formatPrefixList(babel.Advertise.AdvertisedPrefixes), validatePrefixListInput),
			"Explicit allowlist replacing interface discovery; empty = discover."),
		withFieldDescription(workspaceTextField("babel.include", "Include filter", formatPrefixList(babel.Advertise.Include), validatePrefixListInput),
			"Only prefixes contained in these are advertised; empty = allow all."),
		withFieldDescription(workspaceTextField("babel.exclude", "Exclude filter", formatPrefixList(babel.Advertise.Exclude), validatePrefixListInput),
			"Prefixes never advertised; exclude wins over include."),
		workspaceField{ID: "babel.external_interfaces", Label: "External Babel interfaces", Value: externalInterfacesSummary(babel.Interfaces), Kind: workspaceFieldNavigate},
		withFieldDescription(workspaceToggleField("mptcp.enabled", "MPTCP endpoints", settings.Mptcp.Enabled),
			"Register tunnel addresses as MPTCP endpoints; default off."),
		withFieldDescription(workspaceChoiceField("mptcp.scheduler", "MPTCP scheduler", scheduler, schedulerButtons, schedulerSelected),
			"Node-global scheduler affecting all MPTCP traffic; empty leaves the system default."),
	}
	return fields
}

func withFieldDescription(field workspaceField, description string) workspaceField {
	field.Description = description
	return field
}

func externalInterfaceFields(name string, external config.BabelExternalInterface) []workspaceField {
	fields := []workspaceField{
		withFieldDescription(workspaceTextField("iface.bandwidth", "Bandwidth", strconv.Itoa(external.BandwidthMbps), validateInt(0, 400000)),
			"Usable bandwidth in Mbps; 0 = unlimited."),
		workspaceToggleField("iface.multicast", "Multicast", external.Multicast),
	}
	if !external.Multicast {
		fields = append(fields, withFieldDescription(workspaceTextField("iface.neighbours", "Neighbours", formatNeighbourList(external.Neighbours), validateNeighbourListInput),
			"Unicast Babel neighbour addresses."))
	}
	_ = name
	return fields
}

func sortedInterfaceNames(interfaces map[string]config.BabelExternalInterface) []string {
	names := make([]string, 0, len(interfaces))
	for name := range interfaces {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func zeroExternalInterface(external config.BabelExternalInterface) bool {
	return external.BandwidthMbps == 0 && !external.Multicast && len(external.Neighbours) == 0
}

func validateBalanceInput(value string) error {
	bias, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
	if err != nil || math.IsNaN(bias) || math.IsInf(bias, 0) || bias < -2 || bias > 2 {
		return errors.New("balance must be between -2 (latency) and +2 (bandwidth)")
	}
	return nil
}

func settingsChanges(before, after config.Settings) []workspaceChange {
	// Explicit (non-omitempty) encoding so that toggling MPTCP off renders
	// "enabled -> disabled" instead of dropping the field from the diff.
	type editableMptcp struct {
		Enabled   bool   `json:"enabled"`
		Scheduler string `json:"scheduler,omitempty"`
	}
	type editableSettings struct {
		Babel config.BabelSettings `json:"babel,omitempty"`
		Mptcp editableMptcp        `json:"mptcp,omitempty"`
	}
	return workspaceStructuredChanges(
		editableSettings{Babel: before.Babel, Mptcp: editableMptcp{Enabled: before.Mptcp.Enabled, Scheduler: before.Mptcp.Scheduler}},
		editableSettings{Babel: after.Babel, Mptcp: editableMptcp{Enabled: after.Mptcp.Enabled, Scheduler: after.Mptcp.Scheduler}},
	)
}

func (m settingsModel) mptcpStatusLabel() string {
	if m.healthErr != nil {
		return "unavailable"
	}
	label := m.mptcp.Status
	if !m.mptcp.Supported && m.mptcp.Message != "" {
		label += " (" + m.mptcp.Message + ")"
	}
	return label
}

func (m settingsModel) mainView(width int) string {
	fields := settingsFields(m.draft, m.babel.RouterID)
	changes := settingsChanges(m.original, m.draft)
	status := workspaceGoodStyle.Render("Saved")
	if len(changes) > 0 {
		status = workspaceWarnStyle.Bold(true).Render(fmt.Sprintf("Unsaved  %d change(s)", len(changes)))
	}
	feedback := m.feedbackLines(width)
	hints := workspaceHintLines(width, "up/down  Select fields/changes", "enter  Edit field", "s  Save settings", "r  Refresh", "esc  Back")
	if m.changesFocus {
		hints = workspaceHintLines(width, "up/down  Select change", "enter  View complete values", "s  Save settings", "esc  Fields")
	}
	changeLines := workspaceDiffWindow(changes, m.changeSelected, m.changesFocus, width, workspaceChangeViewportRows)
	lines := []string{
		workspaceDimStyle.Render(fit("TH / Settings", width)), "",
		workspaceAccentStyle.Render(fit("Daemon settings", width)), status, "",
	}
	section := ""
	for index := range fields {
		field := fields[index]
		next := "babel"
		if strings.HasPrefix(field.ID, "mptcp.") {
			next = "mptcp"
		}
		if next != section {
			section = next
			sectionLabel := "Babel"
			if section == "mptcp" {
				sectionLabel = "MPTCP"
			}
			lines = append(lines, "", workspaceAccentStyle.Render(fit(sectionLabel, width)))
			if section == "mptcp" {
				lines = append(lines, workspaceDimStyle.Render(truncateDisplay("Kernel: "+m.mptcpStatusLabel(), width)))
				lines = append(lines, workspaceDimStyle.Render(truncateDisplay(fmt.Sprintf("TH-managed endpoints: %d", m.mptcp.Endpoints), width)))
			}
		}
		lines = append(lines, renderWorkspaceField(field, index == m.fieldSelected, width))
	}
	lines = append(lines, "", workspaceDimStyle.Render(truncateDisplay("MPTCP aggregation depends on subflow count; TH manages endpoints only.", width)))
	lines = append(lines, "")
	lines = append(lines, changeLines...)
	lines = append(lines, feedback...)
	lines = append(lines, "")
	lines = append(lines, hints...)
	return strings.Join(lines, "\n")
}

func (m settingsModel) interfacesView(width int) string {
	names := sortedInterfaceNames(m.draft.Babel.Interfaces)
	lines := []string{
		workspaceDimStyle.Render(fit("TH / Settings / Babel / External interfaces", width)), "",
		workspaceAccentStyle.Render(fit("External Babel interfaces", width)), "",
	}
	if len(names) == 0 {
		lines = append(lines, "No external interfaces configured")
	} else {
		start, end := workspaceVisibleRange(len(names), m.ifaceSelected, max(3, m.inlineHeight()-10))
		if status := workspaceWindowStatus(start, end, len(names), width); status != "" {
			lines = append(lines, status)
		}
		for index := start; index < end; index++ {
			name := names[index]
			marker := "  "
			if index == m.ifaceSelected {
				marker = "> "
			}
			detail := externalInterfacesSummary(map[string]config.BabelExternalInterface{name: m.draft.Babel.Interfaces[name]})
			lines = append(lines, wrapDisplayText(marker+name+"  "+detail, width)...)
		}
		lines = append(lines, "")
	}
	lines = append(lines, m.feedbackLines(width)...)
	lines = append(lines, "")
	lines = append(lines, workspaceHintLines(width, "enter  Edit", "a  Add from system", "n  Enter name", "d  Remove", "esc  Back")...)
	return strings.Join(lines, "\n")
}

func (m settingsModel) interfaceEditorView(width int) string {
	fields := externalInterfaceFields(m.ifaceName, m.ifaceDraft)
	lines := []string{
		workspaceDimStyle.Render(fit("TH / Settings / Babel / "+m.ifaceName, width)), "",
		workspaceAccentStyle.Render(fit("External interface "+m.ifaceName, width)), "",
	}
	start, end := workspaceVisibleRange(len(fields), m.fieldSelected, max(3, m.inlineHeight()-8))
	if status := workspaceWindowStatus(start, end, len(fields), width); status != "" {
		lines = append(lines, status)
	}
	for index := start; index < end; index++ {
		lines = append(lines, renderWorkspaceField(fields[index], index == m.fieldSelected, width))
	}
	lines = append(lines, "")
	lines = append(lines, m.feedbackLines(width)...)
	lines = append(lines, "")
	lines = append(lines, workspaceHintLines(width, "enter  Edit field", "esc  Back")...)
	return strings.Join(lines, "\n")
}

func (m settingsModel) View() string {
	height := m.inlineHeight()
	width := m.inlineWidth()
	if !m.loaded {
		lines := []string{
			workspaceDimStyle.Render(fit("TH / Settings", width)), "",
			workspaceAccentStyle.Render("Daemon settings"), "",
		}
		if m.loading {
			lines = append(lines, workspaceDimStyle.Render("Loading settings..."))
		} else if m.err != nil {
			lines = append(lines, workspaceErrorStyle.Render(fit(m.err.Error(), width)), "", workspaceDimStyle.Render("r  Retry    esc  Back"))
		}
		return strings.Join(lines, "\n")
	}
	var base string
	switch m.page {
	case settingsMain:
		base = m.mainView(width)
	case settingsInterfaces:
		base = m.interfacesView(width)
	case settingsInterface:
		base = m.interfaceEditorView(width)
	}
	if m.overlay == nil {
		return fitWorkspaceHeight(base, height)
	}
	overlay := m.overlayView(width)
	overlayLines := strings.Count(overlay, "\n") + 1
	base = fitWorkspaceHeight(base, max(1, height-overlayLines-1))
	return fitWorkspaceHeight(base+"\n\n"+overlay, height)
}

func (m settingsModel) inlineHeight() int {
	if m.height > 0 {
		return m.height
	}
	return workspaceMaxInlineHeight
}

func (m settingsModel) inlineWidth() int {
	if m.width > 0 {
		return m.width
	}
	return 80
}

func (m settingsModel) feedbackLines(width int) []string {
	message := ""
	style := workspaceDimStyle
	if m.notice != "" {
		message = m.notice
		style = workspaceGoodStyle
		if strings.Contains(strings.ToLower(m.notice), "failed") || strings.Contains(strings.ToLower(m.notice), "error") {
			style = workspaceWarnStyle
		}
	}
	if m.busy != "" {
		message = m.busy + "..."
		style = workspaceWarnStyle
	}
	if m.err != nil {
		message = m.err.Error()
		style = workspaceErrorStyle
	}
	lines := []string{"", style.Render(fit(message, width))}
	if m.healthErr != nil {
		lines = append(lines, workspaceWarnStyle.Render(fit("Health unavailable: "+m.healthErr.Error(), width)))
	} else {
		lines = append(lines, "")
	}
	return lines
}

// Overlay handling mirrors the tunnel workspace editor.

func (m *settingsModel) beginInput(action, title, description string, steps ...workspaceInputStep) {
	values := make([]string, len(steps))
	for index := range steps {
		values[index] = steps[index].Value
	}
	m.overlay = &workspaceOverlay{
		Kind: workspaceOverlayInput, Title: title, Description: description,
		Action: action, Steps: steps, Values: values,
	}
	m.configureInputStep()
}

func (m *settingsModel) beginChoice(action, title, description string, buttons []workspaceButton, selected int) {
	if selected < 0 || selected >= len(buttons) {
		selected = 0
	}
	m.overlay = &workspaceOverlay{
		Kind: workspaceOverlayChoice, Title: title, Description: description,
		Action: action, Buttons: buttons, Selected: selected,
	}
}

func (m *settingsModel) beginConfirm(action, title, description, confirmLabel, cancelLabel string, destructive bool) {
	m.overlay = &workspaceOverlay{
		Kind: workspaceOverlayConfirm, Title: title, Description: description,
		Action: action, Selected: 1,
		Buttons: []workspaceButton{
			{Label: confirmLabel, Value: "confirm", Destructive: destructive},
			{Label: cancelLabel, Value: "cancel"},
		},
	}
}

func (m *settingsModel) beginInfo(title, description string, lines ...string) {
	m.overlay = &workspaceOverlay{
		Kind: workspaceOverlayInfo, Title: title, Description: description,
		Lines: append([]string(nil), lines...),
	}
}

func (m *settingsModel) beginList(action, title, description, itemLabel string, items []string, itemValidator func(string) error, listValidator func([]string) error) {
	m.overlay = workspaceListOverlay(action, title, description, itemLabel, items, itemValidator, listValidator)
}

func (m *settingsModel) beginSearch(action, title, description string, buttons []workspaceButton) {
	input := textinput.New()
	input.Prompt = "Filter> "
	input.CharLimit = 128
	input.Width = max(12, min(76, m.width-10))
	input.Focus()
	m.input = input
	m.overlay = &workspaceOverlay{
		Kind: workspaceOverlaySearch, Action: action, Title: title, Description: description,
		Buttons: append([]workspaceButton(nil), buttons...),
	}
}

func (m *settingsModel) configureInputStep() {
	if m.overlay == nil || m.overlay.Kind != workspaceOverlayInput || m.overlay.Step >= len(m.overlay.Steps) {
		return
	}
	step := m.overlay.Steps[m.overlay.Step]
	input := textinput.New()
	input.Prompt = "> "
	input.SetValue(m.overlay.Values[m.overlay.Step])
	input.CharLimit = 8192
	input.Width = max(12, min(76, m.width-6))
	if step.Secret {
		input.EchoMode = textinput.EchoPassword
		input.EchoCharacter = '*'
	}
	input.Focus()
	input.CursorEnd()
	m.input = input
}

func (m *settingsModel) resizeInput() {
	if m.overlay != nil && (m.overlay.Kind == workspaceOverlayInput || m.overlay.Kind == workspaceOverlayList && m.overlay.Editing) {
		m.input.Width = max(12, min(76, m.width-6))
	} else if m.overlay != nil && m.overlay.Kind == workspaceOverlaySearch {
		m.input.Width = max(12, min(76, m.width-10))
	}
}

func (m settingsModel) updateOverlay(message tea.Msg) (tea.Model, tea.Cmd) {
	key, isKey := message.(tea.KeyMsg)
	if m.overlay.Kind == workspaceOverlaySearch {
		return m.updateSearchOverlay(message)
	}
	if m.overlay.Kind == workspaceOverlayList {
		var event workspaceListEvent
		var command tea.Cmd
		m.input, command, event = workspaceUpdateListOverlay(m.overlay, m.input, message, m.width)
		switch event {
		case workspaceListCancel:
			m.overlay = nil
		case workspaceListApply:
			action := m.overlay.Action
			value := strings.Join(m.overlay.Items, ",")
			m.overlay = nil
			if err := m.applySettingsInput(action, []string{value}); err != nil {
				m.err = err
			}
		}
		return m, command
	}
	if !isKey {
		if m.overlay.Kind == workspaceOverlayInput {
			var command tea.Cmd
			m.input, command = m.input.Update(message)
			return m, command
		}
		return m, nil
	}
	if key.String() == "esc" {
		m.overlay = nil
		return m, nil
	}
	if m.overlay.Kind == workspaceOverlayInfo {
		workspaceUpdateInfoOverlay(m.overlay, key, m.width, m.height)
		return m, nil
	}
	if m.overlay.Kind == workspaceOverlayInput {
		if key.String() == "enter" {
			step := m.overlay.Steps[m.overlay.Step]
			value := m.input.Value()
			if step.Validator != nil {
				if err := step.Validator(value); err != nil {
					m.overlay.Err = err
					return m, nil
				}
			}
			m.overlay.Values[m.overlay.Step] = value
			if m.overlay.Step+1 < len(m.overlay.Steps) {
				m.overlay.Step++
				m.overlay.Err = nil
				m.configureInputStep()
				return m, nil
			}
			action, values := m.overlay.Action, append([]string(nil), m.overlay.Values...)
			m.overlay = nil
			if err := m.applySettingsInput(action, values); err != nil {
				m.err = err
			}
			return m, nil
		}
		m.overlay.Err = nil
		var command tea.Cmd
		m.input, command = m.input.Update(message)
		return m, command
	}

	switch key.String() {
	case "left", "up", "shift+tab", "h", "k":
		if m.overlay.Selected > 0 {
			m.overlay.Selected--
		} else {
			m.overlay.Selected = len(m.overlay.Buttons) - 1
		}
	case "right", "down", "tab", "l", "j":
		if m.overlay.Selected+1 < len(m.overlay.Buttons) {
			m.overlay.Selected++
		} else {
			m.overlay.Selected = 0
		}
	case "enter", " ":
		action := m.overlay.Action
		value := m.overlay.Buttons[m.overlay.Selected].Value
		kind := m.overlay.Kind
		m.overlay = nil
		if kind == workspaceOverlayConfirm {
			if value == "cancel" {
				return m, nil
			}
			command, err := m.applySettingsConfirm(action)
			if err != nil {
				m.err = err
			}
			return m, command
		}
		if err := m.applySettingsChoice(action, value); err != nil {
			m.err = err
		}
	}
	return m, nil
}

func (m settingsModel) overlayView(width int) string {
	if m.overlay == nil {
		return ""
	}
	lines := []string{workspaceAccentStyle.Render(fit(m.overlay.Title, width))}
	if m.overlay.Description != "" {
		for _, line := range wrapDisplayText(m.overlay.Description, width) {
			lines = append(lines, workspaceDimStyle.Render(line))
		}
	}
	if m.overlay.Kind == workspaceOverlayInfo {
		return workspaceRenderInfoOverlay(m.overlay, lines, width, m.height)
	}
	if m.overlay.Kind == workspaceOverlayList {
		return workspaceRenderListOverlay(m.overlay, m.input, lines, width, m.height)
	}
	if m.overlay.Kind == workspaceOverlaySearch {
		return m.searchOverlayView(lines, width)
	}
	if m.overlay.Kind == workspaceOverlayInput {
		step := m.overlay.Steps[m.overlay.Step]
		label := step.Label
		if len(m.overlay.Steps) > 1 {
			label = fmt.Sprintf("%s  (%d/%d)", label, m.overlay.Step+1, len(m.overlay.Steps))
		}
		lines = append(lines, label, m.input.View())
		if m.overlay.Err != nil {
			lines = append(lines, workspaceErrorStyle.Render(fit(m.overlay.Err.Error(), width)))
		}
		lines = append(lines, workspaceHintLines(width, "enter  Apply", "esc  Cancel")...)
		return strings.Join(lines, "\n")
	}
	lines = append(lines, renderWorkspaceButtons(m.overlay.Buttons, m.overlay.Selected, width))
	if m.overlay.Err != nil {
		lines = append(lines, workspaceErrorStyle.Render(fit(m.overlay.Err.Error(), width)))
	}
	lines = append(lines, workspaceHintLines(width, "arrows/tab  Select", "enter  Apply", "esc  Cancel")...)
	return strings.Join(lines, "\n")
}

func (m settingsModel) updateSearchOverlay(message tea.Msg) (tea.Model, tea.Cmd) {
	key, isKey := message.(tea.KeyMsg)
	if !isKey {
		var command tea.Cmd
		m.input, command = m.input.Update(message)
		return m, command
	}
	buttons := workspaceFilteredButtons(m.overlay.Buttons, m.input.Value())
	switch key.String() {
	case "esc":
		m.overlay = nil
		return m, nil
	case "up", "shift+tab":
		if len(buttons) > 0 {
			m.overlay.Selected = (m.overlay.Selected - 1 + len(buttons)) % len(buttons)
		}
	case "down", "tab":
		if len(buttons) > 0 {
			m.overlay.Selected = (m.overlay.Selected + 1) % len(buttons)
		}
	case "enter":
		if len(buttons) == 0 {
			return m, nil
		}
		m.overlay.Selected = min(m.overlay.Selected, len(buttons)-1)
		action, value := m.overlay.Action, buttons[m.overlay.Selected].Value
		m.overlay = nil
		if err := m.applySettingsChoice(action, value); err != nil {
			m.err = err
		}
		return m, nil
	default:
		var command tea.Cmd
		m.input, command = m.input.Update(message)
		m.overlay.Selected = 0
		return m, command
	}
	return m, nil
}

func (m settingsModel) searchOverlayView(prefix []string, width int) string {
	lines := append([]string(nil), prefix...)
	lines = append(lines, m.input.View())
	buttons := workspaceFilteredButtons(m.overlay.Buttons, m.input.Value())
	if len(buttons) == 0 {
		lines = append(lines, workspaceDimStyle.Render("No matching interfaces"))
	} else {
		selected := min(m.overlay.Selected, len(buttons)-1)
		start, end := workspaceVisibleRange(len(buttons), selected, 8)
		if status := workspaceWindowStatus(start, end, len(buttons), width); status != "" {
			lines = append(lines, status)
		}
		for index := start; index < end; index++ {
			marker := "  "
			if index == selected {
				marker = "> "
			}
			line := fit(marker+buttons[index].Label, width)
			if index == selected {
				line = workspaceFocusStyle.Render(line)
			}
			lines = append(lines, line)
		}
	}
	lines = append(lines, workspaceHintLines(width, "type  Filter", "up/down  Select", "enter  Add", "esc  Cancel")...)
	return strings.Join(lines, "\n")
}

func workspaceFilteredButtons(buttons []workspaceButton, query string) []workspaceButton {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return buttons
	}
	filtered := make([]workspaceButton, 0, len(buttons))
	for _, button := range buttons {
		if strings.Contains(strings.ToLower(button.Label), query) || strings.Contains(strings.ToLower(button.Value), query) {
			filtered = append(filtered, button)
		}
	}
	return filtered
}

func discoverExternalInterfaceButtons(configured map[string]config.BabelExternalInterface) ([]workspaceButton, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list system interfaces: %w", err)
	}
	buttons := make([]workspaceButton, 0, len(interfaces))
	for _, iface := range interfaces {
		if _, exists := configured[iface.Name]; exists {
			continue
		}
		state := "down"
		if iface.Flags&net.FlagUp != 0 {
			state = "up"
		}
		buttons = append(buttons, workspaceButton{Label: fmt.Sprintf("%-15s  %s", iface.Name, state), Value: iface.Name})
	}
	sort.SliceStable(buttons, func(i, j int) bool { return buttons[i].Value < buttons[j].Value })
	return buttons, nil
}
