package app

import (
	"context"
	"errors"
	"fmt"
	"math"
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
	settings config.Settings
	mptcp    core.MptcpHealth
	err      error
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
	mptcp    core.MptcpHealth

	fieldSelected int
	ifaceSelected int
	ifaceAdding   bool
	ifaceName     string
	ifaceDraft    config.BabelExternalInterface

	width   int
	height  int
	loading bool
	busy    string
	err     error
	notice  string
	overlay *workspaceOverlay
	input   textinput.Model
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
			return settingsLoadMsg{err: healthErr}
		}
		return settingsLoadMsg{settings: settings, mptcp: health.Mptcp}
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
		m.err = message.err
		if message.err == nil {
			m.original = message.settings
			m.draft = message.settings
			m.mptcp = message.mptcp
		}
		return m, nil
	case settingsSaveMsg:
		m.busy = ""
		m.err = message.err
		if message.err != nil {
			return m, nil
		}
		m.original = m.draft
		m.notice = "Settings saved"
		m.fieldSelected = 0
		return m, m.load()
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
	fields := settingsFields(m.draft)
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
		}
	case "enter", " ":
		if err := m.activateSettingsField(fields[m.fieldSelected]); err != nil {
			m.err = err
		}
	case "s", "ctrl+s":
		changes := settingsChanges(m.original, m.draft)
		if len(changes) == 0 {
			m.notice = "No changes to save"
			return m, nil
		}
		m.beginConfirm("save-settings", "Save settings", fmt.Sprintf("Apply %d pending change(s)?", len(changes)), "Save changes", "Keep editing", false)
	}
	return m, nil
}

func (m settingsModel) updateInterfaceList(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	names := sortedInterfaceNames(m.draft.Babel.Interfaces)
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
		m.beginInput("add-interface-name", "Add external Babel interface", "External interfaces are created outside TH; TH only runs Babel on them.", workspaceInputStep{
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
}

func (m *settingsModel) activateSettingsField(field workspaceField) error {
	switch field.Kind {
	case workspaceFieldInput:
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
		m.ifaceDraft = config.BabelExternalInterface{}
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
	case "babel.balance":
		bias, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
		if err != nil || bias < -2 || bias > 2 {
			return errors.New("balance must be between -2 (latency) and +2 (bandwidth)")
		}
		babel.WeightBandwidthExponent, babel.WeightRTTExponent = balanceExponents(true, bias, babel.WeightBandwidthExponent, babel.WeightRTTExponent)
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
		m.draft = m.original
		m.notice = ""
		return nil, nil
	case "remove-interface":
		delete(m.draft.Babel.Interfaces, m.ifaceName)
		m.page = settingsInterfaces
		return nil, nil
	default:
		return nil, fmt.Errorf("unsupported settings action %q", action)
	}
}

// settingsFields lists every operator-editable setting as an editor field.
func settingsFields(settings config.Settings) []workspaceField {
	babel := settings.Babel
	delay := "On"
	delaySelected := 0
	if !babel.DelayMetricEnabled() {
		delay, delaySelected = "Off", 1
	}
	balance := balanceBias(babel.WeightBandwidthExponent, babel.WeightRTTExponent)
	balanceValue := fmt.Sprintf("bias %+.1f  α=%.2f β=%.2f", balance, babel.WeightBandwidthExponent, babel.WeightRTTExponent)

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

	return []workspaceField{
		workspaceTextField("babel.router_id", "Router ID (16 hex, empty = generated)", babel.RouterID, validateBabelRouterIDInput),
		workspaceChoiceField("babel.delay_metric", "Delay-based cost (RFC 9616)", delay, []workspaceButton{
			{Label: "On", Value: "On"}, {Label: "Off", Value: "Off"},
		}, delaySelected),
		workspaceTextField("babel.balance", "ECMP balance (latency ↔ bandwidth)", balanceValue, validateBalanceInput),
		workspaceTextField("babel.route_table", "Route table (0 = main)", strconv.Itoa(babel.RouteTable), validateInt(0, math.MaxInt32)),
		workspaceTextField("babel.unicast_hello_seconds", "Unicast Hello seconds (0 = default 4)", strconv.Itoa(babel.UnicastHelloSeconds), validateInt(0, 3600)),
		workspaceTextField("babel.max_paths", "Max ECMP paths (0 = default 4)", strconv.Itoa(babel.MultipathMaxPaths), validateInt(0, 8)),
		workspaceTextField("babel.slack", "Multipath cost slack", strconv.Itoa(babel.MultipathSlack), validateInt(0, 65534)),
		workspaceTextField("babel.k_penalty", "Bottleneck penalty K", strconv.FormatFloat(babel.WeightBottleneckPenalty, 'g', -1, 64), validateNonNegativeFloatInput),
		workspaceTextField("babel.advertise_sources", "Advertise source interfaces", strings.Join(babel.Advertise.SourceInterfaces, ","), validateInterfaceListInput),
		workspaceTextField("babel.advertise_prefixes", "Explicit advertised prefixes", formatPrefixList(babel.Advertise.AdvertisedPrefixes), validatePrefixListInput),
		workspaceTextField("babel.include", "Advertise include filter", formatPrefixList(babel.Advertise.Include), validatePrefixListInput),
		workspaceTextField("babel.exclude", "Advertise exclude filter", formatPrefixList(babel.Advertise.Exclude), validatePrefixListInput),
		workspaceField{ID: "babel.external_interfaces", Label: "External Babel interfaces", Value: externalInterfacesSummary(babel.Interfaces), Kind: workspaceFieldNavigate},
		workspaceToggleField("mptcp.enabled", "MPTCP endpoint management", settings.Mptcp.Enabled),
		workspaceChoiceField("mptcp.scheduler", "MPTCP scheduler (node-global)", scheduler, schedulerButtons, schedulerSelected),
	}
}

func externalInterfaceFields(name string, external config.BabelExternalInterface) []workspaceField {
	fields := []workspaceField{
		workspaceTextField("iface.bandwidth", "Bandwidth (Mbps, 0 = unlimited)", strconv.Itoa(external.BandwidthMbps), validateInt(0, 400000)),
		workspaceToggleField("iface.multicast", "Multicast", external.Multicast),
	}
	if !external.Multicast {
		fields = append(fields, workspaceTextField("iface.neighbours", "Unicast neighbours (comma separated)", formatNeighbourList(external.Neighbours), validateNeighbourListInput))
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
	if err != nil || bias < -2 || bias > 2 {
		return errors.New("balance must be between -2 (latency) and +2 (bandwidth)")
	}
	return nil
}

func settingsChanges(before, after config.Settings) []workspaceChange {
	type editableSettings struct {
		Babel config.BabelSettings `json:"babel,omitempty"`
		Mptcp config.MptcpSettings `json:"mptcp,omitempty"`
	}
	return workspaceStructuredChanges(
		editableSettings{Babel: before.Babel, Mptcp: before.Mptcp},
		editableSettings{Babel: after.Babel, Mptcp: after.Mptcp},
	)
}

func (m settingsModel) mptcpStatusLabel() string {
	label := m.mptcp.Status
	if !m.mptcp.Supported && m.mptcp.Message != "" {
		label += " (" + m.mptcp.Message + ")"
	}
	return label
}

func (m settingsModel) mainView(width int) string {
	fields := settingsFields(m.draft)
	changes := settingsChanges(m.original, m.draft)
	status := workspaceGoodStyle.Render("Saved")
	if len(changes) > 0 {
		status = workspaceWarnStyle.Bold(true).Render(fmt.Sprintf("Unsaved  %d change(s)", len(changes)))
	}
	lines := []string{
		workspaceDimStyle.Render(fit("TH / Settings", width)), "",
		workspaceAccentStyle.Render(fit("Daemon settings", width)), status, "",
	}
	section := ""
	start, end := workspaceVisibleRange(len(fields), m.fieldSelected, max(3, m.inlineHeight()-16))
	for index := start; index < end; index++ {
		field := fields[index]
		next := "babel"
		if strings.HasPrefix(field.ID, "mptcp.") {
			next = "mptcp"
		}
		if next != section {
			section = next
			if section == "mptcp" {
				lines = append(lines, "", workspaceAccentStyle.Render("MPTCP"))
				lines = append(lines, workspaceDimStyle.Render(fit("Kernel: "+m.mptcpStatusLabel(), width)))
				lines = append(lines, workspaceDimStyle.Render(fit(fmt.Sprintf("TH-managed endpoints: %d", m.mptcp.Endpoints), width)))
			}
		}
		lines = append(lines, renderWorkspaceField(field, index == m.fieldSelected, width))
	}
	lines = append(lines, "", workspaceDimStyle.Render(fit("MPTCP aggregation depends on subflow count; TH manages endpoints only.", width)))
	lines = append(lines, "")
	lines = append(lines, workspaceDiffLines(changes, width, 3)...)
	lines = append(lines, m.feedbackLines(width)...)
	if m.busy != "" {
		lines = append(lines, "", workspaceWarnStyle.Render(m.busy+"..."))
	}
	lines = append(lines, "")
	lines = append(lines, workspaceHintLines(width, "enter  Edit field", "s  Save settings", "esc  Back")...)
	return strings.Join(lines, "\n")
}

func (m settingsModel) interfacesView(width int) string {
	names := sortedInterfaceNames(m.draft.Babel.Interfaces)
	lines := []string{
		workspaceDimStyle.Render(fit("TH / Settings / Babel / External interfaces", width)), "",
		workspaceAccentStyle.Render("External Babel interfaces"), "",
	}
	if len(names) == 0 {
		lines = append(lines, "No external interfaces configured")
	} else {
		start, end := workspaceVisibleRange(len(names), m.ifaceSelected, max(3, m.inlineHeight()-10))
		for index := start; index < end; index++ {
			name := names[index]
			marker := "  "
			if index == m.ifaceSelected {
				marker = "> "
			}
			detail := externalInterfacesSummary(map[string]config.BabelExternalInterface{name: m.draft.Babel.Interfaces[name]})
			lines = append(lines, fit(marker+name+"  "+detail, width))
		}
		lines = append(lines, "")
	}
	lines = append(lines, m.feedbackLines(width)...)
	lines = append(lines, "")
	lines = append(lines, workspaceHintLines(width, "enter  Edit", "a  Add interface", "d  Remove", "esc  Back")...)
	return strings.Join(lines, "\n")
}

func (m settingsModel) interfaceEditorView(width int) string {
	fields := externalInterfaceFields(m.ifaceName, m.ifaceDraft)
	lines := []string{
		workspaceDimStyle.Render(fit("TH / Settings / Babel / "+m.ifaceName, width)), "",
		workspaceAccentStyle.Render(fit("External interface "+m.ifaceName, width)), "",
	}
	start, end := workspaceVisibleRange(len(fields), m.fieldSelected, max(3, m.inlineHeight()-8))
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
	lines := make([]string, 0, 3)
	if m.notice != "" {
		style := workspaceGoodStyle
		if strings.Contains(strings.ToLower(m.notice), "failed") || strings.Contains(strings.ToLower(m.notice), "error") {
			style = workspaceWarnStyle
		}
		lines = append(lines, "", style.Render(fit(m.notice, width)))
	}
	if m.err != nil {
		lines = append(lines, "", workspaceErrorStyle.Render(fit(m.err.Error(), width)))
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
	input.CursorEnd()
	m.input = input
}

func (m *settingsModel) resizeInput() {
	if m.overlay != nil && m.overlay.Kind == workspaceOverlayInput {
		m.input.Width = max(12, min(76, m.width-6))
	}
}

func (m settingsModel) updateOverlay(message tea.Msg) (tea.Model, tea.Cmd) {
	key, isKey := message.(tea.KeyMsg)
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
		lines = append(lines, workspaceDimStyle.Render(fit(m.overlay.Description, width)))
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
