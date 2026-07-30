package app

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/TunnelHelper/TH/internal/control"
	"github.com/TunnelHelper/TH/internal/model"
	"github.com/TunnelHelper/TH/internal/ui"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type workspacePage uint8

const (
	workspaceTunnels workspacePage = iota
	workspaceTunnel
	workspaceEdit
	workspacePeers
	workspacePeer
	workspaceSources
	workspaceSource
)

const workspaceMaxInlineHeight = 22

type workspaceOverlayKind uint8

const (
	workspaceOverlayInput workspaceOverlayKind = iota + 1
	workspaceOverlayChoice
	workspaceOverlayConfirm
)

type workspaceInputStep struct {
	Label     string
	Value     string
	Secret    bool
	Validator func(string) error
}

type workspaceButton struct {
	Label       string
	Value       string
	Destructive bool
}

type workspaceOverlay struct {
	Kind        workspaceOverlayKind
	Title       string
	Description string
	Action      string
	Steps       []workspaceInputStep
	Values      []string
	Step        int
	Buttons     []workspaceButton
	Selected    int
	Err         error
}

type manageWorkspaceModel struct {
	ctx       context.Context
	client    *control.Client
	timeout   time.Duration
	initialID string

	page     workspacePage
	views    []model.TunnelView
	selected int
	view     model.TunnelView
	original model.Tunnel
	draft    model.Tunnel

	fieldSelected  int
	peerSelected   int
	peerIndex      int
	peerAdding     bool
	peerOriginal   model.WireGuardPeer
	peerDraft      model.WireGuardPeer
	sourceSelected int
	sourceIndex    int
	sourceAdding   bool
	sourceOriginal model.SRv6Source
	sourceDraft    model.SRv6Source

	width        int
	height       int
	detailOffset int
	loading      bool
	busy         string
	err          error
	notice       string
	material     []string
	overlay      *workspaceOverlay
	input        textinput.Model
}

type workspaceListMsg struct {
	views []model.TunnelView
	err   error
}

type workspaceMutationMsg struct {
	op       string
	view     model.TunnelView
	err      error
	warning  string
	material []string
}

type workspaceDeleteMsg struct{ err error }

var (
	workspaceAccentStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("6")).Bold(true)
	workspaceGoodStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("2"))
	workspaceWarnStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("3"))
	workspaceErrorStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("1"))
	workspaceDimStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	workspaceFocusStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("0")).Background(lipgloss.Color("6")).Bold(true)
)

func runManageWorkspace(client *control.Client, timeout time.Duration, output *ui.UI, initialID string) error {
	if !output.TTY {
		return errors.New("tunnel management requires a terminal")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	workspace := newManageWorkspaceModel(ctx, client, timeout, initialID)
	program := tea.NewProgram(workspace,
		tea.WithInput(output.Input),
		tea.WithOutput(output.Out),
	)
	_, err := program.Run()
	return err
}

func newManageWorkspaceModel(ctx context.Context, client *control.Client, timeout time.Duration, initialID string) manageWorkspaceModel {
	return manageWorkspaceModel{
		ctx: ctx, client: client, timeout: timeout, initialID: initialID,
		page: workspaceTunnels, peerIndex: -1, sourceIndex: -1, loading: true,
	}
}

func (m manageWorkspaceModel) Init() tea.Cmd {
	return m.loadViews()
}

func (m manageWorkspaceModel) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	if size, ok := message.(tea.WindowSizeMsg); ok {
		m.width, m.height = size.Width, size.Height
		m.resizeInput()
		return m, nil
	}
	if key, ok := message.(tea.KeyMsg); ok && key.String() == "ctrl+c" {
		return m, tea.Quit
	}

	switch message := message.(type) {
	case workspaceListMsg:
		m.loading = false
		m.err = message.err
		if message.err == nil {
			m.views = message.views
			sortWorkspaceViews(m.views)
			m.clampTunnelSelection()
			if m.initialID != "" {
				for index := range m.views {
					if m.views[index].Tunnel.ID == m.initialID {
						m.selected = index
						m.openSelectedTunnel()
						break
					}
				}
				m.initialID = ""
			}
		}
		return m, nil
	case workspaceMutationMsg:
		m.busy = ""
		m.err = message.err
		if message.err != nil {
			return m, nil
		}
		m.view = message.view
		m.upsertView(message.view)
		m.notice = message.warning
		if message.warning == "" {
			m.notice = workspaceMutationNotice(message.op, message.view)
		}
		m.material = message.material
		if message.op == "save" {
			m.page = workspaceTunnel
			m.original = model.Tunnel{}
			m.draft = model.Tunnel{}
			m.fieldSelected = 0
		}
		return m, nil
	case workspaceDeleteMsg:
		m.busy = ""
		m.err = message.err
		if message.err == nil {
			m.removeView(m.view.Tunnel.ID)
			m.page = workspaceTunnels
			m.view = model.TunnelView{}
			m.notice = "Tunnel deleted"
			m.material = nil
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
	case workspaceTunnels:
		return m.updateTunnelList(key)
	case workspaceTunnel:
		return m.updateTunnelDetail(key)
	case workspaceEdit:
		return m.updateTunnelEditor(key)
	case workspacePeers:
		return m.updatePeerList(key)
	case workspacePeer:
		return m.updatePeerEditor(key)
	case workspaceSources:
		return m.updateSourceList(key)
	case workspaceSource:
		return m.updateSourceEditor(key)
	default:
		return m, nil
	}
}

func (m manageWorkspaceModel) updateTunnelList(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch key.String() {
	case "q", "esc":
		return m, tea.Quit
	case "up", "k":
		if m.selected > 0 {
			m.selected--
		}
	case "down", "j":
		if m.selected+1 < len(m.views) {
			m.selected++
		}
	case "enter":
		m.openSelectedTunnel()
	case "r":
		m.loading = true
		return m, m.loadViews()
	}
	return m, nil
}

func (m manageWorkspaceModel) updateTunnelDetail(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch key.String() {
	case "q", "esc":
		m.page = workspaceTunnels
		m.detailOffset = 0
		m.material = nil
	case "e":
		if err := m.beginTunnelEdit(); err != nil {
			m.err = err
		}
	case "r":
		m.busy = "Refreshing status"
		return m, m.observeTunnel()
	case "a":
		m.busy = "Reconciling tunnel"
		return m, m.reconcileTunnel()
	case " ", "t":
		m.busy = "Updating tunnel state"
		return m, m.toggleTunnel()
	case "d":
		target := m.view.Tunnel.Name
		if m.view.Tunnel.Interface != "" {
			target += " (" + m.view.Tunnel.Interface + ")"
		}
		m.beginConfirm("delete-tunnel", "Delete tunnel", "Delete "+target+" and remove its managed network state?", "Delete tunnel", "Cancel", true)
	case "up", "k":
		if m.detailOffset > 0 {
			m.detailOffset--
		}
	case "down", "j":
		m.detailOffset++
	case "pgup":
		m.detailOffset = max(0, m.detailOffset-5)
	case "pgdown":
		m.detailOffset += 5
	}
	return m, nil
}

func (m *manageWorkspaceModel) beginTunnelEdit() error {
	original, err := model.Clone(m.view.Tunnel)
	if err != nil {
		return err
	}
	draft, err := model.Clone(m.view.Tunnel)
	if err != nil {
		return err
	}
	m.original, m.draft = original, draft
	m.page = workspaceEdit
	m.fieldSelected = 0
	m.notice = ""
	m.material = nil
	return nil
}

func (m *manageWorkspaceModel) openSelectedTunnel() {
	if len(m.views) == 0 || m.selected < 0 || m.selected >= len(m.views) {
		return
	}
	m.view = m.views[m.selected]
	m.page = workspaceTunnel
	m.detailOffset = 0
	m.notice = ""
	m.material = nil
}

func (m manageWorkspaceModel) View() string {
	height := m.inlineHeight()
	width := m.inlineWidth()
	var base string
	switch m.page {
	case workspaceTunnels:
		base = m.tunnelListView(width)
	case workspaceTunnel:
		base = m.tunnelDetailView(width)
	case workspaceEdit:
		base = m.tunnelEditorView(width)
	case workspacePeers:
		base = m.peerListView(width)
	case workspacePeer:
		base = m.peerEditorView(width)
	case workspaceSources:
		base = m.sourceListView(width)
	case workspaceSource:
		base = m.sourceEditorView(width)
	}
	if m.overlay == nil {
		return fitWorkspaceHeight(base, height)
	}
	overlay := m.overlayView(width)
	overlayLines := strings.Count(overlay, "\n") + 1
	base = fitWorkspaceHeight(base, max(1, height-overlayLines-1))
	return fitWorkspaceHeight(base+"\n\n"+overlay, height)
}

func (m manageWorkspaceModel) tunnelListView(width int) string {
	lines := []string{m.breadcrumb(width), "", workspaceAccentStyle.Render("Managed tunnels")}
	if m.loading {
		lines = append(lines, "", workspaceDimStyle.Render("Loading tunnels..."))
	} else if len(m.views) == 0 {
		lines = append(lines, "", "No managed tunnels")
	} else {
		lines = append(lines, "", m.tunnelTableHeader(width))
		start, end := workspaceVisibleRange(len(m.views), m.selected, m.inlineHeight()-10)
		for index := start; index < end; index++ {
			lines = append(lines, m.tunnelTableRow(index, width))
		}
		if width >= 90 && m.selected < len(m.views) {
			selected := m.views[m.selected]
			lines = append(lines, "", workspaceDimStyle.Render(fit(workspaceTunnelSummary(selected), width)))
		}
	}
	lines = append(lines, m.feedbackLines(width)...)
	lines = append(lines, "")
	lines = append(lines, workspaceHintLines(width, "enter  Open", "r  Refresh", "esc  Back")...)
	return strings.Join(lines, "\n")
}

func (m manageWorkspaceModel) tunnelDetailView(width int) string {
	lines := []string{m.breadcrumb(width), ""}
	feedback := m.feedbackLines(width)
	hints := workspaceHintLines(width, "e  Edit", "space  Enable/disable", "r  Observe", "a  Reconcile", "d  Delete", "esc  Back")
	status := workspaceStatusLines(m.view, width)
	fixedLines := len(lines) + len(feedback) + len(hints) + 1
	if m.busy != "" {
		fixedLines += 2
	}
	budget := len(status)
	budget = m.inlineHeight() - fixedLines
	if budget < 4 {
		budget = 4
	}
	maxOffset := max(0, len(status)-budget)
	offset := min(m.detailOffset, maxOffset)
	end := min(len(status), offset+budget)
	if offset > 0 {
		lines = append(lines, workspaceDimStyle.Render(fmt.Sprintf("... %d lines above", offset)))
	}
	lines = append(lines, status[offset:end]...)
	if end < len(status) {
		lines = append(lines, workspaceDimStyle.Render(fmt.Sprintf("... %d lines below", len(status)-end)))
	}
	lines = append(lines, feedback...)
	if m.busy != "" {
		lines = append(lines, "", workspaceWarnStyle.Render(m.busy+"..."))
	}
	lines = append(lines, "")
	lines = append(lines, hints...)
	return strings.Join(lines, "\n")
}

func (m manageWorkspaceModel) breadcrumb(width int) string {
	parts := []string{"TH", "Manage"}
	if m.page != workspaceTunnels && m.view.Tunnel.Name != "" {
		parts = append(parts, m.view.Tunnel.Name)
	}
	switch m.page {
	case workspaceEdit:
		parts = append(parts, "Edit")
	case workspacePeers:
		parts = append(parts, "Edit", "Peers")
	case workspacePeer:
		parts = append(parts, "Edit", "Peers", workspacePeerCrumb(m.peerDraft, m.peerAdding))
	case workspaceSources:
		parts = append(parts, "Edit", "Sources")
	case workspaceSource:
		parts = append(parts, "Edit", "Sources", workspaceSourceCrumb(m.sourceDraft, m.sourceAdding))
	}
	return workspaceDimStyle.Render(fit(strings.Join(parts, " / "), width))
}

func (m manageWorkspaceModel) feedbackLines(width int) []string {
	lines := make([]string, 0, 5)
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
	if len(m.material) > 0 {
		lines = append(lines, "", workspaceWarnStyle.Bold(true).Render("New pairing material"))
		for _, line := range m.material {
			lines = append(lines, fit(line, width))
		}
	}
	return lines
}

func (m manageWorkspaceModel) tunnelTableHeader(width int) string {
	nameWidth := workspaceNameWidth(width)
	if width < 82 {
		return fit(fmt.Sprintf("  %-*s %-12s %-10s", nameWidth, "NAME", "KIND", "STATE"), width)
	}
	return fit(fmt.Sprintf("  %-*s %-12s %-10s %-15s %-10s", nameWidth, "NAME", "KIND", "STATE", "INTERFACE", "GENERATION"), width)
}

func (m manageWorkspaceModel) tunnelTableRow(index, width int) string {
	view := m.views[index]
	marker := " "
	if index == m.selected {
		marker = ">"
	}
	state := string(view.Status.Phase)
	if !view.Tunnel.Enabled {
		state = "disabled"
	}
	nameWidth := workspaceNameWidth(width)
	var row string
	if width < 82 {
		row = fmt.Sprintf("%s %-*s %-12s %-10s", marker, nameWidth, fit(view.Tunnel.Name, nameWidth), fit(string(view.Tunnel.Kind), 12), fit(state, 10))
	} else {
		generation := fmt.Sprintf("%d/%d", view.Tunnel.Generation, view.Status.ObservedGeneration)
		row = fmt.Sprintf("%s %-*s %-12s %-10s %-15s %-10s", marker, nameWidth, fit(view.Tunnel.Name, nameWidth), fit(string(view.Tunnel.Kind), 12), fit(state, 10), fit(view.Tunnel.Interface, 15), fit(generation, 10))
	}
	style := workspaceGoodStyle
	if view.Status.Phase == model.PhaseError {
		style = workspaceErrorStyle
	} else if view.Status.Phase == model.PhasePending {
		style = workspaceWarnStyle
	} else if !view.Tunnel.Enabled {
		style = workspaceDimStyle
	}
	if index == m.selected {
		style = workspaceFocusStyle
	}
	return style.Render(fit(row, width))
}

func workspaceStatusLines(view model.TunnelView, width int) []string {
	state := string(view.Status.Phase)
	if !view.Tunnel.Enabled {
		state = "disabled"
	}
	lines := []string{
		workspaceAccentStyle.Render(fit(view.Tunnel.Name+"  "+string(view.Tunnel.Kind), width)),
		fmt.Sprintf("State             %s", state),
		fmt.Sprintf("Interface         %s", optionalWorkspaceValue(view.Tunnel.Interface)),
		fmt.Sprintf("Generation        %d / observed %d", view.Tunnel.Generation, view.Status.ObservedGeneration),
	}
	if value := view.Status.Details["ipv6_link_local"]; value != "" {
		lines = append(lines, "IPv6 link-local   "+value)
	}
	if _, ok := view.Status.Details["link_receive_bytes"]; ok {
		lines = append(lines, fmt.Sprintf("Interface traffic rx %s  tx %s", detailBytes(view, "link_receive_bytes"), detailBytes(view, "link_transmit_bytes")))
	}
	if source := view.Status.Details["counter_source"]; source == "wireguard" || source == "amneziawg" {
		lines = append(lines, fmt.Sprintf("Peer traffic      rx %s  tx %s", detailBytes(view, "receive_bytes"), detailBytes(view, "transmit_bytes")))
	}
	if value := view.Status.Details["latest_handshake"]; value != "" {
		if stamp, err := time.Parse(time.RFC3339, value); err == nil {
			lines = append(lines, "Latest handshake  "+formatHandshakeTime(stamp))
		}
	}
	detailKeys := make([]string, 0, len(view.Status.Details))
	for key := range view.Status.Details {
		switch key {
		case "ipv6_link_local", "link_receive_bytes", "link_transmit_bytes", "receive_bytes", "transmit_bytes", "counter_source", "latest_handshake":
			continue
		}
		detailKeys = append(detailKeys, key)
	}
	sort.Strings(detailKeys)
	for _, key := range detailKeys {
		lines = append(lines, fmt.Sprintf("%-17s %s", statusDetailLabel(key), view.Status.Details[key]))
	}
	for _, condition := range view.Status.Conditions {
		if condition.Message != "" {
			lines = append(lines, workspaceWarnStyle.Render(fit(condition.Message, width)))
		}
	}
	if len(view.Status.Peers) > 0 {
		lines = append(lines, "", workspaceAccentStyle.Render("Peers"))
	}
	for _, peer := range view.Status.Peers {
		handshake := "never"
		if peer.LastHandshakeTime != nil {
			handshake = formatHandshakeTime(*peer.LastHandshakeTime)
		}
		endpoint := optionalWorkspaceValue(peer.Endpoint)
		lines = append(lines,
			fit(fmt.Sprintf("%s  %s", fit(peer.PublicKey, 18), endpoint), width),
			fit(fmt.Sprintf("  handshake %s  rx %s  tx %s", handshake, formatBytes(peer.ReceiveBytes), formatBytes(peer.TransmitBytes)), width),
		)
	}
	for index := range lines {
		lines[index] = fit(lines[index], width)
	}
	return lines
}

func (m manageWorkspaceModel) loadViews() tea.Cmd {
	return func() tea.Msg {
		if m.client == nil {
			return workspaceListMsg{}
		}
		ctx, cancel := context.WithTimeout(m.ctx, m.timeout)
		defer cancel()
		views, err := m.client.List(ctx)
		return workspaceListMsg{views: views, err: err}
	}
}

func (m manageWorkspaceModel) observeTunnel() tea.Cmd {
	id := m.view.Tunnel.ID
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(m.ctx, m.timeout)
		defer cancel()
		view, err := m.client.Observe(ctx, id)
		return workspaceMutationMsg{op: "observe", view: view, err: err}
	}
}

func (m manageWorkspaceModel) reconcileTunnel() tea.Cmd {
	id := m.view.Tunnel.ID
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(m.ctx, m.timeout)
		defer cancel()
		view, err := m.client.Reconcile(ctx, id)
		return workspaceMutationMsg{op: "reconcile", view: view, err: err}
	}
}

func (m manageWorkspaceModel) toggleTunnel() tea.Cmd {
	current := m.view
	enabled := !current.Tunnel.Enabled
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(m.ctx, m.timeout)
		view, err := m.client.SetEnabled(ctx, current, enabled)
		cancel()
		if err != nil {
			return workspaceMutationMsg{op: "toggle", err: err}
		}
		ctx, cancel = context.WithTimeout(m.ctx, m.timeout)
		reconciled, reconcileErr := m.client.Reconcile(ctx, view.Tunnel.ID)
		cancel()
		if reconcileErr != nil {
			return workspaceMutationMsg{op: "toggle", view: view, warning: fmt.Sprintf("State was saved, but applying it failed: %v", reconcileErr)}
		}
		return workspaceMutationMsg{op: "toggle", view: reconciled}
	}
}

func (m manageWorkspaceModel) saveTunnel() tea.Cmd {
	current, currentErr := model.Clone(m.original)
	next, nextErr := model.Clone(m.draft)
	return func() tea.Msg {
		if currentErr != nil {
			return workspaceMutationMsg{op: "save", err: currentErr}
		}
		if nextErr != nil {
			return workspaceMutationMsg{op: "save", err: nextErr}
		}
		generatedReplacement := replacementSecretsRequired(current, next)
		if generatedReplacement {
			if err := model.PrepareUpdateWithGeneratedSecrets(&next, &current, time.Now()); err != nil {
				return workspaceMutationMsg{op: "save", err: err}
			}
			next.Generation = current.Generation
		}
		material := workspacePairingMaterial(next, generatedReplacement)
		ctx, cancel := context.WithTimeout(m.ctx, m.timeout)
		view, err := m.client.Update(ctx, model.TunnelView{Tunnel: next})
		cancel()
		if err != nil {
			return workspaceMutationMsg{op: "save", err: err}
		}
		ctx, cancel = context.WithTimeout(m.ctx, m.timeout)
		reconciled, reconcileErr := m.client.Reconcile(ctx, view.Tunnel.ID)
		cancel()
		if reconcileErr != nil {
			return workspaceMutationMsg{op: "save", view: view, warning: fmt.Sprintf("Changes were saved, but applying them failed: %v", reconcileErr), material: material}
		}
		return workspaceMutationMsg{op: "save", view: reconciled, material: material}
	}
}

func (m manageWorkspaceModel) deleteTunnel() tea.Cmd {
	view := m.view
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(m.ctx, m.timeout)
		defer cancel()
		return workspaceDeleteMsg{err: m.client.Delete(ctx, view)}
	}
}

func workspaceMutationNotice(operation string, view model.TunnelView) string {
	switch operation {
	case "observe":
		return "Status refreshed"
	case "reconcile":
		return fmt.Sprintf("Reconciled %s: %s", view.Tunnel.Name, view.Status.Phase)
	case "toggle":
		if view.Tunnel.Enabled {
			return fmt.Sprintf("Enabled %s: %s", view.Tunnel.Name, view.Status.Phase)
		}
		return "Disabled " + view.Tunnel.Name
	case "save":
		return fmt.Sprintf("Saved %s: %s", view.Tunnel.Name, view.Status.Phase)
	default:
		return "Updated"
	}
}

func (m *manageWorkspaceModel) upsertView(view model.TunnelView) {
	for index := range m.views {
		if m.views[index].Tunnel.ID == view.Tunnel.ID {
			m.views[index] = view
			sortWorkspaceViews(m.views)
			for position := range m.views {
				if m.views[position].Tunnel.ID == view.Tunnel.ID {
					m.selected = position
					break
				}
			}
			return
		}
	}
	m.views = append(m.views, view)
	sortWorkspaceViews(m.views)
	m.clampTunnelSelection()
}

func (m *manageWorkspaceModel) removeView(id string) {
	for index := range m.views {
		if m.views[index].Tunnel.ID == id {
			m.views = append(m.views[:index], m.views[index+1:]...)
			break
		}
	}
	m.clampTunnelSelection()
}

func (m *manageWorkspaceModel) clampTunnelSelection() {
	if len(m.views) == 0 {
		m.selected = 0
	} else if m.selected >= len(m.views) {
		m.selected = len(m.views) - 1
	}
}

func sortWorkspaceViews(views []model.TunnelView) {
	sort.SliceStable(views, func(i, j int) bool { return views[i].Tunnel.Name < views[j].Tunnel.Name })
}

func workspaceVisibleRange(length, selected, available int) (int, int) {
	if length <= 0 {
		return 0, 0
	}
	if available < 1 || available > length {
		available = length
	}
	start := 0
	if selected >= available {
		start = selected - available + 1
	}
	return start, min(length, start+available)
}

func (m manageWorkspaceModel) inlineHeight() int {
	if m.height <= 0 {
		return workspaceMaxInlineHeight
	}
	return min(m.height, workspaceMaxInlineHeight)
}

func (m manageWorkspaceModel) inlineWidth() int {
	if m.width <= 0 {
		return 80
	}
	return max(20, m.width)
}

func workspaceNameWidth(width int) int {
	if width < 82 {
		return max(8, width-29)
	}
	return max(8, min(28, width-58))
}

func workspaceTunnelSummary(view model.TunnelView) string {
	parts := []string{view.Tunnel.ID}
	if value := view.Status.Details["ipv6_link_local"]; value != "" {
		parts = append(parts, "IPv6 LLA "+value)
	}
	if value := view.Status.Details["latest_handshake"]; value != "" {
		if stamp, err := time.Parse(time.RFC3339, value); err == nil {
			parts = append(parts, "handshake "+formatHandshakeTime(stamp))
		}
	}
	return strings.Join(parts, "  ")
}

func optionalWorkspaceValue(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}

func fitWorkspaceHeight(value string, height int) string {
	if height <= 0 {
		return value
	}
	lines := strings.Split(value, "\n")
	if len(lines) <= height {
		return value
	}
	if height == 1 {
		return lines[0]
	}
	if height <= 3 {
		return strings.Join(append(lines[:height-1], workspaceDimStyle.Render("...")), "\n")
	}
	tail := min(10, height-2)
	head := height - tail - 1
	visible := append([]string(nil), lines[:head]...)
	visible = append(visible, workspaceDimStyle.Render("..."))
	visible = append(visible, lines[len(lines)-tail:]...)
	return strings.Join(visible, "\n")
}

func workspaceHintLines(width int, hints ...string) []string {
	if width <= 0 || len(hints) == 0 {
		return nil
	}
	const separator = "    "
	lines := make([]string, 0, 2)
	current := ""
	for _, hint := range hints {
		candidate := hint
		if current != "" {
			candidate = current + separator + hint
		}
		if current != "" && lipgloss.Width(candidate) > width {
			lines = append(lines, workspaceDimStyle.Render(fit(current, width)))
			current = hint
		} else {
			current = candidate
		}
	}
	if current != "" {
		lines = append(lines, workspaceDimStyle.Render(fit(current, width)))
	}
	return lines
}
