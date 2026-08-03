package app

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/TunnelHelper/TH/internal/control"
	"github.com/TunnelHelper/TH/internal/core"
	"github.com/TunnelHelper/TH/internal/model"
	"github.com/TunnelHelper/TH/internal/ui"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	ansi "github.com/charmbracelet/x/ansi"
)

type dashboardModel struct {
	ctx          context.Context
	client       *control.Client
	timeout      time.Duration
	events       <-chan core.Event
	streamErrors <-chan error
	views        []model.TunnelView
	selected     int
	detailsFocus bool
	peerOffset   int
	width        int
	height       int
	loading      bool
	refreshing   bool
	lastSequence uint64
	openID       string
	err          error
}

type dashboardViewsMsg struct {
	views []model.TunnelView
	err   error
}

type dashboardEventMsg struct{ event core.Event }
type dashboardStreamErrorMsg struct{ err error }
type dashboardTickMsg struct{}
type dashboardReconnectTickMsg struct{}
type dashboardReconnectMsg struct {
	events       <-chan core.Event
	streamErrors <-chan error
	err          error
}

const dashboardMaxInlineHeight = 20

func runDashboard(client *control.Client, timeout time.Duration, output *ui.UI) (string, error) {
	if !output.TTY {
		return "", errors.New("live status requires a terminal")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events, streamErrors, err := client.WatchEvents(ctx, 0)
	if err != nil {
		return "", err
	}
	model := dashboardModel{
		ctx: ctx, client: client, timeout: timeout,
		events: events, streamErrors: streamErrors, loading: true,
	}
	program := tea.NewProgram(model,
		tea.WithInput(output.Input),
		tea.WithOutput(output.Out),
	)
	final, err := program.Run()
	if err != nil {
		return "", err
	}
	result, ok := final.(dashboardModel)
	if !ok {
		return "", errors.New("unexpected dashboard state")
	}
	return result.openID, nil
}

func (m dashboardModel) Init() tea.Cmd {
	return tea.Batch(m.loadViews(), waitDashboardEvent(m.events, m.streamErrors), dashboardTick())
}

func (m dashboardModel) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	switch message := message.(type) {
	case tea.KeyMsg:
		if m.detailsFocus {
			m.peerOffset = min(m.peerOffset, m.peerMaxOffset())
			maxOffset := m.peerMaxOffset()
			switch message.String() {
			case "q", "ctrl+c":
				return m, tea.Quit
			case "esc", "tab", "shift+tab":
				m.detailsFocus = false
			case "up", "k":
				m.peerOffset = max(0, m.peerOffset-1)
			case "down", "j":
				m.peerOffset = min(maxOffset, m.peerOffset+1)
			case "pgup":
				m.peerOffset = max(0, m.peerOffset-dashboardPeerViewportRows)
			case "pgdown":
				m.peerOffset = min(maxOffset, m.peerOffset+dashboardPeerViewportRows)
			}
			return m, nil
		}
		switch message.String() {
		case "q", "esc", "ctrl+c":
			return m, tea.Quit
		case "up", "k":
			if m.selected > 0 {
				m.selected--
				m.peerOffset = 0
			}
		case "down", "j":
			if m.selected+1 < len(m.views) {
				m.selected++
				m.peerOffset = 0
			}
		case "r":
			m.refreshing = true
			return m, m.loadViews()
		case "enter":
			if id := m.selectedTunnelID(); id != "" {
				m.openID = id
				return m, tea.Quit
			}
		case "tab":
			if len(m.peerLines(max(20, m.width))) > 1 {
				m.detailsFocus = true
				m.peerOffset = 0
			}
		}
	case tea.WindowSizeMsg:
		m.width, m.height = message.Width, message.Height
	case dashboardViewsMsg:
		m.loading = false
		m.refreshing = false
		m.err = message.err
		if message.err == nil {
			selectedID := m.selectedTunnelID()
			m.views = message.views
			sortDashboardViews(m.views)
			m.restoreSelection(selectedID)
			m.peerOffset = min(m.peerOffset, m.peerMaxOffset())
		}
	case dashboardEventMsg:
		m.err = nil
		event := message.event
		if event.Sequence > m.lastSequence {
			m.lastSequence = event.Sequence
		}
		switch event.Type {
		case core.EventStatus:
			if !m.applyStatusEvent(event) {
				return m, tea.Batch(m.listViews(), waitDashboardEvent(m.events, m.streamErrors))
			}
		case core.EventDeleted:
			m.remove(event.TunnelID)
		case core.EventConnected:
			if event.Message != "" {
				return m, tea.Batch(m.listViews(), waitDashboardEvent(m.events, m.streamErrors))
			}
		}
		return m, waitDashboardEvent(m.events, m.streamErrors)
	case dashboardStreamErrorMsg:
		m.err = message.err
		return m, tea.Tick(time.Second, func(time.Time) tea.Msg { return dashboardReconnectTickMsg{} })
	case dashboardReconnectTickMsg:
		return m, m.reconnect()
	case dashboardReconnectMsg:
		if message.err != nil {
			m.err = message.err
			return m, tea.Tick(time.Second, func(time.Time) tea.Msg { return dashboardReconnectTickMsg{} })
		}
		m.events, m.streamErrors = message.events, message.streamErrors
		m.err = nil
		return m, waitDashboardEvent(m.events, m.streamErrors)
	case dashboardTickMsg:
		return m, tea.Batch(m.loadViews(), dashboardTick())
	}
	return m, nil
}

func (m dashboardModel) View() string {
	height := m.inlineHeight()
	width := m.width
	if width <= 0 {
		width = 80
	} else {
		width = max(20, width)
	}
	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("6")).Render("TH live status")
	lines := []string{title, ""}
	if len(m.views) == 0 {
		if m.loading {
			lines = append(lines, "Loading tunnels...")
		} else {
			lines = append(lines, "No managed tunnels")
		}
	} else {
		lines = append(lines, m.tableHeader(width))
		start, end := 0, len(m.views)
		for index := start; index < end; index++ {
			lines = append(lines, m.tableRow(index, width))
		}
		lines = append(lines, "")
		lines = append(lines, m.peerViewportLines(width)...)
	}
	feedback := ""
	feedbackStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	if m.refreshing {
		feedback = "Refreshing status..."
		feedbackStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("3"))
	}
	if m.err != nil {
		feedback = m.err.Error()
		feedbackStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("1"))
	}
	lines = append(lines, "", feedbackStyle.Render(fit(feedback, width)))
	hintStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	if m.detailsFocus {
		lines = append(lines, "", hintStyle.Render(fit("up/down: scroll details   pgup/pgdown: page", width)), hintStyle.Render("tab/esc: tunnel table   q: back"))
	} else {
		lines = append(lines, "",
			hintStyle.Render(fit("up/down or j/k: select", width)),
			hintStyle.Render(fit("enter: manage   tab: details", width)),
			hintStyle.Render(fit("r: refresh   q/esc: back", width)),
		)
	}
	return fitWorkspaceHeight(strings.Join(lines, "\n"), height)
}

const dashboardPeerViewportRows = 8

func (m dashboardModel) peerViewportLines(width int) []string {
	all := m.peerLines(width)
	if len(all) == 0 {
		return all
	}
	header, content := all[0], all[1:]
	start, end := workspaceScrollRange(len(content), m.peerOffset, dashboardPeerViewportRows)
	lines := []string{header}
	marker := workspaceWindowStatus(start, end, len(content), width)
	if marker != "" {
		if m.detailsFocus {
			marker = workspaceFocusStyle.Render(marker)
		}
	}
	lines = append(lines, marker)
	lines = append(lines, content[start:end]...)
	for rendered := end - start; rendered < dashboardPeerViewportRows; rendered++ {
		lines = append(lines, "")
	}
	return lines
}

func (m dashboardModel) peerMaxOffset() int {
	contentRows := max(0, len(m.peerLines(max(20, m.width)))-1)
	return max(0, contentRows-dashboardPeerViewportRows)
}

func (m dashboardModel) loadViews() tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(m.ctx, m.timeout)
		defer cancel()
		views, err := m.client.List(ctx)
		return dashboardViewsMsg{views: views, err: err}
	}
}

func (m dashboardModel) listViews() tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(m.ctx, m.timeout)
		defer cancel()
		views, err := m.client.List(ctx)
		return dashboardViewsMsg{views: views, err: err}
	}
}

func (m dashboardModel) reconnect() tea.Cmd {
	return func() tea.Msg {
		events, streamErrors, err := m.client.WatchEvents(m.ctx, m.lastSequence)
		return dashboardReconnectMsg{events: events, streamErrors: streamErrors, err: err}
	}
}

func waitDashboardEvent(events <-chan core.Event, streamErrors <-chan error) tea.Cmd {
	return func() tea.Msg {
		select {
		case event, ok := <-events:
			if !ok {
				return dashboardStreamErrorMsg{err: errors.New("daemon event stream closed")}
			}
			return dashboardEventMsg{event: event}
		case err, ok := <-streamErrors:
			if !ok || err == nil {
				return dashboardStreamErrorMsg{err: errors.New("daemon event stream closed")}
			}
			return dashboardStreamErrorMsg{err: err}
		}
	}
}

func dashboardTick() tea.Cmd {
	return tea.Tick(30*time.Second, func(time.Time) tea.Msg { return dashboardTickMsg{} })
}

func (m *dashboardModel) upsert(view model.TunnelView) {
	selectedID := m.selectedTunnelID()
	for index := range m.views {
		if m.views[index].Tunnel.ID == view.Tunnel.ID {
			m.views[index] = view
			sortDashboardViews(m.views)
			m.restoreSelection(selectedID)
			return
		}
	}
	m.views = append(m.views, view)
	sortDashboardViews(m.views)
	m.restoreSelection(selectedID)
}

func (m *dashboardModel) applyStatusEvent(event core.Event) bool {
	if event.Status == nil {
		return false
	}
	for index := range m.views {
		if m.views[index].Tunnel.ID != event.TunnelID {
			continue
		}
		selectedID := m.selectedTunnelID()
		m.views[index].Tunnel.Name = event.TunnelName
		m.views[index].Tunnel.Kind = event.TunnelKind
		m.views[index].Tunnel.Enabled = event.Enabled
		m.views[index].Tunnel.Generation = event.Generation
		m.views[index].Status = *event.Status
		sortDashboardViews(m.views)
		m.restoreSelection(selectedID)
		return true
	}
	return false
}

func (m *dashboardModel) remove(id string) {
	selectedID := m.selectedTunnelID()
	for index := range m.views {
		if m.views[index].Tunnel.ID == id {
			m.views = append(m.views[:index], m.views[index+1:]...)
			break
		}
	}
	if selectedID == id {
		m.clampSelection()
	} else {
		m.restoreSelection(selectedID)
	}
}

func (m dashboardModel) selectedTunnelID() string {
	if m.selected < 0 || m.selected >= len(m.views) {
		return ""
	}
	return m.views[m.selected].Tunnel.ID
}

func (m *dashboardModel) restoreSelection(id string) {
	if id != "" {
		for index := range m.views {
			if m.views[index].Tunnel.ID == id {
				m.selected = index
				return
			}
		}
	}
	m.clampSelection()
}

func (m *dashboardModel) clampSelection() {
	if len(m.views) == 0 {
		m.selected = 0
	} else if m.selected >= len(m.views) {
		m.selected = len(m.views) - 1
	}
}

func sortDashboardViews(views []model.TunnelView) {
	sort.SliceStable(views, func(i, j int) bool {
		return views[i].Tunnel.Name < views[j].Tunnel.Name
	})
}

func (m dashboardModel) visibleRange() (int, int) {
	// Height limiting is intentionally disabled: the whole tunnel table is
	// always rendered and the terminal scrolls.
	return 0, len(m.views)
}

func (m dashboardModel) inlineHeight() int {
	if m.height <= 0 {
		return dashboardMaxInlineHeight
	}
	return m.height
}

func (m dashboardModel) tableHeader(width int) string {
	nameWidth := dashboardNameWidth(width)
	if width < 78 {
		return fit(fmt.Sprintf("  %-*s %-12s %-9s", nameWidth, "NAME", "KIND", "STATE"), width)
	}
	return fit(fmt.Sprintf("  %-*s %-12s %-9s %-10s %10s %10s", nameWidth, "NAME", "KIND", "STATE", "HANDSHAKE", "RX", "TX"), width)
}

func (m dashboardModel) tableRow(index, width int) string {
	view := m.views[index]
	marker := " "
	if index == m.selected {
		marker = ">"
	}
	nameWidth := dashboardNameWidth(width)
	state := string(view.Status.Phase)
	if !view.Tunnel.Enabled {
		state = "disabled"
	}
	var row string
	if width < 78 {
		row = fmt.Sprintf("%s %-*s %-12s %-9s", marker, nameWidth, fit(view.Tunnel.Name, nameWidth), fit(string(view.Tunnel.Kind), 12), fit(state, 9))
	} else {
		row = fmt.Sprintf("%s %-*s %-12s %-9s %-10s %10s %10s",
			marker, nameWidth, fit(view.Tunnel.Name, nameWidth), fit(string(view.Tunnel.Kind), 12), fit(state, 9),
			fit(handshakeAge(view), 10), fitRight(detailBytes(view, "receive_bytes"), 10), fitRight(detailBytes(view, "transmit_bytes"), 10))
	}
	color := lipgloss.Color("2")
	switch view.Status.Phase {
	case model.PhaseError:
		color = lipgloss.Color("1")
	case model.PhasePending:
		color = lipgloss.Color("3")
	case model.PhaseDisabled:
		color = lipgloss.Color("8")
	}
	return lipgloss.NewStyle().Foreground(color).Render(fit(row, width))
}

func (m dashboardModel) peerLines(width int) []string {
	return m.peerLinesWithin(width, -1)
}

func (m dashboardModel) peerLinesWithin(width, maxLines int) []string {
	if len(m.views) == 0 || m.selected >= len(m.views) {
		return nil
	}
	view := m.views[m.selected]
	lines := []string{lipgloss.NewStyle().Bold(true).Render(fit(view.Tunnel.Name, width))}
	if linkLocal := view.Status.Details["ipv6_link_local"]; linkLocal != "" {
		lines = append(lines, fit("IPv6 LLA: "+linkLocal, width))
	}
	if view.Tunnel.Kind == model.KindWireGuard || view.Tunnel.Kind == model.KindAmneziaWG {
		if _, ok := view.Status.Details["link_receive_bytes"]; ok {
			lines = append(lines, fit(fmt.Sprintf("Interface link: rx %s  tx %s",
				detailBytes(view, "link_receive_bytes"), detailBytes(view, "link_transmit_bytes")), width))
		} else {
			lines = append(lines, "Interface link: unavailable")
		}
	}
	if len(view.Status.Peers) == 0 {
		if message := statusMessage(view); message != "" {
			lines = append(lines, fit(message, width))
		}
		return lines
	}
	for _, peer := range view.Status.Peers {
		key := peer.PublicKey
		if peer.Protocol == "babel" {
			key = formatBabelAddress(key)
		}
		if len(key) > 12 {
			key = key[:12]
		}
		endpoint := peer.Endpoint
		if endpoint == "" {
			endpoint = "-"
		}
		if peer.Protocol == "babel" {
			lines = append(lines, fit(fmt.Sprintf("Babel neighbor %s  %s", key, endpoint), width))
			state := "warming"
			if peer.MetricFresh != nil {
				if *peer.MetricFresh {
					state = "fresh"
				} else {
					state = "stale"
				}
			}
			rtt, jitter, age, confidence := time.Duration(0), time.Duration(0), int64(0), 0.0
			if peer.RTTMicros != nil {
				rtt = time.Duration(*peer.RTTMicros) * time.Microsecond
			}
			if peer.JitterMicros != nil {
				jitter = time.Duration(*peer.JitterMicros) * time.Microsecond
			}
			if peer.MetricAgeMillis != nil {
				age = *peer.MetricAgeMillis
			}
			if peer.MetricConfidence != nil {
				confidence = *peer.MetricConfidence * 100
			}
			lines = append(lines, fit(fmt.Sprintf("  RTT %s  jitter %s  age %dms  %.0f%% %s",
				rtt.Round(time.Microsecond), jitter.Round(time.Microsecond), age, confidence, state), width))
			continue
		}
		lines = append(lines, fit(fmt.Sprintf("Peer %s  %s", key, endpoint), width))
		handshake := "never"
		if peer.LastHandshakeTime != nil {
			handshake = formatHandshakeTime(*peer.LastHandshakeTime)
		}
		transferLabel := "WG transfer"
		if view.Tunnel.Kind == model.KindAmneziaWG {
			transferLabel = "AWG transfer"
		}
		lines = append(lines,
			fit("  Handshake: "+handshake, width),
			fit(fmt.Sprintf("  %s: rx %s  tx %s", transferLabel, formatBytes(peer.ReceiveBytes), formatBytes(peer.TransmitBytes)), width),
		)
	}
	return lines
}

func dashboardNameWidth(width int) int {
	if width < 78 {
		return max(8, width-27)
	}
	return max(8, min(28, width-62))
}

func detailBytes(view model.TunnelView, key string) string {
	value, _ := strconv.ParseUint(view.Status.Details[key], 10, 64)
	return formatByteCount(value)
}

func handshakeAge(view model.TunnelView) string {
	value := view.Status.Details["latest_handshake"]
	if value == "" {
		return "never"
	}
	stamp, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return "unknown"
	}
	return formatDuration(time.Since(stamp))
}

func formatDuration(value time.Duration) string {
	if value < 0 {
		value = 0
	}
	if value < time.Minute {
		return fmt.Sprintf("%ds", int(value.Seconds()))
	}
	if value < time.Hour {
		return fmt.Sprintf("%dm", int(value.Minutes()))
	}
	if value < 24*time.Hour {
		return fmt.Sprintf("%dh", int(value.Hours()))
	}
	return fmt.Sprintf("%dd", int(value.Hours()/24))
}

func formatHandshakeTime(value time.Time) string {
	return fmt.Sprintf("%s (%s ago)", value.UTC().Format(time.RFC3339), formatDuration(time.Since(value)))
}

func formatBytes(value int64) string {
	if value < 0 {
		value = 0
	}
	return formatByteCount(uint64(value))
}

func formatByteCount(value uint64) string {
	if value < 1024 {
		return fmt.Sprintf("%d B", value)
	}
	units := []string{"KiB", "MiB", "GiB", "TiB"}
	number := float64(value)
	unit := "B"
	for _, next := range units {
		number /= 1024
		unit = next
		if number < 1024 {
			break
		}
	}
	return fmt.Sprintf("%.1f %s", number, unit)
}

func statusMessage(view model.TunnelView) string {
	for _, condition := range view.Status.Conditions {
		if condition.Message != "" {
			return condition.Message
		}
	}
	return ""
}

func fit(value string, width int) string {
	if width <= 0 {
		return ""
	}
	if ansi.StringWidth(value) <= width {
		return value
	}
	if width <= 3 {
		return ansi.Truncate(value, width, "")
	}
	return ansi.Truncate(value, width, "...")
}

func fitRight(value string, width int) string {
	value = fit(value, width)
	return strings.Repeat(" ", max(0, width-ansi.StringWidth(value))) + value
}
