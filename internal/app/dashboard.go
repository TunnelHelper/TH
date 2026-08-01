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
	width        int
	height       int
	lastSequence uint64
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

func runDashboard(client *control.Client, timeout time.Duration, output *ui.UI) error {
	if !output.TTY {
		return errors.New("live status requires a terminal")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events, streamErrors, err := client.WatchEvents(ctx, 0)
	if err != nil {
		return err
	}
	model := dashboardModel{
		ctx: ctx, client: client, timeout: timeout,
		events: events, streamErrors: streamErrors,
	}
	program := tea.NewProgram(model,
		tea.WithInput(output.Input),
		tea.WithOutput(output.Out),
	)
	_, err = program.Run()
	return err
}

func (m dashboardModel) Init() tea.Cmd {
	return tea.Batch(m.loadViews(), waitDashboardEvent(m.events, m.streamErrors), dashboardTick())
}

func (m dashboardModel) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	switch message := message.(type) {
	case tea.KeyMsg:
		switch message.String() {
		case "q", "esc", "ctrl+c":
			return m, tea.Quit
		case "up", "k":
			if m.selected > 0 {
				m.selected--
			}
		case "down", "j":
			if m.selected+1 < len(m.views) {
				m.selected++
			}
		case "r":
			return m, m.loadViews()
		}
	case tea.WindowSizeMsg:
		m.width, m.height = message.Width, message.Height
	case dashboardViewsMsg:
		m.err = message.err
		if message.err == nil {
			m.views = message.views
			sortDashboardViews(m.views)
			m.clampSelection()
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
		lines = append(lines, "No managed tunnels")
	} else {
		lines = append(lines, m.tableHeader(width))
		start, end := m.visibleRange()
		for index := start; index < end; index++ {
			lines = append(lines, m.tableRow(index, width))
		}
		lines = append(lines, "")
		detailBudget := height - len(lines) - 3
		if m.err != nil {
			detailBudget -= 2
		}
		detailBudget = max(0, detailBudget)
		lines = append(lines, m.peerLinesWithin(width, detailBudget)...)
	}
	if m.err != nil {
		lines = append(lines, "", lipgloss.NewStyle().Foreground(lipgloss.Color("1")).Render(fit(m.err.Error(), width)))
	}
	hintStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	lines = append(lines, "", hintStyle.Render(fit("up/down or j/k: select   r: refresh", width)), hintStyle.Render("q/esc: back"))
	return fitWorkspaceHeight(strings.Join(lines, "\n"), height)
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
	for index := range m.views {
		if m.views[index].Tunnel.ID == view.Tunnel.ID {
			m.views[index] = view
			sortDashboardViews(m.views)
			m.clampSelection()
			return
		}
	}
	m.views = append(m.views, view)
	sortDashboardViews(m.views)
	m.clampSelection()
}

func (m *dashboardModel) applyStatusEvent(event core.Event) bool {
	if event.Status == nil {
		return false
	}
	for index := range m.views {
		if m.views[index].Tunnel.ID != event.TunnelID {
			continue
		}
		m.views[index].Tunnel.Name = event.TunnelName
		m.views[index].Tunnel.Kind = event.TunnelKind
		m.views[index].Tunnel.Enabled = event.Enabled
		m.views[index].Tunnel.Generation = event.Generation
		m.views[index].Status = *event.Status
		sortDashboardViews(m.views)
		m.clampSelection()
		return true
	}
	return false
}

func (m *dashboardModel) remove(id string) {
	for index := range m.views {
		if m.views[index].Tunnel.ID == id {
			m.views = append(m.views[:index], m.views[index+1:]...)
			break
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
	rows := len(m.views)
	maxRows := m.inlineHeight() - 15
	if maxRows < 1 {
		maxRows = 1
	}
	if maxRows > rows {
		maxRows = rows
	}
	start := 0
	if m.selected >= maxRows {
		start = m.selected - maxRows + 1
	}
	end := min(rows, start+maxRows)
	return start, end
}

func (m dashboardModel) inlineHeight() int {
	if m.height <= 0 {
		return dashboardMaxInlineHeight
	}
	return min(m.height, dashboardMaxInlineHeight)
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
	if maxLines == 0 {
		return nil
	}
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
	if maxLines > 0 && len(lines) >= maxLines {
		return lines[:maxLines]
	}
	if len(view.Status.Peers) == 0 {
		if message := statusMessage(view); message != "" {
			lines = append(lines, fit(message, width))
		}
		return lines
	}
	completePeers := 0
	for index, peer := range view.Status.Peers {
		if maxLines >= 0 && len(lines)+3 > maxLines {
			if len(lines) < maxLines {
				lines = append(lines, fit(fmt.Sprintf("... %d more peers", len(view.Status.Peers)-index), width))
			}
			break
		}
		if maxLines >= 0 && completePeers > 0 && index+1 < len(view.Status.Peers) && len(lines)+3 == maxLines {
			lines = append(lines, fit(fmt.Sprintf("... %d more peers", len(view.Status.Peers)-index), width))
			break
		}
		key := peer.PublicKey
		if len(key) > 12 {
			key = key[:12]
		}
		endpoint := peer.Endpoint
		if endpoint == "" {
			endpoint = "-"
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
		completePeers++
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
