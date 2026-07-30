package app

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/TunnelHelper/TH/internal/model"
	tea "github.com/charmbracelet/bubbletea"
)

func (m manageWorkspaceModel) updatePeerList(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	peers := workspaceWireGuardSpec(&m.draft).Peers
	maximum := len(peers)
	m.peerSelected = min(m.peerSelected, maximum)
	switch key.String() {
	case "up", "k":
		if m.peerSelected > 0 {
			m.peerSelected--
		}
	case "down", "j":
		if m.peerSelected < maximum {
			m.peerSelected++
		}
	case "enter", " ":
		if m.peerSelected == len(peers) {
			allowed, _ := parsePrefixes("0.0.0.0/0,::/0")
			m.peerAdding = true
			m.peerIndex = -1
			m.peerOriginal = model.WireGuardPeer{}
			m.peerDraft = model.WireGuardPeer{AllowedIPs: allowed}
		} else {
			m.peerAdding = false
			m.peerIndex = m.peerSelected
			m.peerOriginal = peers[m.peerSelected]
			m.peerDraft = peers[m.peerSelected]
		}
		m.fieldSelected = 0
		m.page = workspacePeer
		m.notice = ""
	case "a":
		m.peerSelected = len(peers)
		allowed, _ := parsePrefixes("0.0.0.0/0,::/0")
		m.peerAdding, m.peerIndex = true, -1
		m.peerOriginal = model.WireGuardPeer{}
		m.peerDraft = model.WireGuardPeer{AllowedIPs: allowed}
		m.fieldSelected = 0
		m.page = workspacePeer
	case "q", "esc":
		m.page = workspaceEdit
		m.fieldSelected = workspaceFieldIndex(workspaceTunnelFields(m.draft), "wg.peers")
	}
	return m, nil
}

func (m manageWorkspaceModel) peerListView(width int) string {
	peers := workspaceWireGuardSpec(&m.draft).Peers
	lines := []string{m.breadcrumb(width), "", workspaceAccentStyle.Render(fmt.Sprintf("WireGuard peers  %d", len(peers))), ""}
	start, end := workspaceVisibleRange(len(peers)+1, m.peerSelected, max(1, m.inlineHeight()-8))
	for index := start; index < end; index++ {
		selected := index == m.peerSelected
		line := "> "
		if !selected {
			line = "  "
		}
		if index == len(peers) {
			line += "+ Add peer"
		} else {
			peer := peers[index]
			line += fmt.Sprintf("%-22s  %-24s  %s", fit(peer.PublicKey, 22), fit(endpointLabel(peer.Endpoint), 24), formatPrefixes(peer.AllowedIPs))
		}
		line = fit(line, width)
		if selected {
			line = workspaceFocusStyle.Render(line)
		}
		lines = append(lines, line)
	}
	lines = append(lines, m.feedbackLines(width)...)
	lines = append(lines, "")
	lines = append(lines, workspaceHintLines(width, "enter  Edit peer", "a  Add peer", "esc  Back to tunnel")...)
	return strings.Join(lines, "\n")
}

func (m manageWorkspaceModel) updatePeerEditor(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	fields := workspacePeerFields(m.peerDraft)
	m.fieldSelected = min(m.fieldSelected, len(fields)-1)
	switch key.String() {
	case "up", "k":
		if m.fieldSelected > 0 {
			m.fieldSelected--
		}
	case "down", "j":
		if m.fieldSelected+1 < len(fields) {
			m.fieldSelected++
		}
	case "enter", " ":
		if err := m.activatePeerField(fields[m.fieldSelected]); err != nil {
			m.err = err
		}
	case "s", "ctrl+s":
		if err := m.validatePeerDraft(); err != nil {
			m.err = err
			return m, nil
		}
		if len(workspacePeerChanges(m.peerOriginal, m.peerDraft, m.peerAdding)) == 0 {
			m.notice = "No peer changes to save"
			return m, nil
		}
		m.beginConfirm("save-peer", "Save peer", "Merge this peer into the pending tunnel configuration?", workspacePeerSaveLabel(m.peerAdding), "Keep editing", false)
	case "d":
		label := "Discard peer"
		if !m.peerAdding {
			label = "Remove peer"
		}
		m.beginConfirm("remove-peer", label, "This change remains local until the tunnel is saved.", label, "Cancel", true)
	case "q", "esc":
		if len(workspacePeerChanges(m.peerOriginal, m.peerDraft, m.peerAdding)) == 0 {
			m.closePeerEditor()
		} else {
			m.beginConfirm("discard-peer", "Unsaved peer changes", "Discard changes made on this peer page?", "Discard changes", "Keep editing", true)
		}
	}
	return m, nil
}

func (m manageWorkspaceModel) peerEditorView(width int) string {
	fields := workspacePeerFields(m.peerDraft)
	changes := workspacePeerChanges(m.peerOriginal, m.peerDraft, m.peerAdding)
	status := workspaceWarnStyle.Render(fmt.Sprintf("Unsaved  %d change(s)", len(changes)))
	if len(changes) == 0 {
		status = workspaceGoodStyle.Render("Saved in draft")
	}
	lines := []string{m.breadcrumb(width), "", workspaceAccentStyle.Render(fit(workspacePeerCrumb(m.peerDraft, m.peerAdding), width)), status, ""}
	start, end := workspaceVisibleRange(len(fields), m.fieldSelected, max(1, m.inlineHeight()-13))
	for index := start; index < end; index++ {
		lines = append(lines, renderWorkspaceField(fields[index], index == m.fieldSelected, width))
	}
	lines = append(lines, "")
	lines = append(lines, workspaceDiffLines(changes, width, 5)...)
	lines = append(lines, m.feedbackLines(width)...)
	lines = append(lines, "")
	lines = append(lines, workspaceHintLines(width, "enter  Edit field", "s  Save peer", "d  Remove/discard", "esc  Back")...)
	return strings.Join(lines, "\n")
}

func workspacePeerFields(peer model.WireGuardPeer) []workspaceField {
	pskState := "keep current"
	if peer.PresharedKey == model.ClearSecretValue {
		pskState = "remove on save"
	} else if peer.PresharedKey != "" {
		pskState = "replace on save"
	}
	return []workspaceField{
		workspaceTextField("key", "Public key", peer.PublicKey, validateWireGuardKey),
		{ID: "psk", Label: "Preshared key", Value: pskState, Kind: workspaceFieldChoice, Buttons: []workspaceButton{
			{Label: "Keep current", Value: "keep"}, {Label: "Replace", Value: "replace"}, {Label: "Remove", Value: "remove", Destructive: true},
		}, Selected: workspacePeerPSKSelection(peer)},
		workspaceTextField("endpoint", "Endpoint", peer.Endpoint, validateEndpointOrHost),
		workspaceTextField("allowed", "Allowed IPs", formatPrefixes(peer.AllowedIPs), validateAllowedPrefixesInput),
		workspaceTextField("keepalive", "Persistent keepalive", strconv.Itoa(peer.Keepalive), validateInt(0, 65535)),
	}
}

func (m *manageWorkspaceModel) activatePeerField(field workspaceField) error {
	if field.Kind == workspaceFieldChoice {
		m.beginChoice("peer:"+field.ID, field.Label, "Choose how this update should handle the redacted secret.", field.Buttons, field.Selected)
		return nil
	}
	m.beginInput("peer:"+field.ID, field.Label, field.Description, workspaceInputStep{
		Label: field.Label, Value: field.EditValue, Validator: field.Validator,
	})
	return nil
}

func (m *manageWorkspaceModel) applyPeerChoice(id, value string) error {
	if id != "psk" {
		return fmt.Errorf("unsupported peer choice %q", id)
	}
	switch value {
	case "keep":
		m.peerDraft.PresharedKey = ""
	case "remove":
		m.peerDraft.PresharedKey = model.ClearSecretValue
	case "replace":
		m.beginInput("peer:psk-value", "Replace preshared key", "The value is staged securely and never shown in the diff.", workspaceInputStep{
			Label: "New preshared key", Secret: true, Validator: validateWireGuardKey,
		})
	default:
		return fmt.Errorf("unsupported preshared-key action %q", value)
	}
	return nil
}

func (m *manageWorkspaceModel) applyPeerInput(id string, values []string) error {
	value := strings.TrimSpace(values[0])
	switch id {
	case "key":
		m.peerDraft.PublicKey = value
	case "psk-value":
		m.peerDraft.PresharedKey = value
	case "endpoint":
		endpoint, err := normalizeWorkspaceEndpoint(value)
		if err != nil {
			return err
		}
		m.peerDraft.Endpoint = endpoint
		if endpoint == "" {
			m.peerDraft.Keepalive = 0
		}
	case "allowed":
		m.peerDraft.AllowedIPs, _ = parsePrefixes(value)
	case "keepalive":
		m.peerDraft.Keepalive = parseInt(value)
	default:
		return fmt.Errorf("unsupported peer field %q", id)
	}
	return nil
}

func (m *manageWorkspaceModel) validatePeerDraft() error {
	peer := m.peerDraft
	if err := validateWireGuardKey(peer.PublicKey); err != nil {
		return fmt.Errorf("public key: %w", err)
	}
	if peer.PresharedKey != "" && peer.PresharedKey != model.ClearSecretValue {
		if err := validateWireGuardKey(peer.PresharedKey); err != nil {
			return fmt.Errorf("preshared key: %w", err)
		}
	}
	if err := validateEndpointInput(peer.Endpoint); err != nil {
		return err
	}
	if err := validateAllowedPrefixesInput(formatPrefixes(peer.AllowedIPs)); err != nil {
		return err
	}
	peers := workspaceWireGuardSpec(&m.draft).Peers
	if duplicatePeer(peers, peer.PublicKey, m.peerIndex) {
		return errors.New("a peer with that public key already exists")
	}
	return nil
}

func (m *manageWorkspaceModel) applyPeerConfirm(action string) (tea.Cmd, error) {
	switch action {
	case "save-peer":
		if err := m.validatePeerDraft(); err != nil {
			return nil, err
		}
		peers := workspaceWireGuardSpec(&m.draft).Peers
		if m.peerAdding {
			if len(peers) >= model.MaxWireGuardPeers {
				return nil, fmt.Errorf("peers exceeds %d entries", model.MaxWireGuardPeers)
			}
			peers = append(peers, m.peerDraft)
			m.peerSelected = len(peers) - 1
		} else if m.peerIndex >= 0 && m.peerIndex < len(peers) {
			peers[m.peerIndex] = m.peerDraft
			m.peerSelected = m.peerIndex
		}
		workspaceWireGuardSpec(&m.draft).Peers = peers
		m.notice = "Peer changes staged in tunnel draft"
		m.closePeerEditor()
	case "discard-peer":
		m.notice = "Peer changes discarded"
		m.closePeerEditor()
	case "remove-peer":
		if !m.peerAdding {
			peers := workspaceWireGuardSpec(&m.draft).Peers
			if m.peerIndex >= 0 && m.peerIndex < len(peers) {
				peers = append(peers[:m.peerIndex], peers[m.peerIndex+1:]...)
				workspaceWireGuardSpec(&m.draft).Peers = peers
				m.peerSelected = min(m.peerIndex, len(peers))
			}
			m.notice = "Peer removal staged in tunnel draft"
		} else {
			m.notice = "New peer discarded"
		}
		m.closePeerEditor()
	}
	return nil, nil
}

func (m *manageWorkspaceModel) closePeerEditor() {
	m.page = workspacePeers
	m.peerIndex = -1
	m.peerAdding = false
	m.peerOriginal, m.peerDraft = model.WireGuardPeer{}, model.WireGuardPeer{}
	m.fieldSelected = 0
}

func normalizeWorkspaceEndpoint(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	if _, _, err := net.SplitHostPort(value); err == nil {
		return value, nil
	}
	if err := validateEndpointOrHost(value); err != nil {
		return "", err
	}
	if address, err := netip.ParseAddr(value); err == nil && address.Is6() {
		return net.JoinHostPort(value, "51820"), nil
	}
	return value + ":51820", nil
}

func workspacePeerPSKSelection(peer model.WireGuardPeer) int {
	if peer.PresharedKey == model.ClearSecretValue {
		return 2
	}
	if peer.PresharedKey != "" {
		return 1
	}
	return 0
}

func workspacePeerSaveLabel(adding bool) string {
	if adding {
		return "Add peer"
	}
	return "Save peer"
}

func workspacePeerCrumb(peer model.WireGuardPeer, adding bool) string {
	if adding {
		return "Add peer"
	}
	if peer.PublicKey == "" {
		return "Peer"
	}
	return "Peer " + fit(peer.PublicKey, 12)
}

func (m manageWorkspaceModel) updateSourceList(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	sources := m.draft.Spec.SRv6.Sources
	maximum := len(sources)
	m.sourceSelected = min(m.sourceSelected, maximum)
	switch key.String() {
	case "up", "k":
		if m.sourceSelected > 0 {
			m.sourceSelected--
		}
	case "down", "j":
		if m.sourceSelected < maximum {
			m.sourceSelected++
		}
	case "enter", " ":
		if m.sourceSelected == len(sources) {
			m.beginSourceAdd(sources)
		} else {
			m.sourceAdding, m.sourceIndex = false, m.sourceSelected
			m.sourceOriginal, m.sourceDraft = sources[m.sourceSelected], sources[m.sourceSelected]
			m.fieldSelected = 0
			m.page = workspaceSource
		}
		m.notice = ""
	case "a":
		m.sourceSelected = len(sources)
		m.beginSourceAdd(sources)
	case "q", "esc":
		m.page = workspaceEdit
		m.fieldSelected = workspaceFieldIndex(workspaceTunnelFields(m.draft), "srv6.sources")
	}
	return m, nil
}

func (m *manageWorkspaceModel) beginSourceAdd(sources []model.SRv6Source) {
	m.sourceAdding, m.sourceIndex = true, -1
	m.sourceOriginal = model.SRv6Source{}
	m.sourceDraft = model.SRv6Source{Name: suggestedSRv6SourceName(sources), Priority: 100, MTU: 1500}
	m.fieldSelected = 0
	m.beginChoice("srv6-source-family", "Address family", "", []workspaceButton{
		{Label: "IPv4", Value: string(model.SRv6FamilyIPv4)},
		{Label: "IPv6", Value: string(model.SRv6FamilyIPv6)},
	}, 0)
}

func (m manageWorkspaceModel) sourceListView(width int) string {
	sources := m.draft.Spec.SRv6.Sources
	lines := []string{m.breadcrumb(width), "", workspaceAccentStyle.Render(fmt.Sprintf("SRv6 route sources  %d", len(sources))), ""}
	start, end := workspaceVisibleRange(len(sources)+1, m.sourceSelected, max(1, m.inlineHeight()-8))
	for index := start; index < end; index++ {
		selected := index == m.sourceSelected
		line := "> "
		if !selected {
			line = "  "
		}
		if index == len(sources) {
			line += "+ Add source"
		} else {
			source := sources[index]
			line += fmt.Sprintf("%-20s  %-4s  priority %-10d  SID %-24s  MTU %d",
				source.Name, srv6FamilyDisplay(source.Family), source.Priority, srv6SIDInput(source.SID), source.MTU)
		}
		line = fit(line, width)
		if selected {
			line = workspaceFocusStyle.Render(line)
		}
		lines = append(lines, line)
	}
	lines = append(lines, m.feedbackLines(width)...)
	lines = append(lines, "")
	lines = append(lines, workspaceHintLines(width, "enter  Edit source", "a  Add source", "esc  Back to tunnel")...)
	return strings.Join(lines, "\n")
}

func (m manageWorkspaceModel) updateSourceEditor(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	fields := workspaceSourceFields(m.sourceDraft)
	m.fieldSelected = min(m.fieldSelected, len(fields)-1)
	switch key.String() {
	case "up", "k":
		if m.fieldSelected > 0 {
			m.fieldSelected--
		}
	case "down", "j":
		if m.fieldSelected+1 < len(fields) {
			m.fieldSelected++
		}
	case "enter", " ":
		field := fields[m.fieldSelected]
		m.beginInput("source:"+field.ID, field.Label, field.Description, workspaceInputStep{
			Label: field.Label, Value: field.EditValue, Validator: field.Validator,
		})
	case "s", "ctrl+s":
		if err := m.validateSourceDraft(); err != nil {
			m.err = err
			return m, nil
		}
		if len(workspaceSourceChanges(m.sourceOriginal, m.sourceDraft, m.sourceAdding)) == 0 {
			m.notice = "No route source changes to save"
			return m, nil
		}
		m.beginConfirm("save-source", "Save route source", "Merge this source into the pending SRv6 configuration?", workspaceSourceSaveLabel(m.sourceAdding), "Keep editing", false)
	case "d":
		if !m.sourceAdding && len(m.draft.Spec.SRv6.Sources) == 1 {
			m.err = errors.New("an SRv6 tunnel must retain at least one route source")
			return m, nil
		}
		label := "Discard source"
		if !m.sourceAdding {
			label = "Remove source"
		}
		m.beginConfirm("remove-source", label, "This change remains local until the tunnel is saved.", label, "Cancel", true)
	case "q", "esc":
		if len(workspaceSourceChanges(m.sourceOriginal, m.sourceDraft, m.sourceAdding)) == 0 {
			m.closeSourceEditor()
		} else {
			m.beginConfirm("discard-source", "Unsaved source changes", "Discard changes made on this source page?", "Discard changes", "Keep editing", true)
		}
	}
	return m, nil
}

func (m manageWorkspaceModel) sourceEditorView(width int) string {
	fields := workspaceSourceFields(m.sourceDraft)
	changes := workspaceSourceChanges(m.sourceOriginal, m.sourceDraft, m.sourceAdding)
	status := workspaceWarnStyle.Render(fmt.Sprintf("Unsaved  %d change(s)", len(changes)))
	if len(changes) == 0 {
		status = workspaceGoodStyle.Render("Saved in draft")
	}
	lines := []string{m.breadcrumb(width), "", workspaceAccentStyle.Render(fit(workspaceSourceCrumb(m.sourceDraft, m.sourceAdding), width)), status, ""}
	for index, field := range fields {
		lines = append(lines, renderWorkspaceField(field, index == m.fieldSelected, width))
	}
	lines = append(lines, "")
	lines = append(lines, workspaceDiffLines(changes, width, 5)...)
	lines = append(lines, m.feedbackLines(width)...)
	lines = append(lines, "")
	lines = append(lines, workspaceHintLines(width, "enter  Edit field", "s  Save source", "d  Remove/discard", "esc  Back")...)
	return strings.Join(lines, "\n")
}

func workspaceSourceFields(source model.SRv6Source) []workspaceField {
	return []workspaceField{
		workspaceTextField("name", "Name", source.Name, validateNameInput),
		workspaceTextField("url", srv6FamilyDisplay(source.Family)+" prefix file URL", source.PrefixURL, validateHTTPURL),
		workspaceTextField("priority", "Priority (higher wins)", strconv.Itoa(source.Priority), validateInt(0, 2147483647)),
		workspaceTextField("sid", "Route SID", srv6SIDInput(source.SID), validateRequiredIPv6),
		workspaceTextField("mtu", "MTU", strconv.Itoa(source.MTU), validateInt(68, 65535)),
	}
}

func (m *manageWorkspaceModel) applySourceInput(id string, values []string) error {
	value := strings.TrimSpace(values[0])
	switch id {
	case "name":
		m.sourceDraft.Name = value
	case "url":
		m.sourceDraft.PrefixURL = value
	case "sid":
		m.sourceDraft.SID, _ = netip.ParseAddr(value)
	case "priority":
		m.sourceDraft.Priority = parseInt(value)
	case "mtu":
		m.sourceDraft.MTU = parseInt(value)
	default:
		return fmt.Errorf("unsupported source field %q", id)
	}
	return nil
}

func (m *manageWorkspaceModel) validateSourceDraft() error {
	if err := validateNameInput(m.sourceDraft.Name); err != nil {
		return err
	}
	if err := validateSRv6SourceFields(m.sourceDraft); err != nil {
		return err
	}
	if m.sourceDraft.MTU < 68 || m.sourceDraft.MTU > 65535 {
		return errors.New("MTU must be between 68 and 65535")
	}
	for index, source := range m.draft.Spec.SRv6.Sources {
		if index != m.sourceIndex && source.Name == m.sourceDraft.Name {
			return fmt.Errorf("source name %q is already in use", m.sourceDraft.Name)
		}
	}
	return nil
}

func (m *manageWorkspaceModel) applySourceConfirm(action string) (tea.Cmd, error) {
	switch action {
	case "save-source":
		if err := m.validateSourceDraft(); err != nil {
			return nil, err
		}
		sources := m.draft.Spec.SRv6.Sources
		if m.sourceAdding {
			if len(sources) >= model.MaxSRv6Sources {
				return nil, fmt.Errorf("sources exceeds %d entries", model.MaxSRv6Sources)
			}
			sources = append(sources, m.sourceDraft)
			m.sourceSelected = len(sources) - 1
		} else if m.sourceIndex >= 0 && m.sourceIndex < len(sources) {
			sources[m.sourceIndex] = m.sourceDraft
			m.sourceSelected = m.sourceIndex
		}
		m.draft.Spec.SRv6.Sources = sources
		m.notice = "Route source changes staged in tunnel draft"
		m.closeSourceEditor()
	case "discard-source":
		m.notice = "Route source changes discarded"
		m.closeSourceEditor()
	case "remove-source":
		if !m.sourceAdding {
			sources := m.draft.Spec.SRv6.Sources
			if len(sources) <= 1 {
				return nil, errors.New("an SRv6 tunnel must retain at least one route source")
			}
			if m.sourceIndex >= 0 && m.sourceIndex < len(sources) {
				sources = append(sources[:m.sourceIndex], sources[m.sourceIndex+1:]...)
				m.draft.Spec.SRv6.Sources = sources
				m.sourceSelected = min(m.sourceIndex, len(sources))
			}
			m.notice = "Route source removal staged in tunnel draft"
		} else {
			m.notice = "New route source discarded"
		}
		m.closeSourceEditor()
	}
	return nil, nil
}

func (m *manageWorkspaceModel) closeSourceEditor() {
	m.page = workspaceSources
	m.sourceIndex = -1
	m.sourceAdding = false
	m.sourceOriginal, m.sourceDraft = model.SRv6Source{}, model.SRv6Source{}
	m.fieldSelected = 0
}

func workspaceSourceSaveLabel(adding bool) string {
	if adding {
		return "Add source"
	}
	return "Save source"
}

func workspaceSourceCrumb(source model.SRv6Source, adding bool) string {
	if adding {
		return "Add " + srv6FamilyDisplay(source.Family) + " source"
	}
	if source.Name == "" {
		return srv6FamilyDisplay(source.Family) + " source"
	}
	return source.Name + " [" + srv6FamilyDisplay(source.Family) + "]"
}

func workspaceFieldIndex(fields []workspaceField, id string) int {
	for index := range fields {
		if fields[index].ID == id {
			return index
		}
	}
	return 0
}
