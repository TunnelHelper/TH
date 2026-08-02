package app

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/TunnelHelper/TH/internal/model"
	tea "github.com/charmbracelet/bubbletea"
)

type workspaceFieldKind uint8

const (
	workspaceFieldInput workspaceFieldKind = iota
	workspaceFieldToggle
	workspaceFieldChoice
	workspaceFieldNavigate
	workspaceFieldAction
)

type workspaceField struct {
	ID          string
	Label       string
	Value       string
	EditValue   string
	Description string
	Kind        workspaceFieldKind
	Secret      bool
	Validator   func(string) error
	Buttons     []workspaceButton
	Selected    int
}

func (m manageWorkspaceModel) updateTunnelEditor(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	fields := workspaceTunnelFields(m.draft)
	if len(fields) == 0 {
		return m, nil
	}
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
		if err := m.activateTunnelField(fields[m.fieldSelected]); err != nil {
			m.err = err
		}
	case "s", "ctrl+s":
		changes := workspaceTunnelChanges(m.original, m.draft)
		if len(changes) == 0 {
			m.notice = "No changes to save"
			return m, nil
		}
		m.beginConfirm("save-tunnel", "Save changes", fmt.Sprintf("Apply %d pending change(s) to %s?", len(changes), m.draft.Name), "Save changes", "Keep editing", false)
	case "q", "esc":
		if len(workspaceTunnelChanges(m.original, m.draft)) == 0 {
			m.page = workspaceTunnel
			m.original, m.draft = model.Tunnel{}, model.Tunnel{}
			return m, nil
		}
		m.beginConfirm("discard-tunnel", "Unsaved changes", "Discard all pending tunnel changes?", "Discard changes", "Keep editing", true)
	}
	return m, nil
}

func (m manageWorkspaceModel) tunnelEditorView(width int) string {
	fields := workspaceTunnelFields(m.draft)
	changes := workspaceTunnelChanges(m.original, m.draft)
	status := workspaceGoodStyle.Render("Saved")
	if len(changes) > 0 {
		status = workspaceWarnStyle.Bold(true).Render(fmt.Sprintf("Unsaved  %d change(s)", len(changes)))
	}
	header := []string{m.breadcrumb(width), "", workspaceAccentStyle.Render(fit("Edit "+m.draft.Name, width)), status, ""}
	fieldLines := []string{workspaceAccentStyle.Render("Configuration")}
	start, end := workspaceVisibleRange(len(fields), m.fieldSelected, max(3, m.inlineHeight()-12))
	for index := start; index < end; index++ {
		fieldLines = append(fieldLines, renderWorkspaceField(fields[index], index == m.fieldSelected, width))
	}
	header = append(header, fieldLines...)
	header = append(header, "")
	header = append(header, workspaceDiffLines(changes, width, 3)...)
	header = append(header, m.feedbackLines(width)...)
	if m.busy != "" {
		header = append(header, "", workspaceWarnStyle.Render(m.busy+"..."))
	}
	header = append(header, "")
	header = append(header, workspaceHintLines(width, "enter  Edit field", "s  Save changes", "esc  Discard/back")...)
	return strings.Join(header, "\n")
}

func renderWorkspaceField(field workspaceField, selected bool, width int) string {
	marker := "  "
	if selected {
		marker = "> "
	}
	labelWidth := min(25, max(14, width/3))
	line := fmt.Sprintf("%s%-*s %s", marker, labelWidth, fit(field.Label, labelWidth), field.Value)
	line = fit(line, max(1, width))
	if selected {
		return workspaceFocusStyle.Render(line)
	}
	return line
}

func workspaceTunnelFields(tunnel model.Tunnel) []workspaceField {
	fields := []workspaceField{{
		ID: "name", Label: "Name", Value: tunnel.Name, EditValue: tunnel.Name,
		Kind: workspaceFieldInput, Validator: validateNameInput,
	}}
	switch tunnel.Kind {
	case model.KindGRE:
		spec := tunnel.Spec.GRE
		fields = append(fields,
			workspaceTextField("gre.remote", "Remote underlay", spec.Remote.String(), validateAddrInput),
			workspaceTextField("gre.local", "Local underlay", spec.Local.String(), validateAddrInput),
			workspaceTextField("gre.addresses", "Interface addresses", formatPrefixes(spec.Addresses), validateInterfacePrefixesInput),
			workspaceTextField("gre.mtu", "MTU", strconv.Itoa(spec.MTU), validateInt(68, 65535)),
			workspaceTextField("gre.ttl", "TTL", strconv.Itoa(int(spec.TTL)), validateInt(1, 255)),
		)
	case model.KindVXLAN:
		spec := tunnel.Spec.VXLAN
		fields = append(fields,
			workspaceTextField("vxlan.vni", "VNI", strconv.Itoa(spec.VNI), validateInt(1, 16777215)),
			workspaceTextField("vxlan.remote", "Remote underlay", spec.Remote.String(), validateAddrInput),
			workspaceTextField("vxlan.local", "Local underlay", spec.Local.String(), validateAddrInput),
			workspaceTextField("vxlan.underlay", "Underlay interface", spec.UnderlayInterface, validateInterfaceInput),
			workspaceTextField("vxlan.port", "Destination port", strconv.Itoa(spec.DestinationPort), validateInt(1, 65535)),
			workspaceToggleField("vxlan.learning", "MAC learning", spec.Learning),
			workspaceTextField("vxlan.addresses", "Interface addresses", formatPrefixes(spec.Addresses), validateInterfacePrefixesInput),
			workspaceTextField("vxlan.mtu", "MTU", strconv.Itoa(spec.MTU), validateInt(68, 65535)),
		)
	case model.KindWireGuard, model.KindAmneziaWG:
		spec := workspaceWireGuardSpec(&tunnel)
		fields = append(fields,
			workspaceTextField("wg.addresses", "Interface addresses", formatPrefixes(spec.Addresses), validateInterfacePrefixesInput),
			workspaceTextField("wg.listen", "Listen port", strconv.Itoa(spec.ListenPort), validateInt(0, 65535)),
			workspaceTextField("wg.mtu", "MTU", strconv.Itoa(spec.MTU), validateInt(68, 65535)),
			workspaceTextField("wg.mark", "Firewall mark", strconv.Itoa(spec.FirewallMark), validateInt(0, 2147483647)),
			workspaceField{ID: "wg.peers", Label: "Peers", Value: fmt.Sprintf("%d configured", len(spec.Peers)), Kind: workspaceFieldNavigate},
			workspaceChoiceField("wg.routing", "AllowedIPs routing", workspaceRoutingValue(spec), []workspaceButton{
				{Label: "Disabled", Value: "disabled"}, {Label: "Automatic", Value: "auto"}, {Label: "Custom table", Value: "custom"},
			}, workspaceRoutingSelection(spec)),
			workspaceField{ID: "wg.rotate", Label: "Local key", Value: "Rotate key pair", Kind: workspaceFieldAction},
		)
		if tunnel.Kind == model.KindAmneziaWG {
			value := formatAmneziaParameters(tunnel.Spec.AmneziaWG)
			fields = append(fields, workspaceTextField("awg.obfuscation", "Obfuscation", value, validateAmneziaParameterString))
		}
	case model.KindXFRMStatic:
		spec := tunnel.Spec.XFRMStatic
		fields = append(fields,
			workspaceTextField("xfrm.remote", "Remote underlay", spec.Remote.String(), validateAddrInput),
			workspaceTextField("xfrm.local", "Local underlay", spec.Local.String(), validateAddrInput),
			workspaceTextField("xfrm.underlay", "Underlay interface", spec.UnderlayInterface, validateInterfaceInput),
			workspaceTextField("xfrm.addresses", "Interface addresses", formatPrefixes(spec.Addresses), validateInterfacePrefixesInput),
			workspaceTextField("xfrm.mtu", "MTU", strconv.Itoa(spec.MTU), validateInt(68, 65535)),
			workspaceTextField("xfrm.spi-in", "Inbound SPI", fmt.Sprintf("0x%x", spec.SPIInbound), validateSPI),
			workspaceTextField("xfrm.spi-out", "Outbound SPI", fmt.Sprintf("0x%x", spec.SPIOutbound), validateSPI),
			workspaceChoiceField("xfrm.algorithm", "Algorithm", string(spec.Algorithm), []workspaceButton{
				{Label: "AES-GCM-128", Value: string(model.XFRMAESGCM)},
				{Label: "AES-CBC-256 + SHA256", Value: string(model.XFRMAESCBCSHA256)},
			}, workspaceStringSelection(string(spec.Algorithm), []string{string(model.XFRMAESGCM), string(model.XFRMAESCBCSHA256)})),
			workspaceField{ID: "xfrm.keys", Label: "Key material", Value: workspaceStaticKeyState(spec), Kind: workspaceFieldAction},
		)
	case model.KindXFRMIKEv2:
		spec := tunnel.Spec.XFRMIKEv2
		fields = append(fields,
			workspaceTextField("ike.remote", "Remote underlay", spec.RemoteAddress, validateIKEAddrInput),
			workspaceTextField("ike.local", "Local underlay", spec.LocalAddress, validateIKEAddrInput),
			workspaceTextField("ike.underlay", "Underlay interface", spec.UnderlayInterface, validateInterfaceInput),
			workspaceTextField("ike.local-id", "Local identity", spec.LocalID, required),
			workspaceTextField("ike.remote-id", "Remote identity", spec.RemoteID, required),
			workspaceTextField("ike.addresses", "Interface addresses", formatPrefixes(spec.Addresses), validateInterfacePrefixesInput),
			workspaceTextField("ike.mtu", "MTU", strconv.Itoa(spec.MTU), validateInt(68, 65535)),
			workspaceChoiceField("ike.auth", "Authentication", string(spec.AuthMethod), []workspaceButton{
				{Label: "Pre-shared key", Value: string(model.IKEAuthPSK)}, {Label: "Raw public key", Value: string(model.IKEAuthRPK)},
			}, workspaceStringSelection(string(spec.AuthMethod), []string{string(model.IKEAuthPSK), string(model.IKEAuthRPK)})),
			workspaceField{ID: "ike.auth-material", Label: "Authentication material", Value: "Replace credentials", Kind: workspaceFieldAction},
			workspaceField{ID: "ike.proposals", Label: "IKE / ESP proposals", Value: spec.IKEProposal + " / " + spec.ESPProposal, Kind: workspaceFieldAction},
			workspaceToggleField("ike.encapsulation", "UDP encapsulation", spec.Encapsulation),
			workspaceChoiceField("ike.start", "Start action", spec.StartAction, []workspaceButton{
				{Label: "Trap policy", Value: "trap"}, {Label: "Initiate", Value: "start"}, {Label: "Load only", Value: "none"},
			}, workspaceStringSelection(spec.StartAction, []string{"trap", "start", "none"})),
		)
	case model.KindSRv6:
		spec := tunnel.Spec.SRv6
		fields = append(fields,
			workspaceTextField("srv6.underlay", "Underlay interface", spec.UnderlayInterface, validateInterfaceInput),
			workspaceTextField("srv6.refresh", "Refresh interval", strconv.Itoa(spec.RefreshIntervalSeconds), validateInt(60, 604800)),
			workspaceField{ID: "srv6.sources", Label: "Route sources", Value: fmt.Sprintf("%d configured", len(spec.Sources)), Kind: workspaceFieldNavigate},
		)
	}
	if tunnel.Kind != model.KindSRv6 {
		babel := workspaceBabelConfig(&tunnel)
		fields = append(fields,
			workspaceToggleField("babel.enabled", "Babel routing", babel.Enabled),
			workspaceTextField("babel.bandwidth", "Babel bandwidth (Mbps)", strconv.Itoa(babel.BandwidthMbps), validateNonNegativeIntInput),
		)
	}
	return fields
}

// workspaceBabelConfig returns the per-tunnel Babel configuration, creating
// it on demand so the editor can toggle it on.
func workspaceBabelConfig(tunnel *model.Tunnel) *model.BabelTunnelConfig {
	if tunnel.Spec.Babel == nil {
		tunnel.Spec.Babel = &model.BabelTunnelConfig{}
	}
	return tunnel.Spec.Babel
}

func workspaceTextField(id, label, value string, validator func(string) error) workspaceField {
	display := value
	if strings.TrimSpace(display) == "" {
		display = "none"
	}
	return workspaceField{ID: id, Label: label, Value: display, EditValue: value, Kind: workspaceFieldInput, Validator: validator}
}

func workspaceToggleField(id, label string, enabled bool) workspaceField {
	return workspaceField{ID: id, Label: label, Value: enabledState(enabled), Kind: workspaceFieldToggle}
}

func workspaceChoiceField(id, label, value string, buttons []workspaceButton, selected int) workspaceField {
	return workspaceField{ID: id, Label: label, Value: value, Kind: workspaceFieldChoice, Buttons: buttons, Selected: selected}
}

func (m *manageWorkspaceModel) activateTunnelField(field workspaceField) error {
	switch field.Kind {
	case workspaceFieldInput:
		m.beginInput("tunnel:"+field.ID, field.Label, field.Description, workspaceInputStep{
			Label: field.Label, Value: field.EditValue, Secret: field.Secret, Validator: field.Validator,
		})
	case workspaceFieldToggle:
		return m.toggleWorkspaceField(field.ID)
	case workspaceFieldChoice:
		m.beginChoice("tunnel:"+field.ID, field.Label, field.Description, field.Buttons, field.Selected)
	case workspaceFieldNavigate:
		switch field.ID {
		case "wg.peers":
			m.page, m.peerSelected = workspacePeers, 0
		case "srv6.sources":
			m.page, m.sourceSelected = workspaceSources, 0
		}
	case workspaceFieldAction:
		switch field.ID {
		case "wg.rotate":
			m.beginConfirm("rotate-wg-key", "Rotate local key", "Peers must be updated with the new public key after this change is saved.", "Rotate key", "Cancel", true)
		case "xfrm.keys":
			m.beginStaticKeyInput()
		case "ike.auth-material":
			m.beginIKECredentialInput("replace")
		case "ike.proposals":
			m.beginChoice("ike-proposals", "Cryptographic profile", "Choose a profile or enter custom proposals.", []workspaceButton{
				{Label: "Recommended", Value: "recommended"}, {Label: "AES-256-GCM", Value: "aes256"}, {Label: "Custom", Value: "custom"},
			}, 0)
		}
	}
	return nil
}

func (m *manageWorkspaceModel) toggleWorkspaceField(id string) error {
	switch id {
	case "vxlan.learning":
		m.draft.Spec.VXLAN.Learning = !m.draft.Spec.VXLAN.Learning
	case "ike.encapsulation":
		m.draft.Spec.XFRMIKEv2.Encapsulation = !m.draft.Spec.XFRMIKEv2.Encapsulation
	case "babel.enabled":
		babel := workspaceBabelConfig(&m.draft)
		babel.Enabled = !babel.Enabled
		if babel.Enabled && model.BabelNeedsUnicastFallback(&m.draft) {
			multicast := false
			babel.Multicast = &multicast
			m.notice = "Babel enabled: peer AllowedIPs do not cover ff02::1:6; using unicast mode with auto-derived neighbours."
		}
	default:
		return fmt.Errorf("unsupported toggle field %q", id)
	}
	return nil
}

func (m *manageWorkspaceModel) applyWorkspaceInput(action string, values []string) error {
	if strings.HasPrefix(action, "tunnel:") {
		return m.applyTunnelInput(strings.TrimPrefix(action, "tunnel:"), values[0])
	}
	switch action {
	case "wg-route-custom":
		spec := workspaceWireGuardSpec(&m.draft)
		spec.RouteAllowedIPs = true
		spec.RouteTable = parseInt(values[0])
	case "xfrm-keys":
		return m.applyStaticKeys(values)
	case "ike-switch-psk", "ike-replace-psk":
		return m.applyIKEPSK(values[0])
	case "ike-switch-rpk", "ike-replace-rpk":
		return m.applyIKERPK(values[0])
	case "ike-custom-proposals":
		spec := m.draft.Spec.XFRMIKEv2
		spec.IKEProposal, spec.ESPProposal = strings.TrimSpace(values[0]), strings.TrimSpace(values[1])
	default:
		if strings.HasPrefix(action, "peer:") {
			return m.applyPeerInput(strings.TrimPrefix(action, "peer:"), values)
		}
		if strings.HasPrefix(action, "source:") {
			return m.applySourceInput(strings.TrimPrefix(action, "source:"), values)
		}
		return fmt.Errorf("unsupported input action %q", action)
	}
	return nil
}

func (m *manageWorkspaceModel) applyTunnelInput(id, value string) error {
	value = strings.TrimSpace(value)
	switch id {
	case "name":
		m.draft.Name = prefixedTunnelName(m.draft.Kind, value)
	case "gre.remote", "gre.local":
		address, _ := netip.ParseAddr(value)
		if id == "gre.remote" {
			m.draft.Spec.GRE.Remote = address
		} else {
			m.draft.Spec.GRE.Local = address
		}
	case "gre.addresses":
		m.draft.Spec.GRE.Addresses, _ = parsePrefixes(value)
	case "gre.mtu":
		m.draft.Spec.GRE.MTU = parseInt(value)
	case "gre.ttl":
		m.draft.Spec.GRE.TTL = uint8(parseInt(value))
	case "vxlan.vni":
		m.draft.Spec.VXLAN.VNI = parseInt(value)
	case "vxlan.remote", "vxlan.local":
		address, _ := netip.ParseAddr(value)
		if id == "vxlan.remote" {
			m.draft.Spec.VXLAN.Remote = address
		} else {
			m.draft.Spec.VXLAN.Local = address
		}
	case "vxlan.underlay":
		m.draft.Spec.VXLAN.UnderlayInterface = value
	case "vxlan.port":
		m.draft.Spec.VXLAN.DestinationPort = parseInt(value)
	case "vxlan.addresses":
		m.draft.Spec.VXLAN.Addresses, _ = parsePrefixes(value)
	case "vxlan.mtu":
		m.draft.Spec.VXLAN.MTU = parseInt(value)
	case "wg.addresses":
		workspaceWireGuardSpec(&m.draft).Addresses, _ = parsePrefixes(value)
	case "wg.listen":
		workspaceWireGuardSpec(&m.draft).ListenPort = parseInt(value)
	case "wg.mtu":
		workspaceWireGuardSpec(&m.draft).MTU = parseInt(value)
	case "wg.mark":
		workspaceWireGuardSpec(&m.draft).FirewallMark = parseInt(value)
	case "babel.bandwidth":
		workspaceBabelConfig(&m.draft).BandwidthMbps = parseInt(value)
	case "awg.obfuscation":
		applyAmneziaParameterString(m.draft.Spec.AmneziaWG, value)
	case "xfrm.remote", "xfrm.local":
		address, _ := netip.ParseAddr(value)
		if id == "xfrm.remote" {
			m.draft.Spec.XFRMStatic.Remote = address
		} else {
			m.draft.Spec.XFRMStatic.Local = address
		}
	case "xfrm.underlay":
		m.draft.Spec.XFRMStatic.UnderlayInterface = value
	case "xfrm.addresses":
		m.draft.Spec.XFRMStatic.Addresses, _ = parsePrefixes(value)
	case "xfrm.mtu":
		m.draft.Spec.XFRMStatic.MTU = parseInt(value)
	case "xfrm.spi-in":
		m.draft.Spec.XFRMStatic.SPIInbound = parseUint32(value)
	case "xfrm.spi-out":
		m.draft.Spec.XFRMStatic.SPIOutbound = parseUint32(value)
	case "ike.remote":
		m.draft.Spec.XFRMIKEv2.RemoteAddress = value
	case "ike.local":
		m.draft.Spec.XFRMIKEv2.LocalAddress = value
	case "ike.underlay":
		m.draft.Spec.XFRMIKEv2.UnderlayInterface = value
	case "ike.local-id":
		m.draft.Spec.XFRMIKEv2.LocalID = value
	case "ike.remote-id":
		m.draft.Spec.XFRMIKEv2.RemoteID = value
	case "ike.addresses":
		m.draft.Spec.XFRMIKEv2.Addresses, _ = parsePrefixes(value)
	case "ike.mtu":
		m.draft.Spec.XFRMIKEv2.MTU = parseInt(value)
	case "srv6.underlay":
		m.draft.Spec.SRv6.UnderlayInterface = value
	case "srv6.refresh":
		m.draft.Spec.SRv6.RefreshIntervalSeconds = parseInt(value)
	default:
		return fmt.Errorf("unsupported tunnel field %q", id)
	}
	return nil
}

func (m *manageWorkspaceModel) applyWorkspaceChoice(action, value string) error {
	if strings.HasPrefix(action, "tunnel:") {
		id := strings.TrimPrefix(action, "tunnel:")
		switch id {
		case "wg.routing":
			spec := workspaceWireGuardSpec(&m.draft)
			switch value {
			case "disabled":
				spec.RouteAllowedIPs, spec.RouteTable = false, 0
			case "auto":
				spec.RouteAllowedIPs, spec.RouteTable = true, 0
			case "custom":
				current := spec.RouteTable
				if current == 0 {
					current = 100
				}
				m.beginInput("wg-route-custom", "Custom route table", "AllowedIPs routes will be installed in this table.", workspaceInputStep{
					Label: "Route table (1-2147483647)", Value: strconv.Itoa(current), Validator: validateInt(1, 2147483647),
				})
			}
		case "xfrm.algorithm":
			spec := m.draft.Spec.XFRMStatic
			next := model.XFRMAlgorithm(value)
			if next != spec.Algorithm {
				spec.Algorithm = next
				clearStaticXFRMKeys(spec)
				m.notice = "New XFRM key material will be generated when changes are saved"
			}
		case "ike.auth":
			next := model.IKEAuthMethod(value)
			if next == m.draft.Spec.XFRMIKEv2.AuthMethod {
				return nil
			}
			m.beginIKECredentialInput("switch-" + value)
		case "ike.start":
			m.draft.Spec.XFRMIKEv2.StartAction = value
		default:
			return fmt.Errorf("unsupported choice field %q", id)
		}
		return nil
	}
	switch action {
	case "srv6-source-family":
		family := model.SRv6AddressFamily(value)
		if family != model.SRv6FamilyIPv4 && family != model.SRv6FamilyIPv6 {
			return fmt.Errorf("unsupported SRv6 address family %q", value)
		}
		m.sourceDraft.Family = family
		m.fieldSelected = 0
		m.page = workspaceSource
		m.notice = ""
	case "ike-proposals":
		spec := m.draft.Spec.XFRMIKEv2
		switch value {
		case "recommended":
			spec.IKEProposal, spec.ESPProposal = "aes128gcm16-prfsha256-curve25519", "aes128gcm16"
		case "aes256":
			spec.IKEProposal, spec.ESPProposal = "aes256gcm16-prfsha384-curve25519", "aes256gcm16"
		case "custom":
			m.beginInput("ike-custom-proposals", "Custom proposals", "Enter the strongSwan IKE and ESP proposal strings.",
				workspaceInputStep{Label: "IKE proposal", Value: spec.IKEProposal, Validator: required},
				workspaceInputStep{Label: "ESP proposal", Value: spec.ESPProposal, Validator: required},
			)
		}
	default:
		if strings.HasPrefix(action, "peer:") {
			return m.applyPeerChoice(strings.TrimPrefix(action, "peer:"), value)
		}
		return fmt.Errorf("unsupported choice action %q", action)
	}
	return nil
}

func (m *manageWorkspaceModel) applyWorkspaceConfirm(action string) (tea.Cmd, error) {
	switch action {
	case "save-tunnel":
		m.busy = "Saving and reconciling changes"
		return m.saveTunnel(), nil
	case "discard-tunnel":
		m.page = workspaceTunnel
		m.original, m.draft = model.Tunnel{}, model.Tunnel{}
		m.notice = "Changes discarded"
		m.material = nil
	case "delete-tunnel":
		m.busy = "Deleting tunnel"
		return m.deleteTunnel(), nil
	case "rotate-wg-key":
		spec := workspaceWireGuardSpec(&m.draft)
		spec.PrivateKey, spec.PublicKey = "", ""
		if err := model.GenerateWireGuardCredentials(spec); err != nil {
			return nil, err
		}
		m.material = []string{"New local public key: " + spec.PublicKey}
	case "save-peer", "discard-peer", "remove-peer":
		return m.applyPeerConfirm(action)
	case "save-source", "discard-source", "remove-source":
		return m.applySourceConfirm(action)
	default:
		return nil, fmt.Errorf("unsupported confirmation action %q", action)
	}
	return nil, nil
}

func (m *manageWorkspaceModel) beginStaticKeyInput() {
	spec := m.draft.Spec.XFRMStatic
	encBytes := 20
	if spec.Algorithm == model.XFRMAESCBCSHA256 {
		encBytes = 32
	}
	steps := []workspaceInputStep{
		{Label: "Inbound encryption key", Secret: true, Validator: validateHexInput(encBytes)},
		{Label: "Outbound encryption key", Secret: true, Validator: validateHexInput(encBytes)},
	}
	if spec.Algorithm == model.XFRMAESCBCSHA256 {
		steps = append(steps,
			workspaceInputStep{Label: "Inbound authentication key", Secret: true, Validator: validateHexInput(32)},
			workspaceInputStep{Label: "Outbound authentication key", Secret: true, Validator: validateHexInput(32)},
		)
	}
	m.beginInput("xfrm-keys", "Replace XFRM key material", "All required directions are applied together when the final value is accepted.", steps...)
}

func (m *manageWorkspaceModel) applyStaticKeys(values []string) error {
	spec := m.draft.Spec.XFRMStatic
	if len(values) < 2 {
		return errors.New("both encryption keys are required")
	}
	normalize := func(value string) string { return strings.TrimPrefix(strings.TrimSpace(value), "0x") }
	spec.EncryptionKeyIn, spec.EncryptionKeyOut = normalize(values[0]), normalize(values[1])
	spec.AuthenticationKeyIn, spec.AuthenticationKeyOut = "", ""
	if spec.Algorithm == model.XFRMAESCBCSHA256 {
		if len(values) != 4 {
			return errors.New("both authentication keys are required")
		}
		spec.AuthenticationKeyIn, spec.AuthenticationKeyOut = normalize(values[2]), normalize(values[3])
	}
	m.notice = "Replacement XFRM key material is staged"
	return nil
}

func (m *manageWorkspaceModel) beginIKECredentialInput(mode string) {
	spec := m.draft.Spec.XFRMIKEv2
	auth := spec.AuthMethod
	if strings.HasSuffix(mode, string(model.IKEAuthPSK)) {
		auth = model.IKEAuthPSK
	} else if strings.HasSuffix(mode, string(model.IKEAuthRPK)) {
		auth = model.IKEAuthRPK
	}
	if auth == model.IKEAuthPSK {
		action := "ike-replace-psk"
		if strings.HasPrefix(mode, "switch") {
			action = "ike-switch-psk"
		}
		m.beginInput(action, "Replace pre-shared key", "Leave blank to generate a strong random PSK.", workspaceInputStep{
			Label: "New PSK", Secret: true, Validator: func(value string) error {
				if value != "" && len(value) < 16 {
					return errors.New("PSK must contain at least 16 bytes")
				}
				return nil
			},
		})
		return
	}
	action := "ike-replace-rpk"
	if strings.HasPrefix(mode, "switch") {
		action = "ike-switch-rpk"
	}
	m.beginInput(action, "Replace raw public-key credentials", "A new local key pair will be generated; enter the peer's public key.", workspaceInputStep{
		Label: "Remote raw public key", Value: spec.RemotePublicKey, Validator: validateRPKInput,
	})
}

func (m *manageWorkspaceModel) applyIKEPSK(value string) error {
	spec := m.draft.Spec.XFRMIKEv2
	clearIKECredentials(spec)
	spec.AuthMethod = model.IKEAuthPSK
	spec.PSK = value
	if err := model.GenerateIKECredentials(spec); err != nil {
		return err
	}
	m.material = []string{"New PSK: " + spec.PSK}
	return nil
}

func (m *manageWorkspaceModel) applyIKERPK(value string) error {
	remote, err := normalizeRPK(value)
	if err != nil {
		return err
	}
	spec := m.draft.Spec.XFRMIKEv2
	clearIKECredentials(spec)
	spec.AuthMethod = model.IKEAuthRPK
	if err := model.GenerateIKECredentials(spec); err != nil {
		return err
	}
	spec.RemotePublicKey = remote
	m.material = []string{"New local raw public key: " + spec.LocalPublicKey}
	return nil
}

func workspaceWireGuardSpec(tunnel *model.Tunnel) *model.WireGuardSpec {
	if tunnel.Kind == model.KindWireGuard {
		return tunnel.Spec.WireGuard
	}
	return &tunnel.Spec.AmneziaWG.WireGuardSpec
}

func workspaceRoutingValue(spec *model.WireGuardSpec) string {
	if !spec.RouteAllowedIPs {
		return "disabled"
	}
	if spec.RouteTable == 0 {
		return "automatic"
	}
	return fmt.Sprintf("table %d", spec.RouteTable)
}

func workspaceRoutingSelection(spec *model.WireGuardSpec) int {
	if !spec.RouteAllowedIPs {
		return 0
	}
	if spec.RouteTable == 0 {
		return 1
	}
	return 2
}

func workspaceStringSelection(value string, values []string) int {
	for index := range values {
		if values[index] == value {
			return index
		}
	}
	return 0
}

func workspaceStaticKeyState(spec *model.XFRMStaticSpec) string {
	if spec.EncryptionKeyIn != "" || spec.EncryptionKeyOut != "" {
		return "replacement staged"
	}
	return "managed (replace)"
}

func workspacePairingMaterial(tunnel model.Tunnel, generatedReplacement bool) []string {
	switch tunnel.Kind {
	case model.KindWireGuard, model.KindAmneziaWG:
		spec := workspaceWireGuardSpec(&tunnel)
		if spec.PrivateKey != "" {
			return []string{"Local public key: " + spec.PublicKey}
		}
	case model.KindXFRMStatic:
		spec := tunnel.Spec.XFRMStatic
		if generatedReplacement || spec.EncryptionKeyIn != "" || spec.EncryptionKeyOut != "" {
			lines := []string{
				fmt.Sprintf("Local SPI pair: 0x%x,0x%x", spec.SPIInbound, spec.SPIOutbound),
				"Local encryption keys: " + spec.EncryptionKeyIn + "," + spec.EncryptionKeyOut,
				fmt.Sprintf("Peer SPI pair: 0x%x,0x%x", spec.SPIOutbound, spec.SPIInbound),
				"Peer encryption keys: " + spec.EncryptionKeyOut + "," + spec.EncryptionKeyIn,
			}
			if spec.AuthenticationKeyIn != "" {
				lines = append(lines,
					"Local authentication keys: "+spec.AuthenticationKeyIn+","+spec.AuthenticationKeyOut,
					"Peer authentication keys: "+spec.AuthenticationKeyOut+","+spec.AuthenticationKeyIn,
				)
			}
			return lines
		}
	case model.KindXFRMIKEv2:
		spec := tunnel.Spec.XFRMIKEv2
		if spec.PSK != "" {
			return []string{"PSK: " + spec.PSK}
		}
		if spec.LocalPrivateKey != "" {
			return []string{"Local raw public key: " + spec.LocalPublicKey}
		}
	}
	return nil
}
