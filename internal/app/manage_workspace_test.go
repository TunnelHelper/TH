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

	"github.com/TunnelHelper/TH/internal/control"
	"github.com/TunnelHelper/TH/internal/model"
	tea "github.com/charmbracelet/bubbletea"
	ansi "github.com/charmbracelet/x/ansi"
)

func TestWorkspaceFieldsCoverEveryTunnelKind(t *testing.T) {
	tests := []struct {
		tunnel model.Tunnel
		ids    []string
	}{
		{workspaceTestTunnel(model.KindGRE), []string{"name", "gre.remote", "gre.local", "gre.addresses", "gre.mtu", "gre.ttl"}},
		{workspaceTestTunnel(model.KindVXLAN), []string{"name", "vxlan.vni", "vxlan.underlay", "vxlan.learning", "vxlan.addresses"}},
		{workspaceTestTunnel(model.KindWireGuard), []string{"name", "wg.addresses", "wg.listen", "wg.peers", "wg.routing", "wg.rotate"}},
		{workspaceTestTunnel(model.KindAmneziaWG), []string{"name", "wg.peers", "wg.routing", "wg.rotate", "awg.obfuscation"}},
		{workspaceTestTunnel(model.KindXFRMStatic), []string{"name", "xfrm.spi-in", "xfrm.algorithm", "xfrm.keys"}},
		{workspaceTestTunnel(model.KindXFRMIKEv2), []string{"name", "ike.auth", "ike.auth-material", "ike.proposals", "ike.encapsulation", "ike.start"}},
		{workspaceTestTunnel(model.KindSRv6), []string{"name", "srv6.underlay", "srv6.refresh", "srv6.sources"}},
	}
	for _, test := range tests {
		t.Run(string(test.tunnel.Kind), func(t *testing.T) {
			fields := workspaceTunnelFields(test.tunnel)
			for _, id := range test.ids {
				if workspaceFieldIndex(fields, id) == 0 && id != "name" {
					t.Fatalf("field %q is missing from %#v", id, fields)
				}
			}
		})
	}
}

func TestWorkspaceBabelFields(t *testing.T) {
	for _, kind := range []model.Kind{model.KindGRE, model.KindVXLAN, model.KindWireGuard, model.KindAmneziaWG, model.KindXFRMStatic, model.KindXFRMIKEv2} {
		t.Run(string(kind), func(t *testing.T) {
			fields := workspaceTunnelFields(workspaceTestTunnel(kind))
			if workspaceFieldIndex(fields, "babel.enabled") == 0 || workspaceFieldIndex(fields, "babel.balance") == 0 || workspaceFieldIndex(fields, "babel.bandwidth") == 0 {
				t.Fatalf("babel fields are missing for %s: %+v", kind, fields)
			}
		})
	}
	fields := workspaceTunnelFields(workspaceTestTunnel(model.KindSRv6))
	if workspaceFieldIndex(fields, "babel.enabled") != 0 {
		t.Fatalf("SRv6 must not expose Babel fields: %+v", fields)
	}

	editor := manageWorkspaceModel{draft: workspaceTestTunnel(model.KindWireGuard)}
	if err := editor.applyTunnelInput("babel.bandwidth", "500"); err != nil {
		t.Fatal(err)
	}
	if editor.draft.Spec.Babel == nil || editor.draft.Spec.Babel.BandwidthMbps != 500 {
		t.Fatalf("bandwidth was not applied: %+v", editor.draft.Spec.Babel)
	}
	if err := editor.applyTunnelInput("babel.balance", "1.5"); err != nil {
		t.Fatal(err)
	}
	if editor.draft.Spec.Babel.Balance == nil || *editor.draft.Spec.Babel.Balance != 1.5 {
		t.Fatalf("balance was not applied: %+v", editor.draft.Spec.Babel.Balance)
	}
	if err := editor.applyTunnelInput("babel.balance", "9"); err == nil {
		t.Fatal("balance outside [-2, 2] must be rejected")
	}
	if err := editor.toggleWorkspaceField("babel.enabled"); err != nil {
		t.Fatal(err)
	}
	if editor.draft.Spec.Babel == nil || !editor.draft.Spec.Babel.Enabled {
		t.Fatal("babel enabled toggle did not take effect")
	}
	if editor.draft.Spec.Babel.Multicast == nil || *editor.draft.Spec.Babel.Multicast {
		t.Fatal("peerless WireGuard must fall back to unicast Babel mode")
	}
	if !strings.Contains(editor.notice, "unicast") {
		t.Fatalf("toggle must explain the unicast fallback, notice = %q", editor.notice)
	}
}

func TestWorkspaceMptcpEndpointChoice(t *testing.T) {
	for _, kind := range []model.Kind{model.KindGRE, model.KindVXLAN, model.KindWireGuard, model.KindAmneziaWG, model.KindXFRMStatic, model.KindXFRMIKEv2} {
		t.Run(string(kind), func(t *testing.T) {
			fields := workspaceTunnelFields(workspaceTestTunnel(kind))
			index := workspaceFieldIndex(fields, "mptcp.endpoint")
			if index == 0 {
				t.Fatalf("mptcp.endpoint is missing for %s: %+v", kind, fields)
			}
			if fields[index].Value != "Follow global" {
				t.Fatalf("default MPTCP endpoint state = %q, want Follow global", fields[index].Value)
			}
		})
	}
	fields := workspaceTunnelFields(workspaceTestTunnel(model.KindSRv6))
	if workspaceFieldIndex(fields, "mptcp.endpoint") != 0 {
		t.Fatalf("SRv6 must not expose MPTCP fields: %+v", fields)
	}

	editor := manageWorkspaceModel{draft: workspaceTestTunnel(model.KindWireGuard)}
	if err := editor.applyWorkspaceChoice("tunnel:mptcp.endpoint", "on"); err != nil {
		t.Fatal(err)
	}
	if editor.draft.Spec.Mptcp == nil || editor.draft.Spec.Mptcp.Endpoint == nil || !*editor.draft.Spec.Mptcp.Endpoint {
		t.Fatalf("On choice was not applied: %+v", editor.draft.Spec.Mptcp)
	}
	if err := editor.applyWorkspaceChoice("tunnel:mptcp.endpoint", "off"); err != nil {
		t.Fatal(err)
	}
	if editor.draft.Spec.Mptcp == nil || editor.draft.Spec.Mptcp.Endpoint == nil || *editor.draft.Spec.Mptcp.Endpoint {
		t.Fatalf("Off choice was not applied: %+v", editor.draft.Spec.Mptcp)
	}
	if err := editor.applyWorkspaceChoice("tunnel:mptcp.endpoint", "follow"); err != nil {
		t.Fatal(err)
	}
	if editor.draft.Spec.Mptcp != nil {
		t.Fatalf("Follow choice must clear the section, got %+v", editor.draft.Spec.Mptcp)
	}
}

func TestWorkspaceEditorChangesScroll(t *testing.T) {
	before := workspaceTestTunnel(model.KindWireGuard)
	after, err := model.Clone(before)
	if err != nil {
		t.Fatal(err)
	}
	after.Name = before.Name + "-renamed"
	after.Spec.WireGuard.ListenPort = 51821
	after.Spec.WireGuard.MTU = 1400
	after.Spec.WireGuard.FirewallMark = 7
	after.Spec.WireGuard.RouteTable = 200
	after.Spec.WireGuard.Addresses = []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")}
	after.Spec.Babel = &model.BabelTunnelConfig{Enabled: true, BandwidthMbps: 100}
	balance := 1.5
	after.Spec.Babel.Balance = &balance
	changes := workspaceTunnelChanges(before, after)
	if len(changes) < 9 {
		t.Fatalf("fixture must produce several changes, got %+v", changes)
	}

	editor := manageWorkspaceModel{
		page: workspaceEdit, original: before, draft: after,
		fieldSelected: len(workspaceTunnelFields(after)) - 1,
		width:         120, height: 40,
	}
	updated, _ := editor.updateTunnelEditor(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("j")})
	editor = updated.(manageWorkspaceModel)
	if !editor.changesFocus {
		t.Fatal("down on the last field must move focus to the pending changes")
	}

	updated, _ = editor.updateTunnelEditor(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("j")})
	editor = updated.(manageWorkspaceModel)
	if editor.changeSelected != 1 {
		t.Fatalf("down must scroll into the changes, selected = %d", editor.changeSelected)
	}
	view := editor.tunnelEditorView(120)
	if !strings.Contains(view, "Pending changes") {
		t.Fatalf("changes view must render the pending changes:\n%s", view)
	}
	if strings.Contains(view, "↑/↓ to scroll") || strings.Contains(view, "more change") {
		t.Fatalf("changes must render in full without a scroll window:\n%s", view)
	}

	// Up at the top of the changes returns to the fields.
	updated, _ = editor.updateTunnelEditor(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("k")})
	editor = updated.(manageWorkspaceModel)
	updated, _ = editor.updateTunnelEditor(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("k")})
	editor = updated.(manageWorkspaceModel)
	if editor.changesFocus || editor.changeSelected != 0 {
		t.Fatalf("up at the top of changes must return to fields: focus=%t selected=%d", editor.changesFocus, editor.changeSelected)
	}
}

func TestWorkspaceEditPreparesLegacyNameMigration(t *testing.T) {
	legacy := workspaceTestTunnel(model.KindXFRMIKEv2)
	legacy.Name = "rfc-tyo"
	legacy.Interface = "ipsec-rfc-tyo"
	workspace := newManageWorkspaceModel(context.Background(), nil, time.Second, "")
	workspace.view = model.TunnelView{Tunnel: legacy}

	if err := workspace.beginTunnelEdit(); err != nil {
		t.Fatal(err)
	}
	if workspace.original.Name != "rfc-tyo" || workspace.draft.Name != "ipsec-rfc-tyo" {
		t.Fatalf("legacy name migration = original %q, draft %q", workspace.original.Name, workspace.draft.Name)
	}
	if workspace.draft.Interface != legacy.Interface {
		t.Fatalf("migration changed interface to %q", workspace.draft.Interface)
	}
}

func TestWorkspaceViewShowsBreadcrumbDirtyStateAndDiff(t *testing.T) {
	tunnel := workspaceTestTunnel(model.KindGRE)
	m := newManageWorkspaceModel(context.Background(), nil, time.Second, "")
	m.page = workspaceEdit
	m.view = model.TunnelView{Tunnel: tunnel}
	m.original = tunnel
	m.draft = tunnel
	m.draft.Name = "renamed"
	m.width, m.height = 120, 30

	view := m.View()
	for _, expected := range []string{"TH / Manage / gre-test / Edit", "Unsaved", "Pending changes", "gre-test -> renamed"} {
		if !strings.Contains(view, expected) {
			t.Fatalf("workspace view does not contain %q:\n%s", expected, view)
		}
	}
	if strings.Contains(view, "│") {
		t.Fatalf("wide editor unexpectedly rendered a split-pane divider:\n%s", view)
	}
}

func TestWorkspaceDiffNeverRendersSecretValues(t *testing.T) {
	before := workspaceTestTunnel(model.KindWireGuard)
	after := before
	after.Spec.WireGuard = cloneWireGuardSpec(before.Spec.WireGuard)
	after.Spec.WireGuard.PrivateKey = "private-key-must-not-appear"
	after.Spec.WireGuard.Peers = []model.WireGuardPeer{{
		PublicKey: "peer", PresharedKey: "preshared-key-must-not-appear",
	}}
	changes := workspaceTunnelChanges(before, after)
	rendered := strings.Join(workspaceDiffLines(changes, 200, 20), "\n")
	for _, secret := range []string{"private-key-must-not-appear", "preshared-key-must-not-appear"} {
		if strings.Contains(rendered, secret) {
			t.Fatalf("secret %q leaked in diff:\n%s", secret, rendered)
		}
	}
	for _, expected := range []string{"Private key", "Preshared key", "replace"} {
		if !strings.Contains(strings.ToLower(rendered), strings.ToLower(expected)) {
			t.Fatalf("redacted diff does not explain %q:\n%s", expected, rendered)
		}
	}
}

func TestWorkspaceConfirmationUsesSharedButtonsAndDefaultsToCancel(t *testing.T) {
	m := newManageWorkspaceModel(context.Background(), nil, time.Second, "")
	m.width = 80
	m.beginConfirm("delete-tunnel", "Delete tunnel", "Remove managed state?", "Delete tunnel", "Cancel", true)
	if m.overlay.Selected != 1 {
		t.Fatalf("destructive confirmation selected button = %d, want Cancel", m.overlay.Selected)
	}
	view := m.overlayView(80)
	for _, expected := range []string{"[ Delete tunnel ]", "[ Cancel ]", "arrows/tab"} {
		if !strings.Contains(view, expected) {
			t.Fatalf("shared confirmation does not contain %q:\n%s", expected, view)
		}
	}
	if buttons := renderWorkspaceButtons(m.overlay.Buttons, m.overlay.Selected, 80); strings.Contains(buttons, "\n") {
		t.Fatalf("two confirmation buttons should stay horizontal at this width: %q", buttons)
	}
}

func TestPeerEditorStagesChangesOnlyAfterSave(t *testing.T) {
	tunnel := workspaceTestTunnel(model.KindWireGuard)
	originalPeer := model.WireGuardPeer{PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", Endpoint: "old.example:51820"}
	tunnel.Spec.WireGuard.Peers = []model.WireGuardPeer{originalPeer}
	m := newManageWorkspaceModel(context.Background(), nil, time.Second, "")
	m.draft = tunnel
	m.page = workspacePeer
	m.peerIndex = 0
	m.peerOriginal = originalPeer
	m.peerDraft = originalPeer

	if err := m.applyPeerInput("endpoint", []string{"new.example"}); err != nil {
		t.Fatal(err)
	}
	if got := m.draft.Spec.WireGuard.Peers[0].Endpoint; got != originalPeer.Endpoint {
		t.Fatalf("main draft changed before peer Save: %q", got)
	}
	if _, err := m.applyPeerConfirm("save-peer"); err != nil {
		t.Fatal(err)
	}
	if got := m.draft.Spec.WireGuard.Peers[0].Endpoint; got != "new.example:51820" {
		t.Fatalf("saved endpoint = %q", got)
	}
}

func TestSRv6SourceEditorPreservesRequiredLastSource(t *testing.T) {
	tunnel := workspaceTestTunnel(model.KindSRv6)
	m := newManageWorkspaceModel(context.Background(), nil, time.Second, "")
	m.draft = tunnel
	m.page = workspaceSource
	m.sourceIndex = 0
	m.sourceOriginal = tunnel.Spec.SRv6.Sources[0]
	m.sourceDraft = tunnel.Spec.SRv6.Sources[0]

	if _, err := m.applySourceConfirm("remove-source"); err == nil {
		t.Fatal("last SRv6 source was removed")
	}
	if len(m.draft.Spec.SRv6.Sources) != 1 {
		t.Fatalf("source count = %d", len(m.draft.Spec.SRv6.Sources))
	}
}

func TestSRv6SourceAddChoosesSingleAddressFamily(t *testing.T) {
	tunnel := workspaceTestTunnel(model.KindSRv6)
	m := newManageWorkspaceModel(context.Background(), nil, time.Second, "")
	m.draft = tunnel
	m.page = workspaceSources
	m.beginSourceAdd(tunnel.Spec.SRv6.Sources)

	if m.overlay == nil || m.overlay.Action != "srv6-source-family" {
		t.Fatalf("new source did not open the address family choice: %+v", m.overlay)
	}
	if m.sourceDraft.Family != "" || m.page != workspaceSources {
		t.Fatalf("source editor opened before choosing a family: %+v", m.sourceDraft)
	}
	m.overlay = nil
	if err := m.applyWorkspaceChoice("srv6-source-family", string(model.SRv6FamilyIPv6)); err != nil {
		t.Fatal(err)
	}
	if m.sourceDraft.Family != model.SRv6FamilyIPv6 || m.sourceDraft.Priority != 101 || m.page != workspaceSource {
		t.Fatalf("chosen source defaults were not applied: %+v, page=%d", m.sourceDraft, m.page)
	}
	fields := workspaceSourceFields(m.sourceDraft)
	for _, id := range []string{"name", "url", "priority", "sid", "mtu"} {
		found := false
		for _, field := range fields {
			found = found || field.ID == id
		}
		if !found {
			t.Fatalf("field %q missing from %+v", id, fields)
		}
	}
	if err := m.validateSourceDraft(); err == nil {
		t.Fatal("source without a prefix URL and SID was accepted")
	}
	if err := m.applySourceInput("url", []string{"https://routes.example/custom-v6.txt"}); err != nil {
		t.Fatal(err)
	}
	if err := m.applySourceInput("sid", []string{"2001:db8::2"}); err != nil {
		t.Fatal(err)
	}
	if err := m.validateSourceDraft(); err != nil {
		t.Fatalf("complete source draft was rejected: %v", err)
	}
	if crumb := workspaceSourceCrumb(m.sourceDraft, true); !strings.Contains(crumb, "IPv6") {
		t.Fatalf("source editor does not identify the fixed family: %q", crumb)
	}
}

func TestWorkspaceIKECredentialDiffIsRedacted(t *testing.T) {
	tunnel := workspaceTestTunnel(model.KindXFRMIKEv2)
	m := newManageWorkspaceModel(context.Background(), nil, time.Second, "")
	m.original, m.draft = tunnel, tunnel
	m.draft.Spec.XFRMIKEv2 = cloneIKESpec(tunnel.Spec.XFRMIKEv2)
	if err := m.applyIKEPSK(""); err != nil {
		t.Fatal(err)
	}
	if m.draft.Spec.XFRMIKEv2.PSK == "" || len(m.material) == 0 {
		t.Fatal("generated PSK and operator material were not retained")
	}
	secret := m.draft.Spec.XFRMIKEv2.PSK
	rendered := strings.Join(workspaceDiffLines(workspaceTunnelChanges(m.original, m.draft), 200, 20), "\n")
	if strings.Contains(rendered, secret) {
		t.Fatalf("generated PSK leaked in diff:\n%s", rendered)
	}
}

func TestWorkspaceViewsRespectTerminalWidth(t *testing.T) {
	gre := workspaceTestTunnel(model.KindGRE)
	gre.Name = strings.Repeat("long-name-", 6)
	greView := model.TunnelView{Tunnel: gre, Status: model.Status{
		Phase: model.PhaseReady,
		Details: map[string]string{
			"ipv6_link_local": "fe80::1234:5678:90ab:cdef/64",
			"diagnostic":      strings.Repeat("long status detail ", 8),
		},
		Conditions: []model.Condition{{Message: strings.Repeat("condition message ", 8)}},
	}}
	wg := workspaceTestTunnel(model.KindWireGuard)
	wg.Spec.WireGuard.Peers = []model.WireGuardPeer{{PublicKey: strings.Repeat("A", 43) + "=", Endpoint: "very-long-peer.example.test:51820"}}
	srv6 := workspaceTestTunnel(model.KindSRv6)

	for _, width := range []int{24, 40, 72, 120} {
		models := []manageWorkspaceModel{
			{page: workspaceTunnels, views: []model.TunnelView{greView}, width: width, height: 40},
			{page: workspaceTunnel, view: greView, width: width, height: 40},
			{page: workspaceEdit, view: greView, original: gre, draft: func() model.Tunnel { changed := gre; changed.Name = "changed-name"; return changed }(), width: width, height: 40},
			{page: workspacePeers, view: model.TunnelView{Tunnel: wg}, draft: wg, width: width, height: 40},
			{page: workspacePeer, view: model.TunnelView{Tunnel: wg}, draft: wg, peerDraft: wg.Spec.WireGuard.Peers[0], peerOriginal: wg.Spec.WireGuard.Peers[0], width: width, height: 40},
			{page: workspaceSources, view: model.TunnelView{Tunnel: srv6}, draft: srv6, width: width, height: 40},
			{page: workspaceSource, view: model.TunnelView{Tunnel: srv6}, draft: srv6, sourceDraft: srv6.Spec.SRv6.Sources[0], sourceOriginal: srv6.Spec.SRv6.Sources[0], width: width, height: 40},
		}
		models[2].beginConfirm("discard-tunnel", "Unsaved changes", strings.Repeat("long confirmation text ", 8), "Discard changes", "Keep editing", true)
		for index, workspace := range models {
			for lineNumber, line := range strings.Split(workspace.View(), "\n") {
				if got := ansi.StringWidth(line); got > width {
					t.Fatalf("width %d model %d line %d is %d cells:\n%s", width, index, lineNumber+1, got, line)
				}
			}
		}
	}
}

func TestWorkspaceSavePreservesGenerationAndGeneratesReplacementSecrets(t *testing.T) {
	type updateEnvelope struct {
		Generation uint64       `json:"generation"`
		Tunnel     model.Tunnel `json:"tunnel"`
	}
	var (
		lock       sync.Mutex
		updateBody updateEnvelope
		response   model.TunnelView
	)
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /v1/tunnels/{id}", func(writer http.ResponseWriter, request *http.Request) {
		var body updateEnvelope
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		responseTunnel := body.Tunnel
		responseTunnel.Generation++
		redacted, fields := model.Redact(responseTunnel)
		view := model.TunnelView{Tunnel: redacted, SecretFields: fields, Status: model.Status{Phase: model.PhasePending}}
		lock.Lock()
		updateBody, response = body, view
		lock.Unlock()
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(view)
	})
	mux.HandleFunc("POST /v1/tunnels/{id}/reconcile", func(writer http.ResponseWriter, _ *http.Request) {
		lock.Lock()
		view := response
		lock.Unlock()
		view.Status.Phase = model.PhaseReady
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(view)
	})

	socketPath := filepath.Join(t.TempDir(), "th.sock")
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

	current := workspaceTestTunnel(model.KindXFRMStatic)
	next, err := model.Clone(current)
	if err != nil {
		t.Fatal(err)
	}
	next.Spec.XFRMStatic.Algorithm = model.XFRMAESCBCSHA256
	clearStaticXFRMKeys(next.Spec.XFRMStatic)
	client := control.NewClient(socketPath, time.Second)
	t.Cleanup(client.CloseIdleConnections)
	workspace := newManageWorkspaceModel(context.Background(), client, time.Second, "")
	workspace.original, workspace.draft = current, next

	message, ok := workspace.saveTunnel()().(workspaceMutationMsg)
	if !ok {
		t.Fatalf("save returned %T", message)
	}
	if message.err != nil {
		t.Fatal(message.err)
	}
	lock.Lock()
	request := updateBody
	lock.Unlock()
	if request.Generation != current.Generation {
		t.Fatalf("precondition generation = %d, want %d", request.Generation, current.Generation)
	}
	if request.Tunnel.Generation != current.Generation {
		t.Fatalf("request tunnel generation = %d, want current %d", request.Tunnel.Generation, current.Generation)
	}
	static := request.Tunnel.Spec.XFRMStatic
	if len(static.EncryptionKeyIn) != 64 || len(static.EncryptionKeyOut) != 64 || len(static.AuthenticationKeyIn) != 64 || len(static.AuthenticationKeyOut) != 64 {
		t.Fatalf("replacement keys were not generated: %+v", static)
	}
	if message.view.Status.Phase != model.PhaseReady || len(message.material) == 0 {
		t.Fatalf("save result = %+v, material = %#v", message.view.Status, message.material)
	}
}

func TestWorkspaceKeepsPairingMaterialAndActionsVisible(t *testing.T) {
	tunnel := workspaceTestTunnel(model.KindXFRMStatic)
	details := make(map[string]string, 30)
	for index := 0; index < 30; index++ {
		details["detail_"+strings.Repeat("x", index%5)+string(rune('a'+index))] = strings.Repeat("value", 8)
	}
	workspace := newManageWorkspaceModel(context.Background(), nil, time.Second, "")
	workspace.page = workspaceTunnel
	workspace.view = model.TunnelView{Tunnel: tunnel, Status: model.Status{Phase: model.PhaseReady, Details: details}}
	workspace.material = []string{"material-1", "material-2", "material-3", "material-4", "material-5", "material-6"}
	workspace.notice = "Saved tunnel"
	workspace.width, workspace.height = 72, 24

	view := workspace.View()
	for _, expected := range []string{"New pairing material", "material-1", "material-6", "e  Edit", "esc  Back"} {
		if !strings.Contains(view, expected) {
			t.Fatalf("priority content %q was clipped:\n%s", expected, view)
		}
	}
}

func workspaceTestTunnel(kind model.Kind) model.Tunnel {
	tunnel := model.Tunnel{
		SchemaVersion: model.SchemaVersion,
		ID:            "00000000-0000-4000-8000-000000000001",
		Generation:    3,
		Name:          string(kind) + "-test",
		Kind:          kind,
		Interface:     "test0",
		Enabled:       true,
		CreatedAt:     time.Unix(1, 0).UTC(),
		UpdatedAt:     time.Unix(2, 0).UTC(),
	}
	local := netip.MustParseAddr("192.0.2.1")
	remote := netip.MustParseAddr("192.0.2.2")
	addresses := []netip.Prefix{netip.MustParsePrefix("10.0.0.1/30")}
	switch kind {
	case model.KindGRE:
		tunnel.Name = "gre-test"
		tunnel.Spec.GRE = &model.GRESpec{Local: local, Remote: remote, Addresses: addresses, MTU: 1450, TTL: 255}
	case model.KindVXLAN:
		tunnel.Spec.VXLAN = &model.VXLANSpec{VNI: 100, UnderlayInterface: "eth0", Local: local, Remote: remote, DestinationPort: 4789, Learning: true, Addresses: addresses, MTU: 1450}
	case model.KindWireGuard:
		tunnel.Spec.WireGuard = &model.WireGuardSpec{PublicKey: "public", MTU: 1420, RouteAllowedIPs: true}
	case model.KindAmneziaWG:
		tunnel.Spec.AmneziaWG = &model.AmneziaWGSpec{
			WireGuardSpec:   model.WireGuardSpec{PublicKey: "public", MTU: 1420},
			JunkPacketCount: 4, JunkPacketMinSize: 40, JunkPacketMaxSize: 1200,
			InitPacketJunkSize: 10, ResponsePacketJunkSize: 20,
			InitMagicHeader: "1", ResponseMagicHeader: "2", UnderloadMagicHeader: "3", TransportMagicHeader: "4",
		}
	case model.KindXFRMStatic:
		tunnel.Spec.XFRMStatic = &model.XFRMStaticSpec{UnderlayInterface: "eth0", Local: local, Remote: remote, Addresses: addresses, MTU: 1400, SPIInbound: 0x101, SPIOutbound: 0x102, Algorithm: model.XFRMAESGCM}
	case model.KindXFRMIKEv2:
		tunnel.Spec.XFRMIKEv2 = &model.XFRMIKEv2Spec{UnderlayInterface: "eth0", LocalAddress: local.String(), RemoteAddress: remote.String(), LocalID: "local", RemoteID: "remote", Addresses: addresses, MTU: 1400, AuthMethod: model.IKEAuthPSK, IKEProposal: "aes128gcm16-prfsha256-curve25519", ESPProposal: "aes128gcm16", StartAction: "trap"}
	case model.KindSRv6:
		tunnel.Interface = ""
		sid := netip.MustParseAddr("2001:db8::1")
		tunnel.Spec.SRv6 = &model.SRv6Spec{UnderlayInterface: "eth0", Table: 100, RulePriority: 20000, RefreshIntervalSeconds: 300, Sources: []model.SRv6Source{{Name: "source1", Family: model.SRv6FamilyIPv4, PrefixURL: "https://example.test/edge-v4.txt", SID: sid, Priority: 100, MTU: 1500}}}
	}
	return tunnel
}

func cloneWireGuardSpec(spec *model.WireGuardSpec) *model.WireGuardSpec {
	copy := *spec
	copy.Peers = append([]model.WireGuardPeer(nil), spec.Peers...)
	return &copy
}

func cloneIKESpec(spec *model.XFRMIKEv2Spec) *model.XFRMIKEv2Spec {
	copy := *spec
	return &copy
}
