package app

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"

	"github.com/TunnelHelper/TH/internal/model"
	"github.com/TunnelHelper/TH/internal/ui"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestCreateFormDefersEnableChoiceUntilReview(t *testing.T) {
	prompts, output := transcriptPrompts("\n\n\n\n\n2\n1\n2\n1\n")
	record, err := collectTunnel(prompts, model.KindWireGuard, nil, "ux-wg", nil)
	if err != nil {
		t.Fatal(err)
	}
	transcript := output.String()
	if strings.Contains(transcript, "Enabled") || strings.Contains(transcript, "Create and enable") {
		t.Fatalf("configuration form asked about activation too early:\n%s", transcript)
	}
	if !record.Enabled {
		t.Fatal("new record did not retain the internal enabled default")
	}
	if record.Name != "wg-ux-wg" || record.Interface != "wg-ux-wg" {
		t.Fatalf("new tunnel identity = name %q, interface %q; want both wg-ux-wg", record.Name, record.Interface)
	}
	options := createActionOptions()
	if len(options) != 3 || options[0].Value != "enable" || options[1].Value != "disable" || options[2].Value != "back" {
		t.Fatalf("final create choices = %+v", options)
	}
}

func TestWireGuardShowsLocalKeyBeforePeerPrompt(t *testing.T) {
	prompts, output := transcriptPrompts("\n\n\n\n\n2\n1\n2\n1\n")
	if _, err := collectTunnel(prompts, model.KindWireGuard, nil, "ux-key-order", nil); err != nil {
		t.Fatal(err)
	}
	transcript := output.String()
	local := strings.Index(transcript, "Local public key:")
	peers := strings.Index(transcript, "Peers")
	if local < 0 || peers < 0 || local >= peers {
		t.Fatalf("local key was not shown before peer collection:\n%s", transcript)
	}
}

func TestCreateFormCollectsBabelToggle(t *testing.T) {
	prompts, output := transcriptPrompts("\n\n\n\n\n2\n1\n1\n250\n1\n")
	record, err := collectTunnel(prompts, model.KindWireGuard, nil, "ux-babel", nil)
	if err != nil {
		t.Fatal(err)
	}
	if record.Spec.Babel == nil || !record.Spec.Babel.Enabled || record.Spec.Babel.BandwidthMbps != 250 {
		t.Fatalf("Babel toggle was not collected: %+v", record.Spec.Babel)
	}
	if !strings.Contains(output.String(), "Babel routing") {
		t.Fatalf("create form did not ask about Babel:\n%s", output.String())
	}
}

func TestCollectBabelUnicastFallback(t *testing.T) {
	prompts, output := transcriptPrompts("1\n250\n")
	record := model.Tunnel{
		Kind: model.KindWireGuard,
		Spec: model.Spec{
			WireGuard: &model.WireGuardSpec{
				Peers: []model.WireGuardPeer{{
					PublicKey:  "peer",
					AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32")},
				}},
			},
		},
	}
	if err := collectBabelTunnelConfig(prompts, &record); err != nil {
		t.Fatal(err)
	}
	if record.Spec.Babel == nil || !record.Spec.Babel.Enabled {
		t.Fatal("Babel must be enabled")
	}
	if record.Spec.Babel.Multicast == nil || *record.Spec.Babel.Multicast {
		t.Fatalf("narrow AllowedIPs must select unicast mode, got %v", record.Spec.Babel.Multicast)
	}
	if record.Spec.Babel.BandwidthMbps != 250 {
		t.Fatalf("bandwidth = %d, want 250", record.Spec.Babel.BandwidthMbps)
	}
	if !strings.Contains(output.String(), "unicast") {
		t.Fatalf("wizard must explain the unicast fallback:\n%s", output.String())
	}
}

func TestCreateFormCollectsMptcpToggle(t *testing.T) {
	prompts, output := transcriptPrompts("2\n2\n") // Babel Off, then MPTCP On
	record := model.Tunnel{
		Kind: model.KindGRE,
		Spec: model.Spec{GRE: &model.GRESpec{}},
	}
	if err := collectBabelTunnelConfig(prompts, &record); err != nil {
		t.Fatal(err)
	}
	if err := collectMptcpTunnelConfig(prompts, &record); err != nil {
		t.Fatal(err)
	}
	if record.Spec.Mptcp == nil || record.Spec.Mptcp.Endpoint == nil || !*record.Spec.Mptcp.Endpoint {
		t.Fatalf("MPTCP endpoint was not collected: %+v", record.Spec.Mptcp)
	}
	if !strings.Contains(output.String(), "MPTCP endpoint") {
		t.Fatalf("create form did not ask about MPTCP:\n%s", output.String())
	}
}

func TestCollectMptcpOffAndFollowGlobal(t *testing.T) {
	record := model.Tunnel{Kind: model.KindGRE, Spec: model.Spec{GRE: &model.GRESpec{}}}
	prompts, _ := transcriptPrompts("3\n") // Off
	if err := collectMptcpTunnelConfig(prompts, &record); err != nil {
		t.Fatal(err)
	}
	if record.Spec.Mptcp == nil || record.Spec.Mptcp.Endpoint == nil || *record.Spec.Mptcp.Endpoint {
		t.Fatalf("Off must set endpoint=false, got %+v", record.Spec.Mptcp)
	}

	record = model.Tunnel{Kind: model.KindGRE, Spec: model.Spec{GRE: &model.GRESpec{}}}
	prompts, _ = transcriptPrompts("1\n") // Follow global
	if err := collectMptcpTunnelConfig(prompts, &record); err != nil {
		t.Fatal(err)
	}
	if record.Spec.Mptcp != nil {
		t.Fatalf("Follow global must leave the MPTCP section empty, got %+v", record.Spec.Mptcp)
	}
}

func TestAmneziaShowsObfuscationAndLocalKeyBeforePeerPrompt(t *testing.T) {
	prompts, output := transcriptPrompts("\n\n\n\n2\n4,40,1200,10,20,1,2,3,4\n2\n1\n")
	record := model.Tunnel{}
	if err := collectAmneziaWG(prompts, &record); err != nil {
		t.Fatal(err)
	}
	transcript := output.String()
	obfuscation := strings.Index(transcript, "Local obfuscation parameters:")
	localKey := strings.Index(transcript, "Local public key:")
	peers := strings.Index(transcript, "Peers")
	if obfuscation < 0 || localKey < 0 || peers < 0 || obfuscation >= localKey || localKey >= peers {
		t.Fatalf("AWG pairing material was not shown in V1 order:\n%s", transcript)
	}
}

func TestEndpointCollectsHostBeforePort(t *testing.T) {
	prompts, output := transcriptPrompts("vpn.example.com\n51821\n")
	endpoint, err := collectEndpoint(prompts, "")
	if err != nil {
		t.Fatal(err)
	}
	if endpoint != "vpn.example.com:51821" {
		t.Fatalf("endpoint = %q", endpoint)
	}
	transcript := output.String()
	host := strings.Index(transcript, "Remote endpoint")
	port := strings.Index(transcript, "Endpoint port")
	if host < 0 || port < 0 || host >= port {
		t.Fatalf("endpoint host was not requested before port:\n%s", transcript)
	}
}

func TestPassiveWireGuardPeerDoesNotAskForKeepalive(t *testing.T) {
	peerKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	input := peerKey.PublicKey().String() + "\n\n\n\n1\n"
	prompts, output := transcriptPrompts(input)
	peer, keep, err := collectWireGuardPeer(prompts, model.WireGuardPeer{})
	if err != nil {
		t.Fatal(err)
	}
	if !keep || peer.Endpoint != "" || peer.Keepalive != 0 {
		t.Fatalf("passive peer = %+v, keep=%t", peer, keep)
	}
	if strings.Contains(output.String(), "keepalive") {
		t.Fatalf("passive peer was asked for keepalive:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "Save peer") || strings.Contains(output.String(), "Add peer") {
		t.Fatalf("peer completion action is ambiguous:\n%s", output.String())
	}
}

func TestRPKShowsLocalMaterialBeforeRemotePrompt(t *testing.T) {
	remote := &model.XFRMIKEv2Spec{AuthMethod: model.IKEAuthRPK}
	if err := model.GenerateIKECredentials(remote); err != nil {
		t.Fatal(err)
	}
	spec := &model.XFRMIKEv2Spec{AuthMethod: model.IKEAuthRPK}
	prompts, output := transcriptPrompts(remote.LocalPublicKey + "\n")
	if err := replaceIKECredentials(prompts, spec); err != nil {
		t.Fatal(err)
	}
	transcript := output.String()
	local := strings.Index(transcript, "Local raw public key:")
	remotePrompt := strings.Index(transcript, "Remote raw public key")
	if local < 0 || remotePrompt < 0 || local >= remotePrompt {
		t.Fatalf("local RPK was not shown before remote prompt:\n%s", transcript)
	}
}

func TestStaticXFRMPeerPairReversesDirections(t *testing.T) {
	keyIn := strings.Repeat("11", 20)
	keyOut := strings.Repeat("22", 20)
	prompts, _ := transcriptPrompts("2\n0x101,0x202\n" + keyIn + "," + keyOut + "\n")
	spec := &model.XFRMStaticSpec{Algorithm: model.XFRMAESGCM}
	if err := collectStaticXFRMPairing(prompts, spec); err != nil {
		t.Fatal(err)
	}
	if spec.SPIInbound != 0x202 || spec.SPIOutbound != 0x101 || spec.EncryptionKeyIn != keyOut || spec.EncryptionKeyOut != keyIn {
		t.Fatalf("local pair was not reversed: %+v", spec)
	}
}

func TestStaticXFRMRejectsReservedSPIsAtThePairingPrompt(t *testing.T) {
	if err := validateUint32Pair("1,255"); err == nil {
		t.Fatal("reserved SPI pair was accepted")
	}
}

func TestEditTunnelSaveAndDiscardAreExplicit(t *testing.T) {
	current := model.Tunnel{
		Name: "original", Kind: model.KindGRE, Interface: "gre-original",
		Spec: model.Spec{GRE: &model.GRESpec{
			Local: netip.MustParseAddr("192.0.2.1"), Remote: netip.MustParseAddr("192.0.2.2"), MTU: 1450, TTL: 255,
		}},
	}
	prompts, output := transcriptPrompts("7\n2\n")
	discarded, saved, err := editTunnel(prompts, current)
	if err != nil || saved || discarded.Name != current.Name {
		t.Fatalf("discard result = %+v, saved=%t, err=%v", discarded, saved, err)
	}
	if transcript := output.String(); !strings.Contains(transcript, "Finish editing") || !strings.Contains(transcript, "Save changes") || !strings.Contains(transcript, "Discard changes") {
		t.Fatalf("edit completion is not an explicit decision:\n%s", transcript)
	}
	prompts, _ = transcriptPrompts("1\nrenamed\n7\n1\n")
	updated, saved, err := editTunnel(prompts, current)
	if err != nil || !saved || updated.Name != "gre-renamed" || updated.Enabled != current.Enabled {
		t.Fatalf("save result = %+v, saved=%t, err=%v", updated, saved, err)
	}
}

func TestActionConfirmationDefaultsToCancel(t *testing.T) {
	prompts, output := transcriptPrompts("\n")
	confirmed, err := prompts.confirmAction("Delete tunnel", "Delete tunnel")
	if err != nil || confirmed {
		t.Fatalf("confirmed=%t, err=%v", confirmed, err)
	}
	if transcript := output.String(); !strings.Contains(transcript, "Delete tunnel") || !strings.Contains(transcript, "Cancel") || !strings.Contains(transcript, "> [2]") {
		t.Fatalf("destructive confirmation does not default to Cancel:\n%s", transcript)
	}
}

func TestToggleUsesEnabledDisabledButtons(t *testing.T) {
	prompts, output := transcriptPrompts("\n")
	enabled, err := prompts.toggle("MAC learning", true)
	if err != nil || !enabled {
		t.Fatalf("enabled=%t, err=%v", enabled, err)
	}
	if transcript := output.String(); !strings.Contains(transcript, "Enabled") || !strings.Contains(transcript, "Disabled") || !strings.Contains(transcript, "> [1]") {
		t.Fatalf("toggle is not rendered as a binary decision:\n%s", transcript)
	}
}

func TestPeerEditorSeparatesFinishFromRemoval(t *testing.T) {
	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	original := model.WireGuardPeer{
		PublicKey: privateKey.PublicKey().String(),
		AllowedIPs: []netip.Prefix{
			netip.MustParsePrefix("10.0.0.0/24"),
		},
	}
	prompts, output := transcriptPrompts("5\n2\n")
	peer, action, err := editWireGuardPeer(prompts, original)
	if err != nil || action != "discard" || peer.PublicKey != original.PublicKey {
		t.Fatalf("peer=%+v, action=%q, err=%v", peer, action, err)
	}
	for _, expected := range []string{"Finish editing", "Remove peer", "Save peer", "Discard changes"} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("peer editor does not contain %q:\n%s", expected, output.String())
		}
	}

	prompts, _ = transcriptPrompts("6\n1\n")
	_, action, err = editWireGuardPeer(prompts, original)
	if err != nil || action != "remove" {
		t.Fatalf("remove action=%q, err=%v", action, err)
	}
}

func TestSRv6SourceEditorUsesSaveDiscardDecision(t *testing.T) {
	sid := netip.MustParseAddr("2001:db8::1")
	original := model.SRv6Source{Name: "source1", Family: model.SRv6FamilyIPv4, PrefixURL: "https://routes.example/edge-v4.txt", SID: sid, Priority: 100, MTU: 1500}
	prompts, output := transcriptPrompts("6\n2\n")
	source, action, err := editSRv6Source(prompts, original)
	if err != nil || action != "discard" || source.Name != original.Name {
		t.Fatalf("source=%+v, action=%q, err=%v", source, action, err)
	}
	for _, expected := range []string{"Finish editing", "Remove source", "Save source", "Discard changes"} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("source editor does not contain %q:\n%s", expected, output.String())
		}
	}
}

func TestNewSRv6SourceChoosesAddressFamilyFirst(t *testing.T) {
	prompts, output := transcriptPrompts("2\n\nhttps://routes.example/edge-v6.txt\n\n2001:db8::2\n\n1\n")
	source, keep, err := collectSRv6Source(prompts, model.SRv6Source{Name: "source2", MTU: 1500})
	if err != nil {
		t.Fatal(err)
	}
	if !keep || source.Family != model.SRv6FamilyIPv6 || source.Priority != 100 || source.PrefixURL != "https://routes.example/edge-v6.txt" {
		t.Fatalf("new IPv6 source = %+v, keep=%t", source, keep)
	}
	transcript := output.String()
	familyPrompt := strings.Index(transcript, "Address family")
	namePrompt := strings.Index(transcript, "Source name")
	if familyPrompt < 0 || namePrompt < 0 || familyPrompt >= namePrompt {
		t.Fatalf("address family was not selected before source editing:\n%s", transcript)
	}
	if !strings.Contains(transcript, "IPv6 prefix file URL") || strings.Contains(transcript, "IPv4 prefix file URL") {
		t.Fatalf("source form exposed the wrong address family fields:\n%s", transcript)
	}
}

func TestAmneziaHeadersRequireNumericDistinctValues(t *testing.T) {
	if err := validateAmneziaParameterString("4,40,1200,10,20,1,2,3,4"); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{
		"4,40,1200,10,20,header,2,3,4",
		"4,40,1200,10,20,1,1,3,4",
		"4,100,40,10,20,1,2,3,4",
	} {
		if err := validateAmneziaParameterString(value); err == nil {
			t.Fatalf("invalid parameter string accepted: %s", value)
		}
	}
}

func TestNewTunnelIdentityRejectsManagedConflicts(t *testing.T) {
	managed := []model.TunnelView{{Tunnel: model.Tunnel{Name: "taken", Interface: "wg-new"}}}
	if err := validateNewTunnelIdentity(model.KindWireGuard, "taken", managed); err == nil || !strings.Contains(err.Error(), "name") {
		t.Fatalf("managed name conflict = %v", err)
	}
	if err := validateNewTunnelIdentity(model.KindWireGuard, "new", managed); err == nil || !strings.Contains(err.Error(), "interface") {
		t.Fatalf("managed interface conflict = %v", err)
	}
}

func TestSuggestedTunnelNameAccountsForStoredPrefix(t *testing.T) {
	views := []model.TunnelView{{Tunnel: model.Tunnel{Name: "wg-prod1", Interface: "wg-prod1"}}}
	if got := suggestedTunnelName(model.KindWireGuard, views); got != "prod12" {
		t.Fatalf("suggested WireGuard name = %q, want prod12", got)
	}
}

func TestPrefixedTunnelNamesAreStoredOnce(t *testing.T) {
	for _, test := range []struct {
		kind model.Kind
		name string
		want string
	}{
		{kind: model.KindAmneziaWG, name: "rfc-tyo", want: "awg-rfc-tyo"},
		{kind: model.KindXFRMIKEv2, name: "rfc-tyo", want: "ipsec-rfc-tyo"},
		{kind: model.KindXFRMIKEv2, name: "ipsec-rfc-tyo", want: "ipsec-rfc-tyo"},
	} {
		t.Run(string(test.kind)+"/"+test.name, func(t *testing.T) {
			if got := prefixedTunnelName(test.kind, test.name); got != test.want {
				t.Fatalf("prefixed name = %q, want %q", got, test.want)
			}
			if got := interfaceName(test.kind, test.want); got != test.want {
				t.Fatalf("interface name = %q, want %q", got, test.want)
			}
		})
	}
}

func TestV1TunnelNameDefaultsAreRetained(t *testing.T) {
	if got := defaultTunnelName(model.KindWireGuard); got != "prod1" {
		t.Fatalf("WireGuard default name = %q", got)
	}
	if got := defaultTunnelName(model.KindXFRMStatic); got != "static1" {
		t.Fatalf("static XFRM default name = %q", got)
	}
}

func TestTunnelInsideAddressDefaultIsRestored(t *testing.T) {
	t.Setenv("TUNNEL_INSIDE_ADDR", "10.20.30.1/30,fd00::1/64")
	prompts, output := transcriptPrompts("")
	value, err := addressesDefault(prompts, "")
	if err != nil {
		t.Fatal(err)
	}
	if value != "10.20.30.1/30,fd00::1/64" || !strings.Contains(output.String(), "TUNNEL_INSIDE_ADDR") {
		t.Fatalf("inside address default = %q, output = %q", value, output.String())
	}
}

func TestPrefixValidationReportsDuplicatesAtTheField(t *testing.T) {
	if err := validateInterfacePrefixesInput("10.0.0.1/24,10.0.0.1/24"); err == nil {
		t.Fatal("duplicate interface address was accepted")
	}
	if err := validateAllowedPrefixesInput("10.0.0.1/24,10.0.0.2/24"); err == nil {
		t.Fatal("duplicate AllowedIP networks were accepted")
	}
}

func TestSRv6SourceNamesStayUniqueInsideTheEditor(t *testing.T) {
	sources := []model.SRv6Source{{Name: "source1"}}
	if suggested := suggestedSRv6SourceName(sources); suggested != "source2" {
		t.Fatalf("suggested source name = %q", suggested)
	}
	prompts, _ := transcriptPrompts("source2\n")
	name := "source1"
	if err := ensureUniqueSRv6SourceName(prompts, sources, -1, &name); err != nil {
		t.Fatal(err)
	}
	if name != "source2" {
		t.Fatalf("resolved source name = %q", name)
	}
}

func TestSRv6SourcePrioritiesStayUniqueInsideTheEditor(t *testing.T) {
	sources := []model.SRv6Source{{Name: "source1", Priority: 100}}
	prompts, _ := transcriptPrompts("101\n")
	priority := 100
	if err := ensureUniqueSRv6SourcePriority(prompts, sources, -1, &priority); err != nil {
		t.Fatal(err)
	}
	if priority != 101 {
		t.Fatalf("resolved source priority = %d", priority)
	}
}

func transcriptPrompts(input string) (*prompts, *bytes.Buffer) {
	output := &bytes.Buffer{}
	userInterface := ui.New(output, output, strings.NewReader(input))
	userInterface.TTY = false
	return newPrompts(userInterface), output
}
