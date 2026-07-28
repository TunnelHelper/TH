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
	prompts, output := transcriptPrompts("\n\n\n\n\n2\n1\n")
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
	options := createActionOptions()
	if len(options) != 3 || options[0].Value != "enable" || options[1].Value != "disable" || options[2].Value != "back" {
		t.Fatalf("final create choices = %+v", options)
	}
}

func TestWireGuardShowsLocalKeyBeforePeerPrompt(t *testing.T) {
	prompts, output := transcriptPrompts("\n\n\n\n\n2\n1\n")
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
	peer, keep, err := collectWireGuardPeer(prompts, model.WireGuardPeer{}, true)
	if err != nil {
		t.Fatal(err)
	}
	if !keep || peer.Endpoint != "" || peer.Keepalive != 0 {
		t.Fatalf("passive peer = %+v, keep=%t", peer, keep)
	}
	if strings.Contains(output.String(), "keepalive") {
		t.Fatalf("passive peer was asked for keepalive:\n%s", output.String())
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
	prompts, _ := transcriptPrompts("8\n")
	discarded, saved, err := editTunnel(prompts, current)
	if err != nil || saved || discarded.Name != current.Name {
		t.Fatalf("discard result = %+v, saved=%t, err=%v", discarded, saved, err)
	}
	prompts, _ = transcriptPrompts("1\nrenamed\n7\n")
	updated, saved, err := editTunnel(prompts, current)
	if err != nil || !saved || updated.Name != "renamed" || updated.Enabled != current.Enabled {
		t.Fatalf("save result = %+v, saved=%t, err=%v", updated, saved, err)
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
	sources := []model.SRv6Source{{Name: "chinamobile"}}
	if suggested := suggestedSRv6SourceName(sources); suggested != "chinaunicom" {
		t.Fatalf("suggested source name = %q", suggested)
	}
	prompts, _ := transcriptPrompts("chinaunicom\n")
	name := "chinamobile"
	if err := ensureUniqueSRv6SourceName(prompts, sources, -1, &name); err != nil {
		t.Fatal(err)
	}
	if name != "chinaunicom" {
		t.Fatalf("resolved source name = %q", name)
	}
}

func transcriptPrompts(input string) (*prompts, *bytes.Buffer) {
	output := &bytes.Buffer{}
	userInterface := ui.New(output, output, strings.NewReader(input))
	userInterface.TTY = false
	return newPrompts(userInterface), output
}
