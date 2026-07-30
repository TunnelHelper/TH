package app

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/TunnelHelper/TH/internal/model"
	"github.com/TunnelHelper/TH/internal/ui"
)

func collectWireGuard(prompts *prompts, record *model.Tunnel) error {
	spec := record.Spec.WireGuard
	creating := spec == nil
	if creating {
		spec = &model.WireGuardSpec{MTU: 1420}
		record.Spec = model.Spec{WireGuard: spec}
	}
	return collectWireGuardBase(prompts, spec, creating, nil)
}

func collectAmneziaWG(prompts *prompts, record *model.Tunnel) error {
	spec := record.Spec.AmneziaWG
	creating := spec == nil
	if creating {
		spec = &model.AmneziaWGSpec{WireGuardSpec: model.WireGuardSpec{MTU: 1420}}
		record.Spec = model.Spec{AmneziaWG: spec}
	}
	return collectWireGuardBase(prompts, &spec.WireGuardSpec, creating, func() error {
		if err := collectAmneziaObfuscation(prompts, spec, creating); err != nil {
			return err
		}
		prompts.ui.Ok("Local obfuscation parameters: " + formatAmneziaParameters(spec))
		return nil
	})
}

func collectWireGuardBase(prompts *prompts, spec *model.WireGuardSpec, creating bool, beforePeers func() error) error {
	if creating {
		if err := model.GenerateWireGuardCredentials(spec); err != nil {
			return err
		}
		if beforePeers == nil {
			showLocalPublicKey(prompts, spec.PublicKey)
		}
	}
	addresses, err := addressesDefault(prompts, formatPrefixes(spec.Addresses))
	if err != nil {
		return err
	}
	listenPort := strconv.Itoa(spec.ListenPort)
	firewallMark := strconv.Itoa(spec.FirewallMark)
	mtu := strconv.Itoa(spec.MTU)
	if spec.MTU == 0 {
		mtu = "1420"
	}
	if err := prompts.input("Interface addresses (comma separated, blank = none)", &addresses, validateInterfacePrefixesInput); err != nil {
		return err
	}
	if err := prompts.input("Listen port (0 = automatic)", &listenPort, validateInt(0, 65535)); err != nil {
		return err
	}
	if err := prompts.input("MTU (68-65535)", &mtu, validateInt(68, 65535)); err != nil {
		return err
	}
	if err := prompts.input("Firewall mark (0 = unset)", &firewallMark, validateInt(0, 2147483647)); err != nil {
		return err
	}
	if beforePeers != nil {
		if err := beforePeers(); err != nil {
			return err
		}
		if creating {
			showLocalPublicKey(prompts, spec.PublicKey)
		}
	}
	peers, err := collectWireGuardPeers(prompts, spec.Peers)
	if err != nil {
		return err
	}
	routeAllowed, routeTable, err := collectWireGuardRouting(prompts, spec.RouteAllowedIPs, spec.RouteTable)
	if err != nil {
		return err
	}
	spec.Addresses, _ = parsePrefixes(addresses)
	spec.ListenPort = parseInt(listenPort)
	spec.FirewallMark = parseInt(firewallMark)
	spec.MTU = parseInt(mtu)
	spec.RouteAllowedIPs = routeAllowed
	spec.RouteTable = routeTable
	spec.Peers = peers
	return nil
}

func showLocalPublicKey(prompts *prompts, publicKey string) {
	fmt.Fprintln(prompts.ui.Out)
	prompts.ui.Ok("Local public key: " + publicKey)
	prompts.ui.Dim("Share this key with the peer before adding its public key.")
}

func collectWireGuardRouting(prompts *prompts, enabled bool, table int) (bool, int, error) {
	mode := "none"
	if enabled && table == 0 {
		mode = "auto"
	} else if enabled {
		mode = "custom"
	}
	if err := prompts.selectValue("AllowedIPs routing", []ui.Option{
		{Label: "Do not install routes", Value: "none"},
		{Label: "Install routes in an automatic table", Value: "auto"},
		{Label: "Install routes in a custom table", Value: "custom"},
	}, &mode); err != nil {
		return false, 0, err
	}
	if mode == "none" {
		return false, 0, nil
	}
	if mode == "auto" {
		return true, 0, nil
	}
	value := strconv.Itoa(table)
	if table == 0 {
		value = "100"
	}
	if err := prompts.input("Route table (1-2147483647)", &value, validateInt(1, 2147483647)); err != nil {
		return false, 0, err
	}
	return true, parseInt(value), nil
}

func collectWireGuardPeers(prompts *prompts, initial []model.WireGuardPeer) ([]model.WireGuardPeer, error) {
	peers := append([]model.WireGuardPeer(nil), initial...)
	for {
		options := make([]ui.Option, 0, len(peers)+2)
		for index, peer := range peers {
			options = append(options, ui.Option{Label: peerLabel(peer), Value: strconv.Itoa(index)})
		}
		addLabel := "Add peer"
		if len(peers) > 0 {
			addLabel = "Add another peer"
		}
		options = append(options, ui.Option{Label: addLabel, Value: "add"}, ui.Option{Label: "Continue", Value: "done"})
		choice := "done"
		if err := prompts.selectValue("Peers", options, &choice); err != nil {
			return nil, err
		}
		if choice == "done" {
			return peers, nil
		}
		if choice == "add" {
			peer, keep, err := collectWireGuardPeer(prompts, model.WireGuardPeer{})
			if err != nil {
				if errors.Is(err, ErrAborted) {
					return nil, err
				}
				prompts.ui.Warn(err.Error())
				continue
			}
			if keep {
				if duplicatePeer(peers, peer.PublicKey, -1) {
					prompts.ui.Warn("A peer with that public key already exists")
					continue
				}
				peers = append(peers, peer)
			}
			continue
		}
		index, _ := strconv.Atoi(choice)
		if index < 0 || index >= len(peers) {
			continue
		}
		peer, action, err := editWireGuardPeer(prompts, peers[index])
		if err != nil {
			return nil, err
		}
		switch action {
		case "save":
			if duplicatePeer(peers, peer.PublicKey, index) {
				prompts.ui.Warn("A peer with that public key already exists")
				continue
			}
			peers[index] = peer
		case "remove":
			peers = append(peers[:index], peers[index+1:]...)
		}
	}
}

func collectWireGuardPeer(prompts *prompts, peer model.WireGuardPeer) (model.WireGuardPeer, bool, error) {
	if err := prompts.input("Peer public key", &peer.PublicKey, validateWireGuardKey); err != nil {
		return peer, false, err
	}
	if err := prompts.secret("Peer preshared key (blank = none or keep)", &peer.PresharedKey, validateOptionalWireGuardKey); err != nil {
		return peer, false, err
	}
	endpoint, err := collectEndpoint(prompts, peer.Endpoint)
	if err != nil {
		return peer, false, err
	}
	peer.Endpoint = endpoint
	if peer.Endpoint != "" {
		keepalive := strconv.Itoa(peer.Keepalive)
		if peer.Keepalive == 0 {
			keepalive = "25"
		}
		if err := prompts.input("Persistent keepalive seconds (0 = disabled)", &keepalive, validateInt(0, 65535)); err != nil {
			return peer, false, err
		}
		peer.Keepalive = parseInt(keepalive)
	} else {
		peer.Keepalive = 0
	}
	allowed := formatPrefixes(peer.AllowedIPs)
	if allowed == "" {
		allowed = "0.0.0.0/0,::/0"
	}
	if err := prompts.input("Allowed IPs (comma separated)", &allowed, validateAllowedPrefixesInput); err != nil {
		return peer, false, err
	}
	peer.AllowedIPs, _ = parsePrefixes(allowed)
	save, err := prompts.saveDiscard("Peer", "Save peer", "Discard peer")
	if err != nil {
		return peer, false, err
	}
	return peer, save, nil
}

func collectEndpoint(prompts *prompts, current string) (string, error) {
	value := current
	if err := prompts.input("Remote endpoint (host[:port], blank = passive)", &value, validateEndpointOrHost); err != nil {
		return "", err
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	if _, _, err := net.SplitHostPort(value); err == nil {
		return value, nil
	}
	port := "51820"
	if err := prompts.input("Endpoint port", &port, validateInt(1, 65535)); err != nil {
		return "", err
	}
	if address, err := netip.ParseAddr(value); err == nil && address.Is6() {
		return net.JoinHostPort(value, port), nil
	}
	return value + ":" + port, nil
}

func validateEndpointOrHost(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	if err := validateEndpointInput(value); err == nil {
		return nil
	}
	if address, err := netip.ParseAddr(value); err == nil && !address.IsUnspecified() {
		return nil
	}
	if !strings.Contains(value, ":") && validateHostname(value) == nil {
		return nil
	}
	return errors.New("endpoint must be a host, IP, or host:port")
}

func validateHostname(value string) error {
	if len(value) == 0 || len(value) > 253 {
		return errors.New("invalid hostname")
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return errors.New("invalid hostname")
		}
		for _, character := range label {
			if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '-') {
				return errors.New("invalid hostname")
			}
		}
	}
	return nil
}

func peerLabel(peer model.WireGuardPeer) string {
	label := peer.PublicKey
	if len(label) > 16 {
		label = label[:16] + "..."
	}
	if peer.Endpoint != "" {
		label += "  " + peer.Endpoint
	}
	return label
}

func duplicatePeer(peers []model.WireGuardPeer, key string, except int) bool {
	for index, peer := range peers {
		if index != except && peer.PublicKey == key {
			return true
		}
	}
	return false
}

func collectAmneziaObfuscation(prompts *prompts, spec *model.AmneziaWGSpec, creating bool) error {
	mode := "manual"
	if err := prompts.selectValue("Obfuscation parameters", []ui.Option{
		{Label: "Review randomized values", Value: "manual"},
		{Label: "Paste Jc,Jmin,Jmax,S1,S2,H1,H2,H3,H4", Value: "paste"},
	}, &mode); err != nil {
		return err
	}
	if mode == "paste" {
		value := ""
		if !creating {
			value = formatAmneziaParameters(spec)
		}
		if err := prompts.input("Obfuscation parameter string", &value, validateAmneziaParameterString); err != nil {
			return err
		}
		applyAmneziaParameterString(spec, value)
		return nil
	}
	values := randomizedAmneziaParameters(spec, creating)
	labels := []string{
		"Jc - junk packet count (1-128)", "Jmin - minimum junk size (1-1280)",
		"Jmax - maximum junk size (Jmin-1280)", "S1 - initiation padding (0-1280)",
		"S2 - response padding (0-1280)", "H1 - non-zero 32-bit header",
		"H2 - non-zero 32-bit header", "H3 - non-zero 32-bit header", "H4 - non-zero 32-bit header",
	}
	for {
		for index := range values {
			validator := validateUint32Text(index >= 5)
			if index == 0 {
				validator = validateInt(1, 128)
			} else if index == 1 || index == 2 {
				validator = validateInt(1, 1280)
			} else if index == 3 || index == 4 {
				validator = validateInt(0, 1280)
			}
			if err := prompts.input(labels[index], &values[index], validator); err != nil {
				return err
			}
		}
		if parseInt(values[2]) < parseInt(values[1]) {
			prompts.ui.Warn("Jmax must be greater than or equal to Jmin")
			continue
		}
		if duplicateStrings(values[5:]) {
			prompts.ui.Warn("H1, H2, H3, and H4 must be distinct")
			continue
		}
		break
	}
	applyAmneziaValues(spec, values)
	return nil
}

func randomizedAmneziaParameters(spec *model.AmneziaWGSpec, creating bool) []string {
	if !creating {
		return strings.Split(formatAmneziaParameters(spec), ",")
	}
	return []string{
		randomInteger(3, 10), randomInteger(30, 100), randomInteger(500, 1200),
		randomInteger(15, 150), randomInteger(15, 150), randomInteger(1000, 2147483647),
		randomInteger(1000, 2147483647), randomInteger(1000, 2147483647), randomInteger(1000, 2147483647),
	}
}

func randomInteger(minimum, maximum int64) string {
	value, err := rand.Int(rand.Reader, big.NewInt(maximum-minimum+1))
	if err != nil {
		return strconv.FormatInt(minimum, 10)
	}
	return strconv.FormatInt(value.Int64()+minimum, 10)
}

func validateAmneziaParameterString(value string) error {
	parts := strings.Split(strings.TrimSpace(value), ",")
	if len(parts) != 9 {
		return errors.New("must contain 9 comma-separated values")
	}
	for index, part := range parts {
		var err error
		switch index {
		case 0:
			err = validateInt(1, 128)(part)
		case 1, 2:
			err = validateInt(1, 1280)(part)
		case 3, 4:
			err = validateInt(0, 1280)(part)
		default:
			err = validateUint32Text(true)(part)
		}
		if err != nil {
			return fmt.Errorf("parameter %d: %w", index+1, err)
		}
	}
	if parseInt(parts[2]) < parseInt(parts[1]) {
		return errors.New("Jmax must be greater than or equal to Jmin")
	}
	if duplicateStrings(parts[5:]) {
		return errors.New("H1, H2, H3, and H4 must be distinct")
	}
	return nil
}

func validateUint32Text(nonZero bool) func(string) error {
	return func(value string) error {
		number, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
		if err != nil {
			return errors.New("must be a 32-bit unsigned integer")
		}
		if nonZero && number == 0 {
			return errors.New("must be a non-zero 32-bit integer")
		}
		return nil
	}
}

func applyAmneziaParameterString(spec *model.AmneziaWGSpec, value string) {
	applyAmneziaValues(spec, strings.Split(strings.TrimSpace(value), ","))
}

func applyAmneziaValues(spec *model.AmneziaWGSpec, values []string) {
	spec.JunkPacketCount = parseInt(values[0])
	spec.JunkPacketMinSize = parseInt(values[1])
	spec.JunkPacketMaxSize = parseInt(values[2])
	spec.InitPacketJunkSize = parseInt(values[3])
	spec.ResponsePacketJunkSize = parseInt(values[4])
	spec.InitMagicHeader = strings.TrimSpace(values[5])
	spec.ResponseMagicHeader = strings.TrimSpace(values[6])
	spec.UnderloadMagicHeader = strings.TrimSpace(values[7])
	spec.TransportMagicHeader = strings.TrimSpace(values[8])
}

func formatAmneziaParameters(spec *model.AmneziaWGSpec) string {
	return fmt.Sprintf("%d,%d,%d,%d,%d,%s,%s,%s,%s",
		spec.JunkPacketCount, spec.JunkPacketMinSize, spec.JunkPacketMaxSize,
		spec.InitPacketJunkSize, spec.ResponsePacketJunkSize, spec.InitMagicHeader,
		spec.ResponseMagicHeader, spec.UnderloadMagicHeader, spec.TransportMagicHeader)
}

func duplicateStrings(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if _, ok := seen[value]; ok {
			return true
		}
		seen[value] = struct{}{}
	}
	return false
}
