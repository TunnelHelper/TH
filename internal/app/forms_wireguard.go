package app

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/TunnelHelper/TH/internal/model"
	"github.com/TunnelHelper/TH/internal/ui"
)

func collectWireGuard(prompts *prompts, record *model.Tunnel) error {
	spec := record.Spec.WireGuard
	if spec == nil {
		spec = &model.WireGuardSpec{MTU: 1420}
		record.Spec = model.Spec{WireGuard: spec}
	}
	return collectWireGuardBase(prompts, spec)
}

func collectAmneziaWG(prompts *prompts, record *model.Tunnel) error {
	spec := record.Spec.AmneziaWG
	if spec == nil {
		spec = &model.AmneziaWGSpec{
			WireGuardSpec:          model.WireGuardSpec{MTU: 1420},
			JunkPacketCount:        4,
			JunkPacketMinSize:      40,
			JunkPacketMaxSize:      1200,
			InitPacketJunkSize:     50,
			ResponsePacketJunkSize: 50,
		}
		record.Spec = model.Spec{AmneziaWG: spec}
	}
	if err := collectWireGuardBase(prompts, &spec.WireGuardSpec); err != nil {
		return err
	}
	jc := strconv.Itoa(spec.JunkPacketCount)
	jmin := strconv.Itoa(spec.JunkPacketMinSize)
	jmax := strconv.Itoa(spec.JunkPacketMaxSize)
	s1 := strconv.Itoa(spec.InitPacketJunkSize)
	s2 := strconv.Itoa(spec.ResponsePacketJunkSize)
	if err := prompts.input("Jc", &jc, validateInt(1, 128)); err != nil {
		return err
	}
	if err := prompts.input("Jmin", &jmin, validateInt(1, 1280)); err != nil {
		return err
	}
	if err := prompts.input("Jmax", &jmax, func(value string) error {
		if err := validateInt(1, 1280)(value); err != nil {
			return err
		}
		if parseInt(value) < parseInt(jmin) {
			return errors.New("Jmax must be greater than or equal to Jmin")
		}
		return nil
	}); err != nil {
		return err
	}
	if err := prompts.input("S1", &s1, validateInt(0, 1280)); err != nil {
		return err
	}
	if err := prompts.input("S2", &s2, validateInt(0, 1280)); err != nil {
		return err
	}
	headers := []*string{&spec.InitMagicHeader, &spec.ResponseMagicHeader, &spec.UnderloadMagicHeader, &spec.TransportMagicHeader}
	for i, header := range headers {
		if err := prompts.input(fmt.Sprintf("H%d", i+1), header, validateMagicInput); err != nil {
			return err
		}
	}
	seenHeaders := make(map[string]struct{}, len(headers))
	for _, header := range headers {
		if *header == "" {
			continue
		}
		if _, exists := seenHeaders[*header]; exists {
			return errors.New("H1, H2, H3, and H4 must be distinct")
		}
		seenHeaders[*header] = struct{}{}
	}
	spec.JunkPacketCount = parseInt(jc)
	spec.JunkPacketMinSize = parseInt(jmin)
	spec.JunkPacketMaxSize = parseInt(jmax)
	spec.InitPacketJunkSize = parseInt(s1)
	spec.ResponsePacketJunkSize = parseInt(s2)
	return nil
}

func collectWireGuardBase(prompts *prompts, spec *model.WireGuardSpec) error {
	privateKey := spec.PrivateKey
	addresses := formatPrefixes(spec.Addresses)
	listenPort := strconv.Itoa(spec.ListenPort)
	firewallMark := strconv.Itoa(spec.FirewallMark)
	mtu := strconv.Itoa(spec.MTU)
	routeTable := strconv.Itoa(spec.RouteTable)
	if spec.MTU == 0 {
		mtu = "1420"
	}
	if err := prompts.secret("Private key (blank = generate or keep)", &privateKey, validateOptionalWireGuardKey); err != nil {
		return err
	}
	if err := prompts.input("Interface addresses", &addresses, validatePrefixesInput); err != nil {
		return err
	}
	if err := prompts.input("Listen port", &listenPort, validateInt(0, 65535)); err != nil {
		return err
	}
	if err := prompts.input("Firewall mark", &firewallMark, validateInt(0, 2147483647)); err != nil {
		return err
	}
	if err := prompts.input("MTU", &mtu, validateInt(68, 65535)); err != nil {
		return err
	}
	routeAllowed, err := prompts.confirm("Install AllowedIPs routes", spec.RouteAllowedIPs)
	if err != nil {
		return err
	}
	if routeAllowed {
		if err := prompts.input("Route table (0 = automatic)", &routeTable, validateInt(0, 2147483647)); err != nil {
			return err
		}
	}
	peers, err := collectWireGuardPeers(prompts, spec.Peers)
	if err != nil {
		return err
	}
	spec.PrivateKey = privateKey
	spec.Addresses, _ = parsePrefixes(addresses)
	spec.ListenPort = parseInt(listenPort)
	spec.FirewallMark = parseInt(firewallMark)
	spec.MTU = parseInt(mtu)
	spec.RouteAllowedIPs = routeAllowed
	spec.RouteTable = parseInt(routeTable)
	spec.Peers = peers
	return nil
}

func collectWireGuardPeers(prompts *prompts, initial []model.WireGuardPeer) ([]model.WireGuardPeer, error) {
	peers := append([]model.WireGuardPeer(nil), initial...)
	for {
		options := make([]ui.Option, 0, len(peers)+2)
		for i, peer := range peers {
			label := peer.PublicKey
			if len(label) > 16 {
				label = label[:16] + "..."
			}
			options = append(options, ui.Option{Label: label, Value: strconv.Itoa(i)})
		}
		options = append(options, ui.Option{Label: "Add peer", Value: "add"}, ui.Option{Label: "Done", Value: "done"})
		choice := "done"
		if err := prompts.selectValue("Peers", options, &choice); err != nil {
			return nil, err
		}
		if choice == "done" {
			return peers, nil
		}
		if choice == "add" {
			peer, keep, err := collectWireGuardPeer(prompts, model.WireGuardPeer{}, true)
			if err != nil {
				return nil, err
			}
			if keep {
				peers = append(peers, peer)
			}
			continue
		}
		index, _ := strconv.Atoi(choice)
		if index < 0 || index >= len(peers) {
			continue
		}
		peer, keep, err := collectWireGuardPeer(prompts, peers[index], false)
		if err != nil {
			return nil, err
		}
		if keep {
			peers[index] = peer
		} else {
			peers = append(peers[:index], peers[index+1:]...)
		}
	}
}

func collectWireGuardPeer(prompts *prompts, peer model.WireGuardPeer, adding bool) (model.WireGuardPeer, bool, error) {
	if err := prompts.input("Peer public key", &peer.PublicKey, validateWireGuardKey); err != nil {
		return peer, false, err
	}
	if err := prompts.secret("Peer preshared key (blank = none or keep)", &peer.PresharedKey, validateOptionalWireGuardKey); err != nil {
		return peer, false, err
	}
	if err := prompts.input("Endpoint", &peer.Endpoint, validateEndpointInput); err != nil {
		return peer, false, err
	}
	keepalive := strconv.Itoa(peer.Keepalive)
	if err := prompts.input("Persistent keepalive", &keepalive, validateInt(0, 65535)); err != nil {
		return peer, false, err
	}
	allowed := formatPrefixes(peer.AllowedIPs)
	if adding && allowed == "" {
		allowed = "0.0.0.0/0,::/0"
	}
	if err := prompts.input("Allowed IPs", &allowed, validatePrefixesInput); err != nil {
		return peer, false, err
	}
	peer.Keepalive = parseInt(keepalive)
	peer.AllowedIPs, _ = parsePrefixes(allowed)
	if !adding {
		remove, err := prompts.confirm("Remove this peer", false)
		if err != nil {
			return peer, false, err
		}
		if remove {
			return peer, false, nil
		}
	}
	return peer, true, nil
}

func validateMagicInput(value string) error {
	if value == "" {
		return nil
	}
	if len(value) > 255 || strings.ContainsRune(value, '\x00') {
		return errors.New("header must contain 1-255 bytes without NUL")
	}
	return nil
}
