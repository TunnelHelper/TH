package app

import (
	"fmt"
	"strconv"

	"github.com/TunnelHelper/TH/internal/model"
	"github.com/TunnelHelper/TH/internal/ui"
)

func wireGuardEditOptions(spec *model.WireGuardSpec, amnezia bool) []ui.Option {
	options := []ui.Option{
		{Label: "Interface addresses: " + formatPrefixes(spec.Addresses), Value: "addresses"},
		{Label: fmt.Sprintf("Listen port: %d", spec.ListenPort), Value: "listen"},
		{Label: fmt.Sprintf("MTU: %d", spec.MTU), Value: "mtu"},
		{Label: fmt.Sprintf("Firewall mark: %d", spec.FirewallMark), Value: "mark"},
		{Label: fmt.Sprintf("Peers: %d", len(spec.Peers)), Value: "peers"},
		{Label: wireGuardRoutingLabel(spec), Value: "routing"},
		{Label: "Rotate local key", Value: "rotate"},
	}
	if amnezia {
		options = append(options, ui.Option{Label: "Obfuscation parameters", Value: "obfuscation"})
	}
	return options
}

func wireGuardRoutingLabel(spec *model.WireGuardSpec) string {
	if !spec.RouteAllowedIPs {
		return "AllowedIPs routing: disabled"
	}
	if spec.RouteTable == 0 {
		return "AllowedIPs routing: automatic"
	}
	return fmt.Sprintf("AllowedIPs routing: table %d", spec.RouteTable)
}

func editWireGuardField(prompts *prompts, record *model.Tunnel, field string) error {
	var spec *model.WireGuardSpec
	if record.Kind == model.KindWireGuard {
		spec = record.Spec.WireGuard
	} else {
		spec = &record.Spec.AmneziaWG.WireGuardSpec
	}
	switch field {
	case "addresses":
		value := formatPrefixes(spec.Addresses)
		if err := prompts.input("Interface addresses (comma separated, blank = none)", &value, validateInterfacePrefixesInput); err != nil {
			return err
		}
		spec.Addresses, _ = parsePrefixes(value)
	case "listen":
		return editInt(prompts, "Listen port (0 = automatic)", &spec.ListenPort, 0, 65535)
	case "mtu":
		return editInt(prompts, "MTU (68-65535)", &spec.MTU, 68, 65535)
	case "mark":
		return editInt(prompts, "Firewall mark (0 = unset)", &spec.FirewallMark, 0, 2147483647)
	case "peers":
		peers, err := editWireGuardPeers(prompts, spec.Peers)
		if err != nil {
			return err
		}
		spec.Peers = peers
	case "routing":
		enabled, table, err := collectWireGuardRouting(prompts, spec.RouteAllowedIPs, spec.RouteTable)
		if err != nil {
			return err
		}
		spec.RouteAllowedIPs, spec.RouteTable = enabled, table
	case "rotate":
		confirmed, err := prompts.confirm("Rotate the local key and require peers to update", false)
		if err != nil || !confirmed {
			return err
		}
		spec.PrivateKey, spec.PublicKey = "", ""
		if err := model.GenerateWireGuardCredentials(spec); err != nil {
			return err
		}
		showLocalPublicKey(prompts, spec.PublicKey)
	case "obfuscation":
		return collectAmneziaObfuscation(prompts, record.Spec.AmneziaWG, false)
	}
	return nil
}

func editWireGuardPeers(prompts *prompts, initial []model.WireGuardPeer) ([]model.WireGuardPeer, error) {
	peers := append([]model.WireGuardPeer(nil), initial...)
	for {
		options := make([]ui.Option, 0, len(peers)+2)
		for index, peer := range peers {
			options = append(options, ui.Option{Label: peerLabel(peer), Value: strconv.Itoa(index)})
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
			if keep && !duplicatePeer(peers, peer.PublicKey, -1) {
				peers = append(peers, peer)
			} else if keep {
				prompts.ui.Warn("A peer with that public key already exists")
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
		if action == "remove" {
			peers = append(peers[:index], peers[index+1:]...)
		} else if action == "save" {
			if duplicatePeer(peers, peer.PublicKey, index) {
				prompts.ui.Warn("A peer with that public key already exists")
				continue
			}
			peers[index] = peer
		}
	}
}

func editWireGuardPeer(prompts *prompts, original model.WireGuardPeer) (model.WireGuardPeer, string, error) {
	peer := original
	for {
		options := []ui.Option{
			{Label: "Public key: " + fit(peer.PublicKey, 24), Value: "key"},
			{Label: "Preshared key", Value: "psk"},
			{Label: "Endpoint: " + endpointLabel(peer.Endpoint), Value: "endpoint"},
			{Label: "Allowed IPs: " + formatPrefixes(peer.AllowedIPs), Value: "allowed"},
		}
		if peer.Endpoint != "" {
			options = append(options, ui.Option{Label: fmt.Sprintf("Keepalive: %d", peer.Keepalive), Value: "keepalive"})
		}
		options = append(options,
			ui.Option{Label: "Save peer", Value: "save"},
			ui.Option{Label: "Remove peer", Value: "remove"},
			ui.Option{Label: "Discard peer changes", Value: "discard"},
		)
		choice := "save"
		if err := prompts.selectValue("Peer field", options, &choice); err != nil {
			return original, "discard", err
		}
		switch choice {
		case "save", "discard":
			return peer, choice, nil
		case "remove":
			confirmed, err := prompts.confirm("Remove this peer", false)
			if err != nil {
				return original, "discard", err
			}
			if confirmed {
				return peer, "remove", nil
			}
		case "key":
			if err := prompts.input("Peer public key", &peer.PublicKey, validateWireGuardKey); err != nil {
				return original, "discard", err
			}
		case "psk":
			if err := editPeerPSK(prompts, &peer); err != nil {
				return original, "discard", err
			}
		case "endpoint":
			endpoint, err := collectEndpoint(prompts, peer.Endpoint)
			if err != nil {
				return original, "discard", err
			}
			peer.Endpoint = endpoint
			if endpoint == "" {
				peer.Keepalive = 0
			}
		case "allowed":
			value := formatPrefixes(peer.AllowedIPs)
			if err := prompts.input("Allowed IPs (comma separated)", &value, validateAllowedPrefixesInput); err != nil {
				return original, "discard", err
			}
			peer.AllowedIPs, _ = parsePrefixes(value)
		case "keepalive":
			if err := editInt(prompts, "Persistent keepalive seconds (0 = disabled)", &peer.Keepalive, 0, 65535); err != nil {
				return original, "discard", err
			}
		}
	}
}

func editPeerPSK(prompts *prompts, peer *model.WireGuardPeer) error {
	action := "keep"
	if err := prompts.selectValue("Preshared key", []ui.Option{
		{Label: "Keep current key", Value: "keep"},
		{Label: "Replace key", Value: "replace"},
		{Label: "Remove key", Value: "remove"},
	}, &action); err != nil {
		return err
	}
	if action == "remove" {
		peer.PresharedKey = model.ClearSecretValue
		return nil
	}
	if action == "replace" {
		value := ""
		if err := prompts.secret("New preshared key", &value, validateWireGuardKey); err != nil {
			return err
		}
		peer.PresharedKey = value
	} else if action == "keep" {
		peer.PresharedKey = ""
	}
	return nil
}

func endpointLabel(value string) string {
	if value == "" {
		return "passive"
	}
	return value
}
