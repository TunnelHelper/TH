package app

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/TunnelHelper/TH/internal/model"
	"github.com/TunnelHelper/TH/internal/ui"
)

func showTunnelSummary(output *ui.UI, record model.Tunnel) {
	output.Title("Review")
	fmt.Fprintf(output.Out, "Name: %s\nKind: %s\n", record.Name, record.Kind)
	if record.Interface != "" {
		fmt.Fprintf(output.Out, "Interface: %s\n", record.Interface)
	}
	switch record.Kind {
	case model.KindGRE:
		spec := record.Spec.GRE
		fmt.Fprintf(output.Out, "Underlay: %s -> %s\nAddresses: %s\n", spec.Local, spec.Remote, formatPrefixes(spec.Addresses))
	case model.KindVXLAN:
		spec := record.Spec.VXLAN
		fmt.Fprintf(output.Out, "VNI: %d\nUnderlay: %s -> %s via %s\n", spec.VNI, spec.Local, spec.Remote, spec.UnderlayInterface)
	case model.KindWireGuard:
		showWireGuardSummary(output, record.Spec.WireGuard)
	case model.KindAmneziaWG:
		showWireGuardSummary(output, &record.Spec.AmneziaWG.WireGuardSpec)
	case model.KindXFRMStatic:
		spec := record.Spec.XFRMStatic
		fmt.Fprintf(output.Out, "Underlay: %s -> %s via %s\nAlgorithm: %s\n", spec.Local, spec.Remote, spec.UnderlayInterface, spec.Algorithm)
	case model.KindXFRMIKEv2:
		spec := record.Spec.XFRMIKEv2
		fmt.Fprintf(output.Out, "Underlay: %s -> %s via %s\nAuthentication: %s\n", spec.LocalAddress, spec.RemoteAddress, spec.UnderlayInterface, spec.AuthMethod)
	case model.KindSRv6:
		spec := record.Spec.SRv6
		ipv4, ipv6 := 0, 0
		for _, source := range spec.Sources {
			if source.Family == model.SRv6FamilyIPv4 {
				ipv4++
			} else if source.Family == model.SRv6FamilyIPv6 {
				ipv6++
			}
		}
		fmt.Fprintf(output.Out, "Underlay: %s\nSources: %d (IPv4: %d, IPv6: %d)\n", spec.UnderlayInterface, len(spec.Sources), ipv4, ipv6)
	}
}

func showWireGuardSummary(output *ui.UI, spec *model.WireGuardSpec) {
	fmt.Fprintf(output.Out, "Addresses: %s\nListen port: %d\nPeers: %d\n", formatPrefixes(spec.Addresses), spec.ListenPort, len(spec.Peers))
	for _, peer := range spec.Peers {
		key := peer.PublicKey
		if len(key) > 16 {
			key = key[:16] + "..."
		}
		fmt.Fprintf(output.Out, "  %s  %s  %s\n", key, peer.Endpoint, strings.Join(prefixStrings(peer.AllowedIPs), ","))
	}
}

func prefixStrings(prefixes []netip.Prefix) []string {
	values := make([]string, len(prefixes))
	for index, prefix := range prefixes {
		values[index] = prefix.String()
	}
	return values
}

func showWireGuardPeerReference(output *ui.UI, spec *model.WireGuardSpec, obfuscation string) {
	fmt.Fprintln(output.Out, "Peer reference:")
	fmt.Fprintf(output.Out, "  Public key: %s\n", spec.PublicKey)
	if spec.ListenPort != 0 {
		fmt.Fprintf(output.Out, "  Endpoint: <this-host>:%d\n", spec.ListenPort)
	} else {
		fmt.Fprintln(output.Out, "  Endpoint: <this-host>:<listen-port>")
	}
	if addresses := formatPrefixes(spec.Addresses); addresses != "" {
		fmt.Fprintf(output.Out, "  Allowed IPs for this host: %s\n", addresses)
	}
	if obfuscation != "" {
		fmt.Fprintf(output.Out, "  Obfuscation: %s\n", obfuscation)
	}
}

func showStaticXFRMPairing(output *ui.UI, spec *model.XFRMStaticSpec) {
	fmt.Fprintf(output.Out, "Local inbound SPI: 0x%x\nLocal outbound SPI: 0x%x\n", spec.SPIInbound, spec.SPIOutbound)
	fmt.Fprintf(output.Out, "Inbound encryption key: %s\nOutbound encryption key: %s\n", spec.EncryptionKeyIn, spec.EncryptionKeyOut)
	if spec.AuthenticationKeyIn != "" {
		fmt.Fprintf(output.Out, "Inbound authentication key: %s\nOutbound authentication key: %s\n", spec.AuthenticationKeyIn, spec.AuthenticationKeyOut)
	}
	fmt.Fprintln(output.Out, "Peer reference (paste on the other endpoint):")
	fmt.Fprintf(output.Out, "  SPI pair: 0x%x,0x%x\n", spec.SPIOutbound, spec.SPIInbound)
	fmt.Fprintf(output.Out, "  Encryption keys: %s,%s\n", spec.EncryptionKeyOut, spec.EncryptionKeyIn)
	if spec.AuthenticationKeyIn != "" {
		fmt.Fprintf(output.Out, "  Authentication keys: %s,%s\n", spec.AuthenticationKeyOut, spec.AuthenticationKeyIn)
	}
}
