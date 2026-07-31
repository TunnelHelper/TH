package model

import "strings"

func TunnelNamePrefix(kind Kind) string {
	switch kind {
	case KindGRE:
		return "gre-"
	case KindVXLAN:
		return "vxlan-"
	case KindWireGuard:
		return "wg-"
	case KindAmneziaWG:
		return "awg-"
	case KindXFRMStatic, KindXFRMIKEv2:
		return "ipsec-"
	default:
		return ""
	}
}

func PrefixedTunnelName(kind Kind, name string) string {
	prefix := TunnelNamePrefix(kind)
	if prefix == "" || strings.HasPrefix(name, prefix) {
		return name
	}
	return prefix + name
}
