package model

import (
	"encoding/json"
	"fmt"
	"strings"
)

func Redact(t Tunnel) (Tunnel, []string) {
	copy, err := Clone(t)
	if err != nil {
		return Tunnel{}, nil
	}
	fields := make([]string, 0, 8)
	switch copy.Kind {
	case KindWireGuard:
		redactWireGuard(copy.Spec.WireGuard, &fields, "spec.wireguard")
	case KindAmneziaWG:
		if copy.Spec.AmneziaWG != nil {
			redactWireGuard(&copy.Spec.AmneziaWG.WireGuardSpec, &fields, "spec.amneziawg")
		}
	case KindXFRMStatic:
		if spec := copy.Spec.XFRMStatic; spec != nil {
			for name, value := range map[string]*string{
				"encryption_key_in":      &spec.EncryptionKeyIn,
				"encryption_key_out":     &spec.EncryptionKeyOut,
				"authentication_key_in":  &spec.AuthenticationKeyIn,
				"authentication_key_out": &spec.AuthenticationKeyOut,
			} {
				if *value != "" {
					fields = append(fields, "spec.xfrm_static."+name)
					*value = ""
				}
			}
		}
	case KindXFRMIKEv2:
		if spec := copy.Spec.XFRMIKEv2; spec != nil {
			for name, value := range map[string]*string{
				"psk":               &spec.PSK,
				"local_private_key": &spec.LocalPrivateKey,
			} {
				if strings.TrimSpace(*value) != "" {
					fields = append(fields, "spec.xfrm_ikev2."+name)
					*value = ""
				}
			}
		}
	}
	return copy, fields
}

func Clone(t Tunnel) (Tunnel, error) {
	data, err := json.Marshal(t)
	if err != nil {
		return Tunnel{}, err
	}
	var copy Tunnel
	if err := json.Unmarshal(data, &copy); err != nil {
		return Tunnel{}, err
	}
	return copy, nil
}

func redactWireGuard(spec *WireGuardSpec, fields *[]string, prefix string) {
	if spec == nil {
		return
	}
	if spec.PrivateKey != "" {
		*fields = append(*fields, prefix+".private_key")
		spec.PrivateKey = ""
	}
	for i := range spec.Peers {
		if spec.Peers[i].PresharedKey != "" {
			*fields = append(*fields, fmt.Sprintf("%s.peers[%d].preshared_key", prefix, i))
			spec.Peers[i].PresharedKey = ""
		}
	}
}
