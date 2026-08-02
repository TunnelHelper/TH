package model

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func PrepareNew(t *Tunnel, now time.Time) error {
	if t == nil {
		return errors.New("tunnel is required")
	}
	if err := validateSpecChoice(t); err != nil {
		return err
	}
	if t.ID == "" {
		id, err := NewID()
		if err != nil {
			return err
		}
		t.ID = id
	}
	t.SchemaVersion = SchemaVersion
	t.Generation = 1
	t.CreatedAt = now.UTC()
	t.UpdatedAt = t.CreatedAt
	applyDefaults(t)
	if err := prepareSecrets(t, true); err != nil {
		return err
	}
	return Validate(t)
}

func PrepareUpdate(next, current *Tunnel, now time.Time) error {
	return prepareUpdate(next, current, now, false)
}

// PrepareUpdateWithGeneratedSecrets is reserved for interactive workflows that
// can immediately show newly generated replacement material to the operator.
// API updates use PrepareUpdate so secrets are never generated and then hidden
// by a redacted response.
func PrepareUpdateWithGeneratedSecrets(next, current *Tunnel, now time.Time) error {
	return prepareUpdate(next, current, now, true)
}

func prepareUpdate(next, current *Tunnel, now time.Time, generateSecrets bool) error {
	if next == nil || current == nil {
		return errors.New("current and updated tunnels are required")
	}
	if err := validateSpecChoice(next); err != nil {
		return err
	}
	next.ID = current.ID
	next.SchemaVersion = SchemaVersion
	next.Generation = current.Generation + 1
	next.CreatedAt = current.CreatedAt
	next.UpdatedAt = now.UTC()
	MergeSecrets(next, current)
	if next.Kind == KindSRv6 && next.Spec.SRv6 != nil && current.Spec.SRv6 != nil && next.Spec.SRv6.RulePriority == 0 {
		next.Spec.SRv6.RulePriority = current.Spec.SRv6.RulePriority
	}
	if next.Kind == KindBabel && next.Spec.Babel != nil && current.Spec.Babel != nil && next.Spec.Babel.RouterID == "" {
		next.Spec.Babel.RouterID = current.Spec.Babel.RouterID
	}
	applyDefaults(next)
	if err := prepareSecrets(next, generateSecrets); err != nil {
		return err
	}
	return Validate(next)
}

func applyDefaults(t *Tunnel) {
	switch t.Kind {
	case KindGRE:
		if t.Spec.GRE != nil {
			if t.Spec.GRE.MTU == 0 {
				t.Spec.GRE.MTU = 1450
			}
			if t.Spec.GRE.TTL == 0 {
				t.Spec.GRE.TTL = 255
			}
		}
	case KindVXLAN:
		if t.Spec.VXLAN != nil {
			if t.Spec.VXLAN.MTU == 0 {
				t.Spec.VXLAN.MTU = 1450
			}
			if t.Spec.VXLAN.DestinationPort == 0 {
				t.Spec.VXLAN.DestinationPort = 4789
			}
		}
	case KindWireGuard:
		if t.Spec.WireGuard != nil && t.Spec.WireGuard.MTU == 0 {
			t.Spec.WireGuard.MTU = 1420
		}
	case KindAmneziaWG:
		if t.Spec.AmneziaWG != nil {
			if t.Spec.AmneziaWG.MTU == 0 {
				t.Spec.AmneziaWG.MTU = 1420
			}
			if t.Spec.AmneziaWG.JunkPacketCount == 0 {
				t.Spec.AmneziaWG.JunkPacketCount = 4
			}
			if t.Spec.AmneziaWG.JunkPacketMinSize == 0 {
				t.Spec.AmneziaWG.JunkPacketMinSize = 40
			}
			if t.Spec.AmneziaWG.JunkPacketMaxSize == 0 {
				t.Spec.AmneziaWG.JunkPacketMaxSize = 1200
			}
			if t.Spec.AmneziaWG.InitMagicHeader == "" {
				t.Spec.AmneziaWG.InitMagicHeader = randomUintString()
			}
			if t.Spec.AmneziaWG.ResponseMagicHeader == "" {
				t.Spec.AmneziaWG.ResponseMagicHeader = randomUintString()
			}
			if t.Spec.AmneziaWG.UnderloadMagicHeader == "" {
				t.Spec.AmneziaWG.UnderloadMagicHeader = randomUintString()
			}
			if t.Spec.AmneziaWG.TransportMagicHeader == "" {
				t.Spec.AmneziaWG.TransportMagicHeader = randomUintString()
			}
		}
	case KindXFRMStatic:
		if t.Spec.XFRMStatic != nil {
			setXFRMDefaults(t.ID, &t.Spec.XFRMStatic.IfID, &t.Spec.XFRMStatic.ReqID)
			if t.Spec.XFRMStatic.MTU == 0 {
				t.Spec.XFRMStatic.MTU = 1400
			}
			if t.Spec.XFRMStatic.Algorithm == "" {
				t.Spec.XFRMStatic.Algorithm = XFRMAESGCM
			}
		}
	case KindXFRMIKEv2:
		if t.Spec.XFRMIKEv2 != nil {
			setXFRMDefaults(t.ID, &t.Spec.XFRMIKEv2.IfID, &t.Spec.XFRMIKEv2.ReqID)
			if t.Spec.XFRMIKEv2.MTU == 0 {
				t.Spec.XFRMIKEv2.MTU = 1400
			}
			if t.Spec.XFRMIKEv2.IKEProposal == "" {
				t.Spec.XFRMIKEv2.IKEProposal = "aes128gcm16-prfsha256-curve25519"
			}
			if t.Spec.XFRMIKEv2.ESPProposal == "" {
				t.Spec.XFRMIKEv2.ESPProposal = "aes128gcm16"
			}
			if t.Spec.XFRMIKEv2.StartAction == "" {
				t.Spec.XFRMIKEv2.StartAction = "trap"
			}
		}
	case KindSRv6:
		if t.Spec.SRv6 != nil {
			if t.Spec.SRv6.RulePriority == 0 {
				t.Spec.SRv6.RulePriority = SRv6AutoRulePriorityMin
			}
			if t.Spec.SRv6.RefreshIntervalSeconds == 0 {
				t.Spec.SRv6.RefreshIntervalSeconds = 3600
			}
			for index := range t.Spec.SRv6.Sources {
				if t.Spec.SRv6.Sources[index].Priority == 0 {
					t.Spec.SRv6.Sources[index].Priority = NextSRv6SourcePriority(t.Spec.SRv6.Sources)
				}
			}
		}
	case KindBabel:
		if t.Spec.Babel != nil {
			spec := t.Spec.Babel
			if spec.RouterID == "" {
				spec.RouterID = randomBabelRouterID()
			}
			if spec.MaxPaths == 0 {
				spec.MaxPaths = 4
			}
			if spec.SplitHorizon == nil {
				enabled := true
				spec.SplitHorizon = &enabled
			}
			if !spec.Multicast && spec.UnicastHelloSeconds == 0 {
				spec.UnicastHelloSeconds = 4
			}
		}
	}
}

// randomBabelRouterID returns 8 random octets as 16 lowercase hex
// characters, the stable identifier advertised by the Babel speaker.
func randomBabelRouterID() string {
	value, err := randomUint32()
	if err != nil {
		return "0000000000000001"
	}
	high, err := randomUint32()
	if err != nil {
		return "0000000000000001"
	}
	return fmt.Sprintf("%08x%08x", high, value)
}

func setXFRMDefaults(id string, ifID, reqID *uint32) {
	digest := sha256.Sum256([]byte(id))
	if *ifID == 0 {
		*ifID = binary.BigEndian.Uint32(digest[0:4]) & 0x7fffffff
		if *ifID == 0 {
			*ifID = 1
		}
	}
	if *reqID == 0 {
		*reqID = binary.BigEndian.Uint32(digest[4:8]) & 0x7fffffff
		if *reqID == 0 {
			*reqID = 1
		}
	}
}

func prepareSecrets(t *Tunnel, generate bool) error {
	switch t.Kind {
	case KindWireGuard:
		if t.Spec.WireGuard == nil {
			return errors.New("wireguard spec is required")
		}
		return ensureWireGuardKey(t.Spec.WireGuard, generate)
	case KindAmneziaWG:
		if t.Spec.AmneziaWG == nil {
			return errors.New("amneziawg spec is required")
		}
		return ensureWireGuardKey(&t.Spec.AmneziaWG.WireGuardSpec, generate)
	case KindXFRMStatic:
		if t.Spec.XFRMStatic == nil {
			return errors.New("xfrm_static spec is required")
		}
		return ensureStaticXFRMKeys(t.Spec.XFRMStatic, generate)
	case KindXFRMIKEv2:
		if t.Spec.XFRMIKEv2 == nil {
			return errors.New("xfrm_ikev2 spec is required")
		}
		return ensureIKECredentials(t.Spec.XFRMIKEv2, generate)
	default:
		return nil
	}
}

func ensureWireGuardKey(spec *WireGuardSpec, generate bool) error {
	if spec.PrivateKey == "" {
		if !generate {
			return errors.New("private_key is required when replacing WireGuard key material")
		}
		key, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			return fmt.Errorf("generate WireGuard private key: %w", err)
		}
		spec.PrivateKey = key.String()
	}
	key, err := wgtypes.ParseKey(spec.PrivateKey)
	if err != nil {
		return fmt.Errorf("parse WireGuard private key: %w", err)
	}
	spec.PublicKey = key.PublicKey().String()
	return nil
}

func ensureStaticXFRMKeys(spec *XFRMStaticSpec, generate bool) error {
	if spec.SPIInbound == 0 {
		if !generate {
			return errors.New("spi_inbound is required on update")
		}
		value, err := randomUint32()
		if err != nil {
			return err
		}
		spec.SPIInbound = value | 0x100
	}
	if spec.SPIOutbound == 0 {
		if !generate {
			return errors.New("spi_outbound is required on update")
		}
		value, err := randomUint32()
		if err != nil {
			return err
		}
		spec.SPIOutbound = value | 0x100
	}
	encSize := 20
	if spec.Algorithm == XFRMAESCBCSHA256 {
		encSize = 32
	}
	var err error
	if spec.EncryptionKeyIn == "" {
		if !generate {
			return errors.New("encryption_key_in is required when replacing XFRM key material")
		}
		spec.EncryptionKeyIn, err = randomHex(encSize)
		if err != nil {
			return err
		}
	}
	if spec.EncryptionKeyOut == "" {
		if !generate {
			return errors.New("encryption_key_out is required when replacing XFRM key material")
		}
		spec.EncryptionKeyOut, err = randomHex(encSize)
		if err != nil {
			return err
		}
	}
	if spec.Algorithm == XFRMAESCBCSHA256 {
		if spec.AuthenticationKeyIn == "" {
			if !generate {
				return errors.New("authentication_key_in is required when replacing XFRM key material")
			}
			spec.AuthenticationKeyIn, err = randomHex(32)
			if err != nil {
				return err
			}
		}
		if spec.AuthenticationKeyOut == "" {
			if !generate {
				return errors.New("authentication_key_out is required when replacing XFRM key material")
			}
			spec.AuthenticationKeyOut, err = randomHex(32)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func ensureIKECredentials(spec *XFRMIKEv2Spec, generate bool) error {
	switch spec.AuthMethod {
	case IKEAuthPSK:
		if spec.PSK == "" {
			if !generate {
				return errors.New("psk is required when switching IKE authentication")
			}
			value := make([]byte, 32)
			if _, err := rand.Read(value); err != nil {
				return fmt.Errorf("generate IKE PSK: %w", err)
			}
			spec.PSK = base64.RawURLEncoding.EncodeToString(value)
		}
	case IKEAuthRPK:
		if spec.LocalPrivateKey != "" || spec.LocalPublicKey != "" {
			if spec.LocalPrivateKey == "" || spec.LocalPublicKey == "" {
				return errors.New("local RPK private and public keys must be supplied together")
			}
			return nil
		}
		if !generate {
			return errors.New("local RPK key pair is required when switching IKE authentication")
		}
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return fmt.Errorf("generate ECDSA key: %w", err)
		}
		privateDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return fmt.Errorf("marshal ECDSA private key: %w", err)
		}
		publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			return fmt.Errorf("marshal ECDSA public key: %w", err)
		}
		spec.RPKAlgorithm = "ecdsa"
		spec.LocalPrivateKey = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}))
		spec.LocalPublicKey = base64.StdEncoding.EncodeToString(publicDER)
	}
	return nil
}

func randomHex(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate random key: %w", err)
	}
	return hex.EncodeToString(value), nil
}

func randomUint32() (uint32, error) {
	value := make([]byte, 4)
	if _, err := rand.Read(value); err != nil {
		return 0, fmt.Errorf("generate random uint32: %w", err)
	}
	return binary.BigEndian.Uint32(value), nil
}

func randomUintString() string {
	value, err := randomUint32()
	if err != nil || value == 0 {
		return "1"
	}
	return fmt.Sprintf("%d", value)
}

func MergeSecrets(next, current *Tunnel) {
	if next == nil || current == nil || next.Kind != current.Kind {
		return
	}
	switch next.Kind {
	case KindWireGuard:
		mergeWireGuardSecrets(next.Spec.WireGuard, current.Spec.WireGuard)
	case KindAmneziaWG:
		if next.Spec.AmneziaWG != nil && current.Spec.AmneziaWG != nil {
			mergeWireGuardSecrets(&next.Spec.AmneziaWG.WireGuardSpec, &current.Spec.AmneziaWG.WireGuardSpec)
		}
	case KindXFRMStatic:
		if next.Spec.XFRMStatic != nil && current.Spec.XFRMStatic != nil {
			n, c := next.Spec.XFRMStatic, current.Spec.XFRMStatic
			if n.Algorithm != c.Algorithm {
				break
			}
			if n.EncryptionKeyIn == "" {
				n.EncryptionKeyIn = c.EncryptionKeyIn
			}
			if n.EncryptionKeyOut == "" {
				n.EncryptionKeyOut = c.EncryptionKeyOut
			}
			if n.AuthenticationKeyIn == "" {
				n.AuthenticationKeyIn = c.AuthenticationKeyIn
			}
			if n.AuthenticationKeyOut == "" {
				n.AuthenticationKeyOut = c.AuthenticationKeyOut
			}
		}
	case KindXFRMIKEv2:
		if next.Spec.XFRMIKEv2 != nil && current.Spec.XFRMIKEv2 != nil {
			n, c := next.Spec.XFRMIKEv2, current.Spec.XFRMIKEv2
			switch n.AuthMethod {
			case IKEAuthPSK:
				n.RPKAlgorithm = ""
				n.LocalPrivateKey = ""
				n.LocalPublicKey = ""
				n.RemotePublicKey = ""
				if n.PSK == "" && c.AuthMethod == IKEAuthPSK {
					n.PSK = c.PSK
				}
			case IKEAuthRPK:
				n.PSK = ""
				if c.AuthMethod == IKEAuthRPK {
					if n.LocalPrivateKey == "" {
						n.LocalPrivateKey = c.LocalPrivateKey
					}
					if n.LocalPublicKey == "" {
						n.LocalPublicKey = c.LocalPublicKey
					}
					if n.RemotePublicKey == "" {
						n.RemotePublicKey = c.RemotePublicKey
					}
				}
			}
		}
	}
}

func mergeWireGuardSecrets(next, current *WireGuardSpec) {
	if next == nil || current == nil {
		return
	}
	if next.PrivateKey == "" {
		next.PrivateKey = current.PrivateKey
	}
	currentPeers := make(map[string]WireGuardPeer, len(current.Peers))
	for _, peer := range current.Peers {
		currentPeers[peer.PublicKey] = peer
	}
	for i := range next.Peers {
		if next.Peers[i].PresharedKey == ClearSecretValue {
			next.Peers[i].PresharedKey = ""
		} else if next.Peers[i].PresharedKey == "" {
			if old, ok := currentPeers[next.Peers[i].PublicKey]; ok {
				next.Peers[i].PresharedKey = old.PresharedKey
			}
		}
	}
}
