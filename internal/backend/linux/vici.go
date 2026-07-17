//go:build linux

package linux

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/TunnelHelper/TH/internal/core"
	"github.com/TunnelHelper/TH/internal/model"
	"github.com/strongswan/govici/vici"
	"github.com/vishvananda/netlink"
)

type viciController struct {
	path        string
	timeout     time.Duration
	dialContext func(context.Context, string, string) (net.Conn, error)
}

type viciConnection struct {
	Version     int                  `vici:"version"`
	Unique      string               `vici:"unique"`
	LocalAddrs  []string             `vici:"local_addrs"`
	RemoteAddrs []string             `vici:"remote_addrs"`
	Encap       bool                 `vici:"encap"`
	Local       viciAuth             `vici:"local"`
	Remote      viciAuth             `vici:"remote"`
	Children    map[string]viciChild `vici:"children"`
	Proposals   []string             `vici:"proposals"`
	RekeyTime   string               `vici:"rekey_time"`
	OverTime    string               `vici:"over_time"`
	DPDDelay    string               `vici:"dpd_delay"`
	DPDTimeout  string               `vici:"dpd_timeout"`
}

type viciAuth struct {
	Auth    string   `vici:"auth"`
	ID      string   `vici:"id"`
	Pubkeys []string `vici:"pubkeys"`
}

type viciChild struct {
	Mode         string   `vici:"mode"`
	LocalTS      []string `vici:"local_ts"`
	RemoteTS     []string `vici:"remote_ts"`
	IfIDIn       uint32   `vici:"if_id_in"`
	IfIDOut      uint32   `vici:"if_id_out"`
	ReqID        uint32   `vici:"reqid"`
	StartAction  string   `vici:"start_action"`
	CloseAction  string   `vici:"close_action"`
	ESPProposals []string `vici:"esp_proposals"`
	RekeyTime    string   `vici:"rekey_time"`
	LifeTime     string   `vici:"life_time"`
	DPDAction    string   `vici:"dpd_action"`
}

func newVICIController(path string, timeout time.Duration) *viciController {
	return &viciController{path: path, timeout: timeout}
}

func (c *viciController) session(ctx context.Context) (*vici.Session, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	dialContext := c.dialContext
	if dialContext == nil {
		dialContext = (&net.Dialer{Timeout: c.timeout}).DialContext
	}
	session, err := vici.NewSession(
		vici.WithAddr("unix", c.path),
		vici.WithDialContext(dialContext),
	)
	if err != nil {
		return nil, fmt.Errorf("connect VICI socket %s: %w", c.path, err)
	}
	return session, nil
}

func (c *viciController) call(ctx context.Context, command string, message *vici.Message) (*vici.Message, error) {
	session, err := c.session(ctx)
	if err != nil {
		return nil, err
	}
	defer session.Close()
	requestContext, requestCancel := context.WithTimeout(ctx, c.timeout)
	defer requestCancel()
	response, err := session.Call(requestContext, command, message)
	if err != nil {
		return response, fmt.Errorf("VICI %s: %w", command, err)
	}
	if response != nil {
		if err := response.Err(); err != nil {
			return response, fmt.Errorf("VICI %s: %w", command, err)
		}
	}
	return response, nil
}

func (c *viciController) streamCount(ctx context.Context, command, event string, message *vici.Message) (int, error) {
	session, err := c.session(ctx)
	if err != nil {
		return 0, err
	}
	defer session.Close()
	requestContext, requestCancel := context.WithTimeout(ctx, c.timeout)
	defer requestCancel()
	count := 0
	for item, err := range session.CallStreaming(requestContext, command, event, message) {
		if err != nil {
			return count, fmt.Errorf("VICI %s: %w", command, err)
		}
		if item != nil {
			count++
		}
	}
	return count, nil
}

func (c *viciController) watchEvents(ctx context.Context, notify func()) error {
	session, err := c.session(ctx)
	if err != nil {
		return err
	}
	defer session.Close()

	subscribeContext, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		result <- session.Subscribe("ike-updown", "child-updown")
	}()
	select {
	case err := <-result:
		if err != nil {
			return fmt.Errorf("subscribe to VICI events: %w", err)
		}
	case <-subscribeContext.Done():
		_ = session.Close()
		return fmt.Errorf("subscribe to VICI events: %w", subscribeContext.Err())
	}

	events := make(chan vici.Event, 16)
	session.NotifyEvents(events)
	defer session.StopEvents(events)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case _, ok := <-events:
			if !ok {
				return errors.New("VICI event stream closed")
			}
			notify()
		}
	}
}

func (c *viciController) health(ctx context.Context) error {
	_, err := c.call(ctx, "version", nil)
	return err
}

func connectionName(record model.Tunnel) string {
	return "th-" + record.ID
}

func childName(record model.Tunnel) string {
	return connectionName(record) + "-child"
}

func sharedKeyID(record model.Tunnel) string {
	return "th:" + record.ID
}

func buildVICIConnection(record model.Tunnel) (*vici.Message, error) {
	spec := record.Spec.XFRMIKEv2
	local := viciAuth{ID: spec.LocalID}
	remote := viciAuth{ID: spec.RemoteID}
	switch spec.AuthMethod {
	case model.IKEAuthPSK:
		local.Auth = "psk"
		remote.Auth = "psk"
	case model.IKEAuthRPK:
		local.Auth = "pubkey"
		remote.Auth = "pubkey"
		localPublic, err := base64.StdEncoding.DecodeString(spec.LocalPublicKey)
		if err != nil {
			return nil, fmt.Errorf("decode local RPK: %w", err)
		}
		remotePublic, err := base64.StdEncoding.DecodeString(spec.RemotePublicKey)
		if err != nil {
			return nil, fmt.Errorf("decode remote RPK: %w", err)
		}
		local.Pubkeys = []string{string(localPublic)}
		remote.Pubkeys = []string{string(remotePublic)}
	default:
		return nil, fmt.Errorf("unsupported IKE auth method %q", spec.AuthMethod)
	}
	connection := viciConnection{
		Version:     2,
		Unique:      "never",
		LocalAddrs:  []string{spec.LocalAddress},
		RemoteAddrs: []string{spec.RemoteAddress},
		Encap:       spec.Encapsulation,
		Local:       local,
		Remote:      remote,
		Children: map[string]viciChild{
			childName(record): {
				Mode:         "tunnel",
				LocalTS:      []string{"0.0.0.0/0", "::/0"},
				RemoteTS:     []string{"0.0.0.0/0", "::/0"},
				IfIDIn:       spec.IfID,
				IfIDOut:      spec.IfID,
				ReqID:        spec.ReqID,
				StartAction:  spec.StartAction,
				CloseAction:  "trap",
				ESPProposals: []string{spec.ESPProposal},
				RekeyTime:    "8h",
				LifeTime:     "10h",
				DPDAction:    "clear",
			},
		},
		Proposals:  []string{spec.IKEProposal},
		RekeyTime:  "1h",
		OverTime:   "90m",
		DPDDelay:   "60s",
		DPDTimeout: "300s",
	}
	inner, err := vici.MarshalMessage(&connection)
	if err != nil {
		return nil, fmt.Errorf("marshal VICI connection: %w", err)
	}
	outer := vici.NewMessage()
	if err := outer.Set(connectionName(record), inner); err != nil {
		return nil, fmt.Errorf("wrap VICI connection: %w", err)
	}
	return outer, nil
}

func (c *viciController) loadConnection(ctx context.Context, record model.Tunnel) error {
	message, err := buildVICIConnection(record)
	if err != nil {
		return err
	}
	_, err = c.call(ctx, "load-conn", message)
	return err
}

func (c *viciController) loadShared(ctx context.Context, record model.Tunnel) error {
	spec := record.Spec.XFRMIKEv2
	message := vici.NewMessage()
	for name, value := range map[string]any{
		"id":     sharedKeyID(record),
		"type":   "IKE",
		"data":   spec.PSK,
		"owners": []string{spec.LocalID, spec.RemoteID},
	} {
		if err := message.Set(name, value); err != nil {
			return err
		}
	}
	_, err := c.call(ctx, "load-shared", message)
	return err
}

func (c *viciController) unloadShared(ctx context.Context, record model.Tunnel) error {
	message := vici.NewMessage()
	if err := message.Set("id", sharedKeyID(record)); err != nil {
		return err
	}
	_, err := c.call(ctx, "unload-shared", message)
	return err
}

func (c *viciController) loadPrivateKey(ctx context.Context, record model.Tunnel) (string, error) {
	spec := record.Spec.XFRMIKEv2
	if spec.LocalPrivateKey == "" {
		return "", errors.New("local RPK private key is empty")
	}
	message := vici.NewMessage()
	if err := message.Set("type", spec.RPKAlgorithm); err != nil {
		return "", err
	}
	if err := message.Set("data", spec.LocalPrivateKey); err != nil {
		return "", err
	}
	response, err := c.call(ctx, "load-key", message)
	if err != nil {
		return "", err
	}
	id, ok := response.Get("id").(string)
	if !ok || id == "" {
		return "", errors.New("VICI load-key returned no key id")
	}
	expected, err := privateKeyID(record)
	if err != nil {
		return "", err
	}
	if !strings.EqualFold(id, expected) {
		return "", fmt.Errorf("VICI loaded private key as %s, expected %s", id, expected)
	}
	return id, nil
}

func (c *viciController) ensurePrivateKey(ctx context.Context, record model.Tunnel) error {
	id, err := privateKeyID(record)
	if err != nil {
		return err
	}
	loaded, err := c.keyLoaded(ctx, id)
	if err != nil {
		return err
	}
	if loaded {
		return nil
	}
	_, err = c.loadPrivateKey(ctx, record)
	return err
}

func (c *viciController) unloadPrivateKey(ctx context.Context, record model.Tunnel) error {
	if record.Spec.XFRMIKEv2.LocalPrivateKey == "" {
		return nil
	}
	id, err := privateKeyID(record)
	if err != nil {
		return err
	}
	loaded, err := c.keyLoaded(ctx, id)
	if err != nil || !loaded {
		return err
	}
	message := vici.NewMessage()
	if err := message.Set("id", id); err != nil {
		return err
	}
	_, err = c.call(ctx, "unload-key", message)
	return err
}

func privateKeyID(record model.Tunnel) (string, error) {
	spec := record.Spec.XFRMIKEv2
	der, err := base64.StdEncoding.DecodeString(spec.LocalPublicKey)
	if err != nil {
		return "", fmt.Errorf("decode local public key for VICI key id: %w", err)
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return "", fmt.Errorf("parse local public key for VICI key id: %w", err)
	}
	publicKey, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return "", fmt.Errorf("unsupported local public key type %T", parsed)
	}
	encoded := publicKey.Curve.Params()
	if encoded == nil {
		return "", errors.New("local public key has no curve parameters")
	}
	width := (encoded.BitSize + 7) / 8
	point := make([]byte, 1+2*width)
	point[0] = 4
	publicKey.X.FillBytes(point[1 : 1+width])
	publicKey.Y.FillBytes(point[1+width:])
	digest := sha1.Sum(point)
	return hex.EncodeToString(digest[:]), nil
}

func (c *viciController) keyLoaded(ctx context.Context, id string) (bool, error) {
	response, err := c.call(ctx, "get-keys", nil)
	if err != nil {
		return false, err
	}
	keys, ok := response.Get("keys").([]string)
	if !ok {
		return false, nil
	}
	for _, key := range keys {
		if key == id {
			return true, nil
		}
	}
	return false, nil
}

func (c *viciController) connectionLoaded(ctx context.Context, record model.Tunnel) (bool, error) {
	response, err := c.call(ctx, "get-conns", nil)
	if err != nil {
		return false, err
	}
	connections, ok := response.Get("conns").([]string)
	if !ok {
		return false, nil
	}
	for _, name := range connections {
		if name == connectionName(record) {
			return true, nil
		}
	}
	return false, nil
}

func (c *viciController) unloadConnection(ctx context.Context, record model.Tunnel) error {
	loaded, err := c.connectionLoaded(ctx, record)
	if err != nil || !loaded {
		return err
	}
	return c.unloadKnownConnection(ctx, record)
}

func (c *viciController) unloadKnownConnection(ctx context.Context, record model.Tunnel) error {
	message := vici.NewMessage()
	if err := message.Set("name", connectionName(record)); err != nil {
		return err
	}
	_, err := c.call(ctx, "unload-conn", message)
	return err
}

func (c *viciController) initiate(ctx context.Context, record model.Tunnel) error {
	message := vici.NewMessage()
	if err := message.Set("ike", connectionName(record)); err != nil {
		return err
	}
	if err := message.Set("child", childName(record)); err != nil {
		return err
	}
	if err := message.Set("timeout", int(c.timeout.Milliseconds())); err != nil {
		return err
	}
	_, err := c.streamCount(ctx, "initiate", "control-log", message)
	return err
}

func (c *viciController) terminate(ctx context.Context, record model.Tunnel) error {
	message := vici.NewMessage()
	if err := message.Set("ike", connectionName(record)); err != nil {
		return err
	}
	if err := message.Set("timeout", int(c.timeout.Milliseconds())); err != nil {
		return err
	}
	_, err := c.streamCount(ctx, "terminate", "control-log", message)
	return err
}

func (c *viciController) countSAs(ctx context.Context, record model.Tunnel) (int, error) {
	message := vici.NewMessage()
	if err := message.Set("ike", connectionName(record)); err != nil {
		return 0, err
	}
	return c.streamCount(ctx, "list-sas", "list-sa", message)
}

func (b *Backend) applyIKEv2(ctx context.Context, record model.Tunnel) (core.Observation, error) {
	spec := record.Spec.XFRMIKEv2
	if err := b.preflightXFRMOwnership(record, spec.IfID, spec.ReqID); err != nil {
		return core.Observation{}, err
	}
	underlay, err := b.netlink.LinkByName(spec.UnderlayInterface)
	if err != nil {
		return core.Observation{}, fmt.Errorf("lookup XFRM underlay %s: %w", spec.UnderlayInterface, err)
	}
	desired := &netlink.Xfrmi{
		LinkAttrs: netlink.LinkAttrs{
			Name:        record.Interface,
			MTU:         spec.MTU,
			Alias:       ownershipAlias(record.ID),
			ParentIndex: underlay.Attrs().Index,
		},
		Ifid: spec.IfID,
	}
	link, err := b.ensureLink(record, desired, func(existing netlink.Link) bool {
		xfrmi, ok := existing.(*netlink.Xfrmi)
		return ok && xfrmi.Ifid == desired.Ifid && xfrmi.Attrs().ParentIndex == desired.Attrs().ParentIndex
	})
	if err != nil {
		return core.Observation{}, err
	}
	if err := b.configureOwnedLink(record, link, spec.MTU, spec.Addresses); err != nil {
		return observationFromLink(link), err
	}
	switch spec.AuthMethod {
	case model.IKEAuthPSK:
		if err := b.vici.unloadPrivateKey(ctx, record); err != nil {
			return observationFromLink(link), err
		}
		if err := b.vici.loadShared(ctx, record); err != nil {
			return observationFromLink(link), err
		}
	case model.IKEAuthRPK:
		if err := b.vici.unloadShared(ctx, record); err != nil {
			return observationFromLink(link), err
		}
		if err := b.vici.ensurePrivateKey(ctx, record); err != nil {
			return observationFromLink(link), err
		}
	}
	if err := b.vici.loadConnection(ctx, record); err != nil {
		return observationFromLink(link), err
	}
	if spec.StartAction == "start" {
		count, err := b.vici.countSAs(ctx, record)
		if err != nil {
			return observationFromLink(link), err
		}
		if count == 0 {
			if err := b.vici.initiate(ctx, record); err != nil {
				return observationFromLink(link), err
			}
		}
	}
	return b.observeIKEv2(ctx, record)
}

func (b *Backend) removeIKEv2(ctx context.Context, record model.Tunnel) error {
	var result error
	loaded, err := b.vici.connectionLoaded(ctx, record)
	if err != nil {
		result = errors.Join(result, err)
	}
	count, err := b.vici.countSAs(ctx, record)
	if err != nil {
		result = errors.Join(result, err)
	} else if count > 0 {
		if err := b.vici.terminate(ctx, record); err != nil {
			result = errors.Join(result, err)
		}
	}
	if loaded {
		if err := b.vici.unloadKnownConnection(ctx, record); err != nil {
			result = errors.Join(result, err)
		}
	}
	if err := b.vici.unloadShared(ctx, record); err != nil {
		result = errors.Join(result, err)
	}
	if err := b.vici.unloadPrivateKey(ctx, record); err != nil {
		result = errors.Join(result, err)
	}
	return errors.Join(result, b.removeOwnedLink(record))
}

func (b *Backend) observeIKEv2(ctx context.Context, record model.Tunnel) (core.Observation, error) {
	observation, err := b.observeLink(record)
	if err != nil {
		return observation, err
	}
	loaded, err := b.vici.connectionLoaded(ctx, record)
	if err != nil {
		return observation, err
	}
	count, err := b.vici.countSAs(ctx, record)
	if err != nil {
		return observation, err
	}
	if observation.Details == nil {
		observation.Details = make(map[string]string)
	}
	observation.Details["vici_connection"] = strconv.FormatBool(loaded)
	observation.Details["ike_sas"] = strconv.Itoa(count)
	if !loaded {
		return observation, errors.New("VICI connection is not loaded")
	}
	return observation, nil
}
