//go:build linux

package linux

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"syscall"

	"github.com/TunnelHelper/TH/internal/core"
	"github.com/TunnelHelper/TH/internal/model"
	"github.com/vishvananda/netlink"
)

func (b *Backend) applyStaticXFRM(ctx context.Context, record model.Tunnel) (core.Observation, error) {
	if err := ctx.Err(); err != nil {
		return core.Observation{}, err
	}
	spec := record.Spec.XFRMStatic
	if err := b.preflightXFRMOwnership(record, spec.IfID, spec.ReqID); err != nil {
		return core.Observation{}, err
	}
	underlay, err := b.linkByName(spec.UnderlayInterface)
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
	if err := b.reconcileStaticStates(spec); err != nil {
		return observationFromLink(link), err
	}
	if err := b.reconcileStaticPolicies(spec); err != nil {
		return observationFromLink(link), err
	}
	return b.observeStaticXFRM(record)
}

func (b *Backend) preflightXFRMOwnership(record model.Tunnel, ifID, reqID uint32) error {
	ownedLink := false
	link, err := b.linkByName(record.Interface)
	if err == nil {
		if link.Attrs().Alias != ownershipAlias(record.ID) {
			return fmt.Errorf("link %s has alias %q: %w", record.Interface, link.Attrs().Alias, ErrOwnershipConflict)
		}
		ownedLink = true
	} else if !isLinkNotFound(err) {
		return fmt.Errorf("look up XFRM link: %w", err)
	}
	links, err := b.netlink.LinkList()
	if err != nil {
		return fmt.Errorf("list links for XFRM ownership: %w", err)
	}
	for _, candidate := range links {
		xfrmi, ok := candidate.(*netlink.Xfrmi)
		if !ok || xfrmi.Ifid != ifID {
			continue
		}
		if candidate.Attrs().Alias != ownershipAlias(record.ID) || candidate.Attrs().Name != record.Interface {
			return fmt.Errorf("XFRM if_id %d is used by link %s: %w", ifID, candidate.Attrs().Name, ErrOwnershipConflict)
		}
	}
	if ownedLink {
		return nil
	}
	states, err := b.netlink.XfrmStateList(netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("list XFRM states for ownership: %w", err)
	}
	for _, state := range states {
		if state.Ifid == int(ifID) || state.Reqid == int(reqID) {
			return fmt.Errorf("XFRM state uses if_id %d or reqid %d without an owned link: %w", ifID, reqID, ErrOwnershipConflict)
		}
	}
	policies, err := b.listXFRMPolicies()
	if err != nil {
		return fmt.Errorf("list XFRM policies for ownership: %w", err)
	}
	for _, policy := range policies {
		if policy.Ifid == int(ifID) {
			return fmt.Errorf("XFRM policy uses if_id %d without an owned link: %w", ifID, ErrOwnershipConflict)
		}
		for _, template := range policy.Tmpls {
			if template.Reqid == int(reqID) {
				return fmt.Errorf("XFRM policy uses reqid %d without an owned link: %w", reqID, ErrOwnershipConflict)
			}
		}
	}
	return nil
}

func (b *Backend) desiredStaticStates(spec *model.XFRMStaticSpec) ([]netlink.XfrmState, error) {
	in := netlink.XfrmState{
		Src:   ipFromAddr(spec.Remote),
		Dst:   ipFromAddr(spec.Local),
		Proto: netlink.XFRM_PROTO_ESP,
		Mode:  netlink.XFRM_MODE_TUNNEL,
		Spi:   int(spec.SPIInbound),
		Reqid: int(spec.ReqID),
		Ifid:  int(spec.IfID),
	}
	out := netlink.XfrmState{
		Src:   ipFromAddr(spec.Local),
		Dst:   ipFromAddr(spec.Remote),
		Proto: netlink.XFRM_PROTO_ESP,
		Mode:  netlink.XFRM_MODE_TUNNEL,
		Spi:   int(spec.SPIOutbound),
		Reqid: int(spec.ReqID),
		Ifid:  int(spec.IfID),
	}
	encIn, _ := hex.DecodeString(spec.EncryptionKeyIn)
	encOut, _ := hex.DecodeString(spec.EncryptionKeyOut)
	switch spec.Algorithm {
	case model.XFRMAESGCM:
		in.Aead = &netlink.XfrmStateAlgo{Name: "rfc4106(gcm(aes))", Key: encIn, ICVLen: 128}
		out.Aead = &netlink.XfrmStateAlgo{Name: "rfc4106(gcm(aes))", Key: encOut, ICVLen: 128}
	case model.XFRMAESCBCSHA256:
		authIn, _ := hex.DecodeString(spec.AuthenticationKeyIn)
		authOut, _ := hex.DecodeString(spec.AuthenticationKeyOut)
		in.Crypt = &netlink.XfrmStateAlgo{Name: "cbc(aes)", Key: encIn}
		out.Crypt = &netlink.XfrmStateAlgo{Name: "cbc(aes)", Key: encOut}
		in.Auth = &netlink.XfrmStateAlgo{Name: "hmac(sha256)", Key: authIn, TruncateLen: 128}
		out.Auth = &netlink.XfrmStateAlgo{Name: "hmac(sha256)", Key: authOut, TruncateLen: 128}
	default:
		return nil, fmt.Errorf("unsupported static XFRM algorithm %q", spec.Algorithm)
	}
	return []netlink.XfrmState{in, out}, nil
}

func (b *Backend) reconcileStaticStates(spec *model.XFRMStaticSpec) error {
	desired, err := b.desiredStaticStates(spec)
	if err != nil {
		return err
	}
	current, err := b.netlink.XfrmStateList(netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("list XFRM states: %w", err)
	}
	owned := make([]netlink.XfrmState, 0, 2)
	for _, state := range current {
		if state.Ifid == int(spec.IfID) && state.Reqid == int(spec.ReqID) {
			owned = append(owned, state)
		}
	}
	for i := range desired {
		found := -1
		for j := range owned {
			if sameStateIdentity(&desired[i], &owned[j]) {
				found = j
				break
			}
		}
		if found >= 0 {
			if equalState(&desired[i], &owned[found]) {
				owned = append(owned[:found], owned[found+1:]...)
				continue
			}
			if err := b.netlink.XfrmStateDel(&owned[found]); err != nil && !errors.Is(err, syscall.ESRCH) {
				return fmt.Errorf("replace XFRM state: %w", err)
			}
			owned = append(owned[:found], owned[found+1:]...)
		}
		if err := b.netlink.XfrmStateAdd(&desired[i]); err != nil {
			return fmt.Errorf("add XFRM state: %w", err)
		}
	}
	for i := range owned {
		if err := b.netlink.XfrmStateDel(&owned[i]); err != nil && !errors.Is(err, syscall.ESRCH) {
			return fmt.Errorf("remove stale XFRM state: %w", err)
		}
	}
	return nil
}

func (b *Backend) desiredStaticPolicies(spec *model.XFRMStaticSpec) []netlink.XfrmPolicy {
	policies := make([]netlink.XfrmPolicy, 0, 6)
	for _, family := range []int{4, 6} {
		bits := 32
		zero := net.IPv4zero
		if family == 6 {
			bits = 128
			zero = net.IPv6zero
		}
		wildcard := &net.IPNet{IP: zero, Mask: net.CIDRMask(0, bits)}
		for _, direction := range []netlink.Dir{netlink.XFRM_DIR_IN, netlink.XFRM_DIR_FWD, netlink.XFRM_DIR_OUT} {
			src, dst := spec.Remote, spec.Local
			if direction == netlink.XFRM_DIR_OUT {
				src, dst = spec.Local, spec.Remote
			}
			policies = append(policies, netlink.XfrmPolicy{
				Src:      wildcard,
				Dst:      wildcard,
				Dir:      direction,
				Action:   netlink.XFRM_POLICY_ALLOW,
				Ifid:     int(spec.IfID),
				Priority: 0,
				Tmpls: []netlink.XfrmPolicyTmpl{{
					Src:   ipFromAddr(src),
					Dst:   ipFromAddr(dst),
					Proto: netlink.XFRM_PROTO_ESP,
					Mode:  netlink.XFRM_MODE_TUNNEL,
					Reqid: int(spec.ReqID),
				}},
			})
		}
	}
	return policies
}

func (b *Backend) reconcileStaticPolicies(spec *model.XFRMStaticSpec) error {
	desired := b.desiredStaticPolicies(spec)
	current, err := b.listXFRMPolicies()
	if err != nil {
		return fmt.Errorf("list XFRM policies: %w", err)
	}
	owned := make([]netlink.XfrmPolicy, 0, len(desired))
	for _, policy := range current {
		if policy.Ifid != int(spec.IfID) {
			continue
		}
		for _, tmpl := range policy.Tmpls {
			if tmpl.Reqid == int(spec.ReqID) {
				owned = append(owned, policy)
				break
			}
		}
	}
	for i := range desired {
		found := -1
		for j := range owned {
			if samePolicyIdentity(&desired[i], &owned[j]) {
				found = j
				break
			}
		}
		if found >= 0 {
			if equalPolicy(&desired[i], &owned[found]) {
				owned = append(owned[:found], owned[found+1:]...)
				continue
			}
			if err := b.netlink.XfrmPolicyDel(&owned[found]); err != nil && !errors.Is(err, syscall.ENOENT) {
				return fmt.Errorf("replace XFRM policy: %w", err)
			}
			owned = append(owned[:found], owned[found+1:]...)
		}
		if err := b.netlink.XfrmPolicyAdd(&desired[i]); err != nil {
			return fmt.Errorf("add XFRM policy: %w", err)
		}
	}
	for i := range owned {
		if err := b.netlink.XfrmPolicyDel(&owned[i]); err != nil && !errors.Is(err, syscall.ENOENT) {
			return fmt.Errorf("remove stale XFRM policy: %w", err)
		}
	}
	return nil
}

func (b *Backend) removeStaticXFRM(record model.Tunnel) error {
	spec := record.Spec.XFRMStatic
	if spec == nil {
		return nil
	}
	states, err := b.netlink.XfrmStateList(netlink.FAMILY_ALL)
	if err != nil {
		return err
	}
	for i := range states {
		if states[i].Ifid == int(spec.IfID) && states[i].Reqid == int(spec.ReqID) {
			if err := b.netlink.XfrmStateDel(&states[i]); err != nil && !errors.Is(err, syscall.ESRCH) {
				return err
			}
		}
	}
	policies, err := b.listXFRMPolicies()
	if err != nil {
		return err
	}
	for i := range policies {
		if policies[i].Ifid != int(spec.IfID) {
			continue
		}
		for _, tmpl := range policies[i].Tmpls {
			if tmpl.Reqid == int(spec.ReqID) {
				if err := b.netlink.XfrmPolicyDel(&policies[i]); err != nil && !errors.Is(err, syscall.ENOENT) {
					return err
				}
				break
			}
		}
	}
	return nil
}

func (b *Backend) observeStaticXFRM(record model.Tunnel) (core.Observation, error) {
	observation, err := b.observeLink(record)
	if err != nil || !observation.InterfaceExists {
		return observation, err
	}
	spec := record.Spec.XFRMStatic
	states, err := b.netlink.XfrmStateList(netlink.FAMILY_ALL)
	if err != nil {
		return observation, err
	}
	policies, err := b.listXFRMPolicies()
	if err != nil {
		return observation, err
	}
	stateCount, policyCount := 0, 0
	for _, state := range states {
		if state.Ifid == int(spec.IfID) && state.Reqid == int(spec.ReqID) {
			stateCount++
		}
	}
	for _, policy := range policies {
		if policy.Ifid == int(spec.IfID) {
			for _, tmpl := range policy.Tmpls {
				if tmpl.Reqid == int(spec.ReqID) {
					policyCount++
					break
				}
			}
		}
	}
	observation.Details["xfrm_states"] = strconv.Itoa(stateCount)
	observation.Details["xfrm_policies"] = strconv.Itoa(policyCount)
	if stateCount != 2 || policyCount != 6 {
		return observation, fmt.Errorf("expected 2 XFRM states and 6 policies, observed %d and %d", stateCount, policyCount)
	}
	return observation, nil
}

func (b *Backend) listXFRMPolicies() ([]netlink.XfrmPolicy, error) {
	var policies []netlink.XfrmPolicy
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		items, err := b.netlink.XfrmPolicyList(family)
		if err != nil {
			return nil, err
		}
		policies = append(policies, items...)
	}
	return policies, nil
}

func sameStateIdentity(a, b *netlink.XfrmState) bool {
	return a.Src.Equal(b.Src) && a.Dst.Equal(b.Dst) && a.Proto == b.Proto && a.Spi == b.Spi && a.Ifid == b.Ifid && a.Reqid == b.Reqid
}

func equalState(a, b *netlink.XfrmState) bool {
	return sameStateIdentity(a, b) && a.Mode == b.Mode && equalAlgo(a.Aead, b.Aead) && equalAlgo(a.Crypt, b.Crypt) && equalAlgo(a.Auth, b.Auth)
}

func equalAlgo(a, b *netlink.XfrmStateAlgo) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Name == b.Name && a.TruncateLen == b.TruncateLen && a.ICVLen == b.ICVLen && bytes.Equal(a.Key, b.Key)
}

func samePolicyIdentity(a, b *netlink.XfrmPolicy) bool {
	return a.Dir == b.Dir && a.Ifid == b.Ifid && a.Src.String() == b.Src.String() && a.Dst.String() == b.Dst.String()
}

func equalPolicy(a, b *netlink.XfrmPolicy) bool {
	if !samePolicyIdentity(a, b) || a.Action != b.Action || len(a.Tmpls) != len(b.Tmpls) {
		return false
	}
	for i := range a.Tmpls {
		at, bt := a.Tmpls[i], b.Tmpls[i]
		if !at.Src.Equal(bt.Src) || !at.Dst.Equal(bt.Dst) || at.Proto != bt.Proto || at.Mode != bt.Mode || at.Reqid != bt.Reqid {
			return false
		}
	}
	return true
}
