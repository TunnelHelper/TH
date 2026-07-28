//go:build linux

package linux

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/TunnelHelper/TH/internal/core"
	"github.com/TunnelHelper/TH/internal/model"
	"github.com/vishvananda/netlink"
)

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
