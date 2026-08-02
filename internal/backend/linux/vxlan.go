//go:build linux

package linux

import (
	"context"
	"fmt"

	"github.com/TunnelHelper/TH/internal/core"
	"github.com/TunnelHelper/TH/internal/model"
	"github.com/vishvananda/netlink"
)

func (b *Backend) applyVXLAN(ctx context.Context, record model.Tunnel) (core.Observation, error) {
	if err := ctx.Err(); err != nil {
		return core.Observation{}, err
	}
	spec := record.Spec.VXLAN
	underlay, err := b.linkByName(spec.UnderlayInterface)
	if err != nil {
		return core.Observation{}, fmt.Errorf("lookup VXLAN underlay %s: %w", spec.UnderlayInterface, err)
	}
	desired := &netlink.Vxlan{
		LinkAttrs: netlink.LinkAttrs{
			Name:        record.Interface,
			MTU:         spec.MTU,
			Alias:       ownershipAlias(record.ID),
			ParentIndex: underlay.Attrs().Index,
		},
		VxlanId:      spec.VNI,
		VtepDevIndex: underlay.Attrs().Index,
		SrcAddr:      ipFromAddr(spec.Local),
		Group:        ipFromAddr(spec.Remote),
		Port:         spec.DestinationPort,
		Learning:     spec.Learning,
	}
	link, err := b.ensureLink(record, desired, func(existing netlink.Link) bool {
		vxlan, ok := existing.(*netlink.Vxlan)
		return ok && vxlan.VxlanId == desired.VxlanId &&
			vxlan.VtepDevIndex == desired.VtepDevIndex &&
			vxlan.SrcAddr.Equal(desired.SrcAddr) && vxlan.Group.Equal(desired.Group) &&
			vxlan.Port == desired.Port && vxlan.Learning == desired.Learning
	})
	if err != nil {
		return core.Observation{}, err
	}
	if err := b.configureOwnedLink(record, link, spec.MTU, spec.Addresses); err != nil {
		return observationFromLink(link), fmt.Errorf("configure VXLAN link: %w", err)
	}
	return b.observeLink(record)
}
