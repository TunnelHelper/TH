//go:build linux

package linux

import (
	"context"
	"fmt"

	"github.com/TunnelHelper/TH/internal/core"
	"github.com/TunnelHelper/TH/internal/model"
	"github.com/vishvananda/netlink"
)

func (b *Backend) applyGRE(ctx context.Context, record model.Tunnel) (core.Observation, error) {
	if err := ctx.Err(); err != nil {
		return core.Observation{}, err
	}
	spec := record.Spec.GRE
	desired := &netlink.Gretun{
		LinkAttrs: netlink.LinkAttrs{
			Name:  record.Interface,
			MTU:   spec.MTU,
			Alias: ownershipAlias(record.ID),
		},
		Local:  ipFromAddr(spec.Local),
		Remote: ipFromAddr(spec.Remote),
		Ttl:    spec.TTL,
	}
	link, err := b.ensureLink(record, desired, func(existing netlink.Link) bool {
		gre, ok := existing.(*netlink.Gretun)
		return ok && gre.Local.Equal(desired.Local) && gre.Remote.Equal(desired.Remote) && gre.Ttl == desired.Ttl
	})
	if err != nil {
		return core.Observation{}, err
	}
	if err := b.configureOwnedLink(record, link, spec.MTU, spec.Addresses); err != nil {
		return observationFromLink(link), fmt.Errorf("configure GRE link: %w", err)
	}
	return b.observeLink(record)
}
