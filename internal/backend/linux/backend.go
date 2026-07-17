//go:build linux

package linux

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"

	"github.com/TunnelHelper/TH/internal/config"
	"github.com/TunnelHelper/TH/internal/core"
	"github.com/TunnelHelper/TH/internal/model"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
)

const managedRouteProtocol = 242

var ErrOwnershipConflict = errors.New("kernel object is not owned by TH")

type Backend struct {
	settings config.Settings
	netlink  *netlink.Handle
	wg       *wgctrl.Client
	wgErr    error
	awg      *amneziaClient
	awgErr   error
	vici     *viciController
	eventCtx context.Context
	eventEnd context.CancelFunc
	events   chan struct{}
	eventWG  sync.WaitGroup
	close    sync.Once
}

func New(settings config.Settings) (*Backend, error) {
	handle, err := netlink.NewHandle(unix.NETLINK_ROUTE, unix.NETLINK_XFRM)
	if err != nil {
		return nil, fmt.Errorf("open netlink handles: %w", err)
	}
	if err := handle.SetSocketTimeout(settings.RequestTimeout()); err != nil {
		handle.Close()
		return nil, fmt.Errorf("set netlink timeout: %w", err)
	}
	wg, wgErr := wgctrl.New()
	awg, awgErr := newAmneziaClient(settings.RequestTimeout())
	eventCtx, eventEnd := context.WithCancel(context.Background())
	backend := &Backend{
		settings: settings,
		netlink:  handle,
		wg:       wg,
		wgErr:    wgErr,
		awg:      awg,
		awgErr:   awgErr,
		vici:     newVICIController(settings.VICISocketPath, settings.RequestTimeout()),
		eventCtx: eventCtx,
		eventEnd: eventEnd,
		events:   make(chan struct{}, 1),
	}
	backend.startEventWatchers()
	return backend, nil
}

func (b *Backend) Apply(ctx context.Context, record model.Tunnel) (core.Observation, error) {
	if err := ctx.Err(); err != nil {
		return core.Observation{}, err
	}
	switch record.Kind {
	case model.KindGRE:
		return b.applyGRE(ctx, record)
	case model.KindVXLAN:
		return b.applyVXLAN(ctx, record)
	case model.KindWireGuard:
		return b.applyWireGuard(ctx, record)
	case model.KindXFRMStatic:
		return b.applyStaticXFRM(ctx, record)
	case model.KindAmneziaWG:
		return b.applyAmneziaWG(ctx, record)
	case model.KindXFRMIKEv2:
		return b.applyIKEv2(ctx, record)
	case model.KindSRv6:
		return b.applySRv6(ctx, record)
	default:
		return core.Observation{}, fmt.Errorf("unsupported tunnel kind %q", record.Kind)
	}
}

func (b *Backend) Remove(ctx context.Context, record model.Tunnel) (core.Observation, error) {
	if err := ctx.Err(); err != nil {
		return core.Observation{}, err
	}
	var err error
	switch record.Kind {
	case model.KindWireGuard:
		err = errors.Join(b.removeWireGuardRoutes(record), b.removeOwnedLink(record))
	case model.KindXFRMStatic:
		if ownershipErr := b.assertLinkOwnershipOrMissing(record); ownershipErr != nil {
			err = ownershipErr
		} else {
			err = errors.Join(b.removeStaticXFRM(record), b.removeOwnedLink(record))
		}
	case model.KindGRE, model.KindVXLAN:
		err = b.removeOwnedLink(record)
	case model.KindAmneziaWG:
		err = errors.Join(b.removeWireGuardRoutes(record), b.removeOwnedLink(record))
	case model.KindXFRMIKEv2:
		err = b.removeIKEv2(ctx, record)
	case model.KindSRv6:
		err = b.removeSRv6(record)
	default:
		err = fmt.Errorf("unsupported tunnel kind %q", record.Kind)
	}
	return core.Observation{}, err
}

func (b *Backend) Observe(ctx context.Context, record model.Tunnel) (core.Observation, error) {
	if err := ctx.Err(); err != nil {
		return core.Observation{}, err
	}
	switch record.Kind {
	case model.KindSRv6:
		return b.observeSRv6(record)
	case model.KindWireGuard:
		return b.observeWireGuard(record)
	case model.KindAmneziaWG:
		return b.observeAmneziaWG(ctx, record)
	case model.KindXFRMStatic:
		return b.observeStaticXFRM(record)
	case model.KindXFRMIKEv2:
		return b.observeIKEv2(ctx, record)
	default:
		return b.observeLink(record)
	}
}

func (b *Backend) Health(ctx context.Context) map[model.Kind]core.BackendHealth {
	health := make(map[model.Kind]core.BackendHealth, len(model.Kinds))
	for _, kind := range model.Kinds {
		health[kind] = core.BackendHealth{Available: true}
	}
	if b.wgErr != nil {
		health[model.KindWireGuard] = core.BackendHealth{Available: false, Message: b.wgErr.Error()}
	}
	if b.awgErr != nil {
		health[model.KindAmneziaWG] = core.BackendHealth{Available: false, Message: b.awgErr.Error()}
	} else if err := b.awg.health(ctx); err != nil {
		health[model.KindAmneziaWG] = core.BackendHealth{Available: false, Message: err.Error()}
	}
	if err := b.vici.health(ctx); err != nil {
		health[model.KindXFRMIKEv2] = core.BackendHealth{Available: false, Message: err.Error()}
	}
	return health
}

func (b *Backend) Events() <-chan struct{} {
	return b.events
}

func (b *Backend) Close() error {
	var closeErr error
	b.close.Do(func() {
		b.eventEnd()
		b.eventWG.Wait()
		close(b.events)
		if b.wg != nil {
			closeErr = b.wg.Close()
		}
		if b.awg != nil {
			closeErr = errors.Join(closeErr, b.awg.Close())
		}
		b.netlink.Close()
	})
	return closeErr
}

func observationFromLink(link netlink.Link) core.Observation {
	if link == nil {
		return core.Observation{}
	}
	attrs := link.Attrs()
	return core.Observation{
		InterfaceExists: true,
		InterfaceUp:     attrs.Flags&net.FlagUp != 0,
		Details: map[string]string{
			"link_type": link.Type(),
			"mtu":       strconv.Itoa(attrs.MTU),
		},
	}
}
