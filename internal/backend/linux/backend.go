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
)

const managedRouteProtocol = 242

var ErrOwnershipConflict = errors.New("kernel object is not owned by TH")

func routeOwnedByRecord(record model.Tunnel, route netlink.Route) bool {
	return route.Protocol == managedRouteProtocol && route.Realm == model.ManagedRouteRealm(record)
}

func legacyExpectedRoute(route netlink.Route, expectedKeys map[string]netlink.Route) bool {
	if route.Protocol != managedRouteProtocol || route.Realm != 0 {
		return false
	}
	_, expected := expectedKeys[managedRouteKey(route)]
	return expected
}

type Backend struct {
	settings config.Settings
	netlink  *netlink.Handle
	wg       *wireGuardControl
	awg      *amneziaClient
	awgErr   error
	vici     *viciController
	babel    *babelRegistry
	eventCtx context.Context
	eventEnd context.CancelFunc
	events   chan core.BackendEvent
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
	awg, awgErr := newAmneziaClient(settings.RequestTimeout())
	eventCtx, eventEnd := context.WithCancel(context.Background())
	backend := &Backend{
		settings: settings,
		netlink:  handle,
		wg:       newWireGuardControl(settings.RequestTimeout()),
		awg:      awg,
		awgErr:   awgErr,
		vici:     newVICIController(settings.VICISocketPath, settings.RequestTimeout()),
		babel:    newBabelRegistry(),
		eventCtx: eventCtx,
		eventEnd: eventEnd,
		events:   make(chan core.BackendEvent, 64),
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
	case model.KindBabel:
		return b.applyBabel(ctx, record)
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
	case model.KindBabel:
		_, err = b.removeBabel(record)
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
		return b.observeWireGuard(ctx, record)
	case model.KindAmneziaWG:
		return b.observeAmneziaWG(ctx, record)
	case model.KindXFRMStatic:
		return b.observeStaticXFRM(record)
	case model.KindXFRMIKEv2:
		return b.observeIKEv2(ctx, record)
	case model.KindBabel:
		return b.observeBabel(record)
	default:
		return b.observeLink(record)
	}
}

func (b *Backend) Health(ctx context.Context) map[model.Kind]core.BackendHealth {
	health := make(map[model.Kind]core.BackendHealth, len(model.Kinds))
	for _, kind := range model.Kinds {
		health[kind] = core.BackendHealth{Available: true}
	}
	if err := b.wg.health(ctx); err != nil {
		health[model.KindWireGuard] = core.BackendHealth{Available: false, Message: err.Error()}
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

func (b *Backend) Events() <-chan core.BackendEvent {
	return b.events
}

func (b *Backend) Close() error {
	var closeErr error
	b.close.Do(func() {
		b.eventEnd()
		b.eventWG.Wait()
		b.closeBabelInstances()
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
	details := map[string]string{
		"link_type": link.Type(),
		"mtu":       strconv.Itoa(attrs.MTU),
	}
	if statistics := attrs.Statistics; statistics != nil {
		details["link_receive_bytes"] = strconv.FormatUint(statistics.RxBytes, 10)
		details["link_transmit_bytes"] = strconv.FormatUint(statistics.TxBytes, 10)
		details["receive_bytes"] = details["link_receive_bytes"]
		details["transmit_bytes"] = details["link_transmit_bytes"]
		details["counter_source"] = "link"
	}
	return core.Observation{
		InterfaceExists: true,
		InterfaceUp:     attrs.Flags&net.FlagUp != 0,
		Details:         details,
	}
}
