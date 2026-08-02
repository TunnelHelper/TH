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
	settings     config.Settings
	netlink      *netlink.Handle
	wg           *wireGuardControl
	awg          *amneziaClient
	awgErr       error
	vici         *viciController
	babel        *babelEngine
	mptcp        *mptcpControl
	eventCtx     context.Context
	eventEnd     context.CancelFunc
	events       chan core.BackendEvent
	eventWG      sync.WaitGroup
	linkLookupMu sync.Mutex
	close        sync.Once
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
		babel:    nil,
		eventCtx: eventCtx,
		eventEnd: eventEnd,
		events:   make(chan core.BackendEvent, 64),
	}
	backend.babel, err = newBabelEngine(backend)
	if err != nil {
		handle.Close()
		return nil, fmt.Errorf("start Babel engine: %w", err)
	}
	backend.mptcp = newMptcpControl(backend)
	backend.startEventWatchers()
	return backend, nil
}

func (b *Backend) Apply(ctx context.Context, record model.Tunnel) (core.Observation, error) {
	if err := ctx.Err(); err != nil {
		return core.Observation{}, err
	}
	var observation core.Observation
	var err error
	switch record.Kind {
	case model.KindGRE:
		observation, err = b.applyGRE(ctx, record)
	case model.KindVXLAN:
		observation, err = b.applyVXLAN(ctx, record)
	case model.KindWireGuard:
		observation, err = b.applyWireGuard(ctx, record)
	case model.KindXFRMStatic:
		observation, err = b.applyStaticXFRM(ctx, record)
	case model.KindAmneziaWG:
		observation, err = b.applyAmneziaWG(ctx, record)
	case model.KindXFRMIKEv2:
		observation, err = b.applyIKEv2(ctx, record)
	case model.KindSRv6:
		observation, err = b.applySRv6(ctx, record)
	default:
		err = fmt.Errorf("unsupported tunnel kind %q", record.Kind)
	}

	// Reconcile Babel after the tunnel objects exist so a freshly created
	// link is picked up by the speaker immediately. A Babel failure must
	// not prevent the tunnel itself from being applied; it is retried on
	// the next reconcile pass.
	if record.Spec.Babel != nil && record.Spec.Babel.Enabled {
		b.babel.upsertTunnel(record)
	} else {
		b.babel.removeTunnel(record.ID)
	}
	if babelErr := b.babel.reconcile(); babelErr != nil {
		err = errors.Join(err, babelErr)
	}
	// MPTCP endpoints must be registered only after the link and its
	// addresses exist, so the endpoint follows the Apply in the same pass
	// instead of waiting for the next reconcile (see §5.3 of
	// docs/MPTCP_MANAGEMENT.md).
	if b.mptcp != nil {
		b.mptcp.upsertTunnel(record)
		if mptcpErr := b.mptcp.reconcile(ctx); mptcpErr != nil {
			err = errors.Join(err, mptcpErr)
		}
		appendObservationDetails(&observation, b.mptcp.observationDetails())
	}
	return observation, err
}

func (b *Backend) Remove(ctx context.Context, record model.Tunnel) (core.Observation, error) {
	if err := ctx.Err(); err != nil {
		return core.Observation{}, err
	}
	var err error
	// Endpoints must be withdrawn before the link disappears: the
	// ownership lookup for TH addresses relies on the tunnel record, so
	// deleting the endpoint first keeps the cleanup provable.
	if b.mptcp != nil {
		b.mptcp.removeTunnel(record)
		if mptcpErr := b.mptcp.reconcile(ctx); mptcpErr != nil {
			err = errors.Join(err, mptcpErr)
		}
	}
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
	b.babel.removeTunnel(record.ID)
	if babelErr := b.babel.reconcile(); babelErr != nil {
		err = errors.Join(err, babelErr)
	}
	return core.Observation{}, err
}

func (b *Backend) Observe(ctx context.Context, record model.Tunnel) (core.Observation, error) {
	if err := ctx.Err(); err != nil {
		return core.Observation{}, err
	}
	var observation core.Observation
	var err error
	switch record.Kind {
	case model.KindSRv6:
		observation, err = b.observeSRv6(record)
	case model.KindWireGuard:
		observation, err = b.observeWireGuard(ctx, record)
	case model.KindAmneziaWG:
		observation, err = b.observeAmneziaWG(ctx, record)
	case model.KindXFRMStatic:
		observation, err = b.observeStaticXFRM(record)
	case model.KindXFRMIKEv2:
		observation, err = b.observeIKEv2(ctx, record)
	default:
		if record.Spec.Babel != nil && record.Spec.Babel.Enabled {
			observation = b.babel.observe(record)
		} else {
			observation, err = b.observeLink(record)
		}
	}
	if b.mptcp != nil {
		appendObservationDetails(&observation, b.mptcp.observationDetails())
	}
	return observation, err
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

// ApplySettings applies a new daemon settings snapshot at runtime: Babel
// protocol settings and the MPTCP infrastructure switch.
func (b *Backend) ApplySettings(ctx context.Context, settings config.Settings) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := b.babel.refreshSettings(settings.Babel); err != nil {
		return err
	}
	if b.mptcp != nil {
		if err := b.mptcp.refreshSettings(ctx, settings.Mptcp); err != nil {
			return err
		}
	}
	return nil
}

// ReconcileGlobal reconciles daemon-global state from the authoritative
// tunnel list. It is invoked at daemon startup and on every periodic
// reconcile pass so both the Babel engine (including external interfaces
// with no tunnels at all) and the MPTCP endpoint set converge even when no
// per-tunnel event fired.
func (b *Backend) ReconcileGlobal(ctx context.Context, records []model.Tunnel) error {
	var err error
	if babelErr := b.babel.reconcile(); babelErr != nil {
		err = errors.Join(err, babelErr)
	}
	if b.mptcp == nil {
		return err
	}
	return errors.Join(err, b.mptcp.reconcileAll(ctx, records))
}

// MptcpHealth returns the daemon-wide MPTCP capability and endpoint
// snapshot for th health and the TUI.
func (b *Backend) MptcpHealth() core.MptcpHealth {
	if b.mptcp == nil {
		return core.MptcpHealth{}
	}
	return b.mptcp.health()
}

// BabelHealth returns the daemon-wide Babel state (the effective router ID)
// for th health and the TUI settings editor.
func (b *Backend) BabelHealth() core.BabelHealth {
	if b.babel == nil {
		return core.BabelHealth{}
	}
	return b.babel.health()
}

func (b *Backend) Close() error {
	var closeErr error
	b.close.Do(func() {
		b.eventEnd()
		b.eventWG.Wait()
		b.babel.close()
		if b.mptcp != nil {
			b.mptcp.close()
		}
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

func appendObservationDetails(observation *core.Observation, details map[string]string) {
	if len(details) == 0 {
		return
	}
	if observation.Details == nil {
		observation.Details = make(map[string]string, len(details))
	}
	for key, value := range details {
		observation.Details[key] = value
	}
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
