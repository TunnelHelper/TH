//go:build linux && integration

package linux

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/TunnelHelper/TH/internal/config"
	"github.com/TunnelHelper/TH/internal/model"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestNamespaceTunnelLifecycles(t *testing.T) {
	restore := enterTestNamespace(t)
	defer restore()

	loopback, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(loopback); err != nil {
		t.Fatal(err)
	}
	for _, prefix := range []string{"192.0.2.1/32", "2001:db8::1/128"} {
		if err := netlink.AddrAdd(loopback, &netlink.Addr{IPNet: prefixToIPNet(netip.MustParsePrefix(prefix))}); err != nil && !errors.Is(err, syscall.EEXIST) {
			t.Fatal(err)
		}
	}
	underlay := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "underlay0"}}
	if err := netlink.LinkAdd(underlay); err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(underlay); err != nil {
		t.Fatal(err)
	}
	if err := netlink.AddrAdd(underlay, &netlink.Addr{IPNet: prefixToIPNet(netip.MustParsePrefix("198.51.100.1/24"))}); err != nil {
		t.Fatal(err)
	}

	settings := config.Defaults()
	settings.StateDir = t.TempDir()
	settings.RuntimeDir = t.TempDir()
	settings.SocketPath = settings.RuntimeDir + "/control.sock"
	settings.VICISocketPath = settings.RuntimeDir + "/missing.vici"
	settings.RequestTimeoutSeconds = 1
	backend, err := New(settings)
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()

	t.Run("gre-ipv4", func(t *testing.T) {
		record := prepareIntegrationRecord(t, model.Tunnel{
			Name: "gre4", Kind: model.KindGRE, Interface: "gre4",
			Spec: model.Spec{GRE: &model.GRESpec{
				Local: netip.MustParseAddr("192.0.2.1"), Remote: netip.MustParseAddr("192.0.2.2"),
				Addresses: []netip.Prefix{netip.MustParsePrefix("10.0.0.1/30")},
			}},
		})
		assertLifecycle(t, backend, record)
	})

	t.Run("gre-ipv6", func(t *testing.T) {
		record := prepareIntegrationRecord(t, model.Tunnel{
			Name: "gre6", Kind: model.KindGRE, Interface: "gre6",
			Spec: model.Spec{GRE: &model.GRESpec{
				Local: netip.MustParseAddr("2001:db8::1"), Remote: netip.MustParseAddr("2001:db8::2"),
				Addresses: []netip.Prefix{netip.MustParsePrefix("fd00::1/127")},
			}},
		})
		assertLifecycle(t, backend, record)
	})

	t.Run("vxlan", func(t *testing.T) {
		record := prepareIntegrationRecord(t, model.Tunnel{
			Name: "vxlan", Kind: model.KindVXLAN, Interface: "vxlan0",
			Spec: model.Spec{VXLAN: &model.VXLANSpec{
				VNI: 100, UnderlayInterface: "underlay0", Local: netip.MustParseAddr("198.51.100.1"),
				Remote: netip.MustParseAddr("198.51.100.2"), Addresses: []netip.Prefix{netip.MustParsePrefix("10.1.0.1/30")},
			}},
		})
		assertLifecycle(t, backend, record)
	})

	t.Run("wireguard-routes-and-rules", func(t *testing.T) {
		peer, _ := wgtypes.GeneratePrivateKey()
		record := prepareIntegrationRecord(t, model.Tunnel{
			Name: "wg", Kind: model.KindWireGuard, Interface: "wg0",
			Spec: model.Spec{WireGuard: &model.WireGuardSpec{
				RouteAllowedIPs: true,
				Addresses:       []netip.Prefix{netip.MustParsePrefix("10.2.0.1/30")},
				Peers: []model.WireGuardPeer{{
					PublicKey: peer.PublicKey().String(), AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
				}},
			}},
		})
		assertLifecycleOrSkipUnsupported(t, backend, record)
	})

	t.Run("wireguard-route-realm-migration", func(t *testing.T) {
		peer, _ := wgtypes.GeneratePrivateKey()
		record := prepareIntegrationRecord(t, model.Tunnel{
			Name: "wg-migrate", Kind: model.KindWireGuard, Interface: "wg-migrate",
			Spec: model.Spec{WireGuard: &model.WireGuardSpec{
				RouteAllowedIPs: true,
				RouteTable:      1200,
				Peers: []model.WireGuardPeer{{
					PublicKey: peer.PublicKey().String(), AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.222.0.0/24")},
				}},
			}},
		})
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := backend.Apply(ctx, record); err != nil {
			if unsupportedKernelError(err) {
				_, _ = backend.Remove(ctx, record)
				t.Skipf("kernel does not support %s in this environment: %v", record.Kind, err)
			}
			t.Fatal(err)
		}
		assertIntegrationAddresses(t, backend, record)
		removed := false
		defer func() {
			if !removed {
				_, _ = backend.Remove(context.Background(), record)
			}
		}()
		link, err := backend.netlink.LinkByName(record.Interface)
		if err != nil {
			t.Fatal(err)
		}
		routes, err := backend.listRoutesForLinkTable(link, netlink.FAMILY_V4, record.Spec.WireGuard.RouteTable)
		if err != nil {
			t.Fatal(err)
		}
		key := fmt.Sprintf("%d|10.222.0.0/24", record.Spec.WireGuard.RouteTable)
		var managed *netlink.Route
		for i := range routes {
			if managedRouteKey(routes[i]) == key && routeOwnedByRecord(record, routes[i]) {
				copy := routes[i]
				managed = &copy
				break
			}
		}
		if managed == nil {
			t.Fatal("managed WireGuard route was not created with a record realm")
		}
		if err := backend.netlink.RouteDel(managed); err != nil {
			t.Fatal(err)
		}
		legacy := *managed
		legacy.Realm = 0
		if err := backend.netlink.RouteAdd(&legacy); err != nil {
			t.Fatal(err)
		}
		if _, err := backend.Apply(ctx, record); err != nil {
			t.Fatalf("migrate legacy route: %v", err)
		}
		routes, err = backend.listRoutesForLinkTable(link, netlink.FAMILY_V4, record.Spec.WireGuard.RouteTable)
		if err != nil {
			t.Fatal(err)
		}
		foundOwned, foundLegacy := false, false
		for _, route := range routes {
			if managedRouteKey(route) != key {
				continue
			}
			foundOwned = foundOwned || routeOwnedByRecord(record, route)
			foundLegacy = foundLegacy || route.Protocol == managedRouteProtocol && route.Realm == 0
		}
		if !foundOwned || foundLegacy {
			t.Fatalf("legacy route migration result: owned=%t legacy=%t", foundOwned, foundLegacy)
		}
		if _, err := backend.Remove(ctx, record); err != nil {
			t.Fatal(err)
		}
		removed = true
	})

	t.Run("amneziawg", func(t *testing.T) {
		record := prepareIntegrationRecord(t, model.Tunnel{
			Name: "awg", Kind: model.KindAmneziaWG, Interface: "awg0",
			Spec: model.Spec{AmneziaWG: &model.AmneziaWGSpec{
				WireGuardSpec: model.WireGuardSpec{
					Addresses: []netip.Prefix{netip.MustParsePrefix("10.4.0.1/30")},
				},
			}},
		})
		assertLifecycleOrSkipUnsupported(t, backend, record)
	})

	t.Run("static-xfrm", func(t *testing.T) {
		record := prepareIntegrationRecord(t, model.Tunnel{
			Name: "static", Kind: model.KindXFRMStatic, Interface: "xfrm0",
			Spec: model.Spec{XFRMStatic: &model.XFRMStaticSpec{
				UnderlayInterface: "underlay0", Local: netip.MustParseAddr("198.51.100.1"), Remote: netip.MustParseAddr("198.51.100.2"),
				Addresses: []netip.Prefix{netip.MustParsePrefix("10.3.0.1/30")},
			}},
		})
		assertLifecycleOrSkipUnsupported(t, backend, record)
		underlayLink, err := backend.netlink.LinkByName("underlay0")
		if err != nil {
			t.Fatal(err)
		}
		foreign := &netlink.Xfrmi{
			LinkAttrs: netlink.LinkAttrs{Name: "foreign-xfrm", ParentIndex: underlayLink.Attrs().Index},
			Ifid:      record.Spec.XFRMStatic.IfID,
		}
		if err := backend.netlink.LinkAdd(foreign); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if _, err := backend.Apply(ctx, record); !errors.Is(err, ErrOwnershipConflict) {
			t.Fatalf("XFRM ID conflict error = %v, want ownership conflict", err)
		}
		if _, err := backend.netlink.LinkByName("foreign-xfrm"); err != nil {
			t.Fatalf("foreign XFRM link was deleted: %v", err)
		}
		if err := backend.netlink.LinkDel(foreign); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("srv6", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if request.URL.Path != "/carrier_v4.txt" {
				http.NotFound(response, request)
				return
			}
			_, _ = response.Write([]byte("203.0.113.0/24\n"))
		}))
		defer server.Close()
		record := prepareIntegrationRecord(t, model.Tunnel{
			Name: "srv6", Kind: model.KindSRv6,
			Spec: model.Spec{SRv6: &model.SRv6Spec{
				BaseURL: server.URL, UnderlayInterface: "underlay0", Table: 1001,
				Sources: []model.SRv6Source{{Name: "carrier", SIDv4: integrationAddrPointer("2001:db8:1::1"), MTU: 1400}},
			}},
		})
		underlayLink, err := backend.netlink.LinkByName("underlay0")
		if err != nil {
			t.Fatal(err)
		}
		foreignRoute := netlink.Route{
			LinkIndex: underlayLink.Attrs().Index,
			Dst:       prefixToIPNet(netip.MustParsePrefix("198.18.0.0/15")),
			Table:     record.Spec.SRv6.Table,
			Protocol:  managedRouteProtocol,
			Realm:     1234,
			Scope:     netlink.SCOPE_LINK,
		}
		if err := backend.netlink.RouteAdd(&foreignRoute); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = backend.netlink.RouteDel(&foreignRoute) }()
		assertLifecycleOrSkipUnsupported(t, backend, record)
		routes, err := backend.netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Table: record.Spec.SRv6.Table}, netlink.RT_FILTER_TABLE)
		if err != nil {
			t.Fatal(err)
		}
		preserved := false
		for _, route := range routes {
			if routeKey(route) == routeKey(foreignRoute) && route.Realm == foreignRoute.Realm {
				preserved = true
				break
			}
		}
		if !preserved {
			t.Fatal("foreign protocol-242 route was deleted during SRv6 reconciliation")
		}
	})

	t.Run("netlink-delete-event", func(t *testing.T) {
		record := prepareIntegrationRecord(t, model.Tunnel{
			Name: "event", Kind: model.KindGRE, Interface: "event0",
			Spec: model.Spec{GRE: &model.GRESpec{Local: netip.MustParseAddr("192.0.2.1"), Remote: netip.MustParseAddr("192.0.2.2")}},
		})
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := backend.Apply(ctx, record); err != nil {
			t.Fatal(err)
		}
		time.Sleep(100 * time.Millisecond)
	drainEvents:
		for {
			select {
			case <-backend.Events():
			default:
				break drainEvents
			}
		}
		link, err := backend.netlink.LinkByName(record.Interface)
		if err != nil {
			t.Fatal(err)
		}
		if err := backend.netlink.LinkDel(link); err != nil {
			t.Fatal(err)
		}
		select {
		case event := <-backend.Events():
			if event.RecordID != record.ID || event.Interface != record.Interface {
				t.Fatalf("backend event = %+v, want record %s interface %s", event, record.ID, record.Interface)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("managed link deletion did not emit a backend event")
		}
		if _, err := backend.Apply(ctx, record); err != nil {
			t.Fatalf("repair after event: %v", err)
		}
		if _, err := backend.Remove(ctx, record); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("ownership-conflict", func(t *testing.T) {
		foreign := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "foreign0"}}
		if err := backend.netlink.LinkAdd(foreign); err != nil {
			t.Fatal(err)
		}
		record := prepareIntegrationRecord(t, model.Tunnel{
			Name: "foreign", Kind: model.KindGRE, Interface: "foreign0",
			Spec: model.Spec{GRE: &model.GRESpec{Local: netip.MustParseAddr("192.0.2.1"), Remote: netip.MustParseAddr("192.0.2.2")}},
		})
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if _, err := backend.Apply(ctx, record); !errors.Is(err, ErrOwnershipConflict) {
			t.Fatalf("Apply error = %v, want ownership conflict", err)
		}
		if _, err := backend.Remove(ctx, record); !errors.Is(err, ErrOwnershipConflict) {
			t.Fatalf("Remove error = %v, want ownership conflict", err)
		}
		if _, err := backend.netlink.LinkByName("foreign0"); err != nil {
			t.Fatalf("foreign link was deleted: %v", err)
		}
	})
}

func enterTestNamespace(t *testing.T) func() {
	t.Helper()
	runtime.LockOSThread()
	original, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		t.Fatal(err)
	}
	namespace, err := netns.New()
	if err != nil {
		original.Close()
		runtime.UnlockOSThread()
		if errors.Is(err, syscall.EPERM) {
			t.Skip("network namespace creation requires CAP_SYS_ADMIN")
		}
		t.Fatal(err)
	}
	return func() {
		if err := netns.Set(original); err != nil {
			t.Errorf("restore network namespace: %v", err)
		}
		namespace.Close()
		original.Close()
		runtime.UnlockOSThread()
	}
}

func prepareIntegrationRecord(t *testing.T, record model.Tunnel) model.Tunnel {
	t.Helper()
	record.Enabled = true
	if err := model.PrepareNew(&record, time.Now()); err != nil {
		t.Fatal(err)
	}
	return record
}

func integrationAddrPointer(value string) *netip.Addr {
	address := netip.MustParseAddr(value)
	return &address
}

func assertLifecycle(t *testing.T, backend *Backend, record model.Tunnel) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	observation, err := backend.Apply(ctx, record)
	if err != nil {
		t.Fatal(err)
	}
	if record.Kind == model.KindSRv6 {
		if observation.Details["managed_routes"] == "0" || observation.Details["managed_routes"] == "" {
			t.Fatalf("unexpected SRv6 observation: %+v", observation)
		}
	} else if !observation.InterfaceExists || !observation.InterfaceUp {
		t.Fatalf("unexpected apply observation: %+v", observation)
	}
	if record.Interface != "" && observation.Details["ipv6_link_local"] != managedLinkLocalPrefix(record).String() {
		t.Fatalf("apply observation is missing the managed IPv6 link-local address: %+v", observation)
	}
	assertIntegrationAddresses(t, backend, record)
	if _, err := backend.Apply(ctx, record); err != nil {
		t.Fatalf("idempotent apply: %v", err)
	}
	if _, err := backend.Remove(ctx, record); err != nil {
		t.Fatal(err)
	}
	observation, err = backend.Observe(ctx, record)
	if err != nil || observation.InterfaceExists {
		t.Fatalf("observe after remove = %+v, %v", observation, err)
	}
}

func assertLifecycleOrSkipUnsupported(t *testing.T, backend *Backend, record model.Tunnel) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	observation, err := backend.Apply(ctx, record)
	if err != nil {
		if unsupportedKernelError(err) {
			_, _ = backend.Remove(ctx, record)
			t.Skipf("kernel does not support %s in this environment: %v", record.Kind, err)
		}
		t.Fatal(err)
	}
	if record.Kind == model.KindSRv6 {
		if observation.Details["managed_routes"] == "0" || observation.Details["managed_routes"] == "" {
			t.Fatalf("unexpected SRv6 observation: %+v", observation)
		}
	} else if !observation.InterfaceExists || !observation.InterfaceUp {
		t.Fatalf("unexpected apply observation: %+v", observation)
	}
	assertIntegrationAddresses(t, backend, record)
	if _, err := backend.Apply(ctx, record); err != nil {
		t.Fatalf("idempotent apply: %v", err)
	}
	if _, err := backend.Remove(ctx, record); err != nil {
		t.Fatal(err)
	}
}

func unsupportedKernelError(err error) bool {
	if errors.Is(err, syscall.EOPNOTSUPP) || errors.Is(err, syscall.ENODEV) || errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.EPROTONOSUPPORT) {
		return true
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "not supported") || strings.Contains(message, "no such device")
}

func assertIntegrationAddresses(t *testing.T, backend *Backend, record model.Tunnel) {
	t.Helper()
	var desired []netip.Prefix
	switch record.Kind {
	case model.KindGRE:
		desired = record.Spec.GRE.Addresses
	case model.KindVXLAN:
		desired = record.Spec.VXLAN.Addresses
	case model.KindWireGuard:
		desired = record.Spec.WireGuard.Addresses
	case model.KindAmneziaWG:
		desired = record.Spec.AmneziaWG.Addresses
	case model.KindXFRMStatic:
		desired = record.Spec.XFRMStatic.Addresses
	case model.KindXFRMIKEv2:
		desired = record.Spec.XFRMIKEv2.Addresses
	case model.KindSRv6:
		return
	default:
		t.Fatalf("tunnel kind %s does not expose an owned interface", record.Kind)
	}
	link, err := backend.netlink.LinkByName(record.Interface)
	if err != nil {
		t.Fatal(err)
	}
	addresses, err := backend.netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		t.Fatal(err)
	}
	present := make(map[netip.Prefix]struct{}, len(addresses))
	for _, address := range addresses {
		if prefix, ok := prefixFromIPNet(address.IPNet); ok {
			present[prefix] = struct{}{}
		}
	}
	for _, prefix := range desired {
		if _, ok := present[prefix]; !ok {
			t.Fatalf("interface %s is missing exact address %s; observed %v", record.Interface, prefix, present)
		}
	}
	managedLinkLocal := managedLinkLocalPrefix(record)
	if _, ok := present[managedLinkLocal]; !ok {
		t.Fatalf("interface %s is missing managed IPv6 link-local address %s; observed %v", record.Interface, managedLinkLocal, present)
	}
}
