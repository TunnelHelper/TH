//go:build linux && integration

package linux

import (
	"context"
	"errors"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/TunnelHelper/TH/internal/config"
	"github.com/TunnelHelper/TH/internal/model"
	"github.com/vishvananda/netlink"
)

// TestMptcpEndpointLifecycle exercises the real mptcp_pm kernel API in a
// fresh network namespace: Apply registers the tunnel address as an
// endpoint, idempotent applies keep exactly one, and Remove withdraws it.
// On kernels without MPTCP it asserts the documented degradation path:
// tunnels still apply and health reports unsupported.
func TestMptcpEndpointLifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	restore := enterTestNamespace(t)
	defer restore()

	loopback, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(loopback); err != nil {
		t.Fatal(err)
	}
	if err := netlink.AddrAdd(loopback, &netlink.Addr{IPNet: prefixToIPNet(netip.MustParsePrefix("192.0.2.1/32"))}); err != nil && !errors.Is(err, syscall.EEXIST) {
		t.Fatal(err)
	}

	settings := config.Defaults()
	settings.StateDir = t.TempDir()
	settings.RuntimeDir = t.TempDir()
	settings.SocketPath = settings.RuntimeDir + "/control.sock"
	settings.VICISocketPath = settings.RuntimeDir + "/missing.vici"
	settings.RequestTimeoutSeconds = 1
	settings.Mptcp.Enabled = true
	backend, err := New(settings)
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()

	record := prepareIntegrationRecord(t, model.Tunnel{
		Name: "mptcp-gre", Kind: model.KindGRE, Interface: "mptcp-gre",
		Spec: model.Spec{GRE: &model.GRESpec{
			Local:     netip.MustParseAddr("192.0.2.1"),
			Remote:    netip.MustParseAddr("192.0.2.2"),
			Addresses: []netip.Prefix{netip.MustParsePrefix("10.77.0.1/30")},
		}},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	observation, err := backend.Apply(ctx, record)
	if err != nil {
		t.Fatal(err)
	}
	if !observation.InterfaceExists || !observation.InterfaceUp {
		t.Fatalf("MPTCP tunnel did not apply: %+v", observation)
	}

	health := backend.MptcpHealth()
	if !health.Supported {
		// Documented degradation: the tunnel is fine, the endpoint set is
		// empty and health explains why MPTCP is not effective.
		if health.Status != mptcpStatusUnsupported {
			t.Fatalf("unsupported health status = %q, want unsupported", health.Status)
		}
		if health.Message == "" {
			t.Fatal("unsupported health must carry a reason")
		}
		if observation.Details["mptcp_endpoints"] != "0" {
			t.Fatalf("unsupported observation endpoints = %q, want 0", observation.Details["mptcp_endpoints"])
		}
		t.Logf("kernel MPTCP is not available, degradation verified: %s", health.Message)
		return
	}

	// The tunnel address must be registered as an endpoint with the
	// SUBFLOW|SIGNAL flags.
	t.Log("kernel MPTCP is available; exercising the endpoint lifecycle")
	client, ok := backend.mptcp.client.(*mptcpGenlClient)
	if !ok {
		t.Fatal("supported backend must use the real mptcp_pm client")
	}
	endpoints, err := client.list(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(endpoints) != 1 {
		t.Fatalf("endpoints after apply = %+v, want exactly the tunnel address", endpoints)
	}
	if endpoints[0].Address != netip.MustParseAddr("10.77.0.1") || endpoints[0].Flags != mptcpDefaultEndpointFlags {
		t.Fatalf("endpoint = %+v, want 10.77.0.1 with default flags", endpoints[0])
	}
	if health.Status != mptcpStatusEnabled || health.Endpoints != 1 {
		t.Fatalf("health = %+v, want enabled with 1 endpoint", health)
	}
	if observation.Details["mptcp"] != mptcpStatusEnabled || observation.Details["mptcp_endpoints"] != "1" {
		t.Fatalf("observation details = %+v", observation.Details)
	}

	// Idempotent apply must not duplicate the endpoint.
	if _, err := backend.Apply(ctx, record); err != nil {
		t.Fatal(err)
	}
	endpoints, err = client.list(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(endpoints) != 1 {
		t.Fatalf("endpoints after idempotent apply = %+v, want 1", endpoints)
	}

	// Remove withdraws the endpoint (before the link disappears).
	if _, err := backend.Remove(ctx, record); err != nil {
		t.Fatal(err)
	}
	endpoints, err = client.list(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(endpoints) != 0 {
		t.Fatalf("endpoints after remove = %+v, want none", endpoints)
	}
	if health := backend.MptcpHealth(); health.Endpoints != 0 {
		t.Fatalf("health after remove = %+v, want 0 endpoints", health)
	}
}
