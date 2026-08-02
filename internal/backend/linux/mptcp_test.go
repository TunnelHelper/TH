//go:build linux

package linux

import (
	"context"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/TunnelHelper/TH/internal/config"
	"github.com/TunnelHelper/TH/internal/model"
	"github.com/mdlayher/genetlink"
)

// fakeMptcpPMClient records every call the reconcile engine makes, so
// tests can assert the exact add/del/keep decisions.
type fakeMptcpPMClient struct {
	mu        sync.Mutex
	endpoints []mptcpEndpoint
	added     []mptcpEndpoint
	deleted   []uint8
	listCalls int
	failList  error
	failAdd   error
	failDel   error
}

func (f *fakeMptcpPMClient) list(context.Context) ([]mptcpEndpoint, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listCalls++
	if f.failList != nil {
		return nil, f.failList
	}
	return append([]mptcpEndpoint(nil), f.endpoints...), nil
}

func (f *fakeMptcpPMClient) add(_ context.Context, addr netip.Addr, flags uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failAdd != nil {
		return f.failAdd
	}
	entry := mptcpEndpoint{ID: uint8(len(f.endpoints) + 1), Address: addr, Flags: flags}
	f.added = append(f.added, entry)
	f.endpoints = append(f.endpoints, entry)
	return nil
}

func (f *fakeMptcpPMClient) delByID(_ context.Context, id uint8) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failDel != nil {
		return f.failDel
	}
	f.deleted = append(f.deleted, id)
	kept := f.endpoints[:0]
	for _, endpoint := range f.endpoints {
		if endpoint.ID != id {
			kept = append(kept, endpoint)
		}
	}
	f.endpoints = kept
	return nil
}

func (f *fakeMptcpPMClient) snapshot() (added []mptcpEndpoint, deleted []uint8) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]mptcpEndpoint(nil), f.added...), append([]uint8(nil), f.deleted...)
}

func newFakeMptcpControl(client *fakeMptcpPMClient, enabled bool) *mptcpControl {
	return &mptcpControl{
		settings:  config.MptcpSettings{Enabled: enabled},
		client:    client,
		supported: true,
		tunnels:   make(map[string]mptcpTunnel),
		status:    mptcpStatusDisabled,
	}
}

func mptcpTestRecord(id string, addresses ...string) model.Tunnel {
	prefixes := make([]netip.Prefix, 0, len(addresses))
	for _, address := range addresses {
		prefixes = append(prefixes, netip.MustParsePrefix(address))
	}
	return model.Tunnel{
		ID:        id,
		Name:      "mptcp-test",
		Kind:      model.KindGRE,
		Interface: "gre-" + id,
		Enabled:   true,
		Spec: model.Spec{GRE: &model.GRESpec{
			Local:     netip.MustParseAddr("192.0.2.1"),
			Remote:    netip.MustParseAddr("192.0.2.2"),
			Addresses: prefixes,
		}},
	}
}

func TestMptcpReconcileAddsMissingEndpoints(t *testing.T) {
	client := &fakeMptcpPMClient{}
	control := newFakeMptcpControl(client, true)
	control.upsertTunnel(mptcpTestRecord("a", "10.0.0.1/30", "2001:db8::1/64"))

	if err := control.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	added, _ := client.snapshot()
	if len(added) != 2 {
		t.Fatalf("added %d endpoints, want 2", len(added))
	}
	seen := make(map[netip.Addr]uint32, len(added))
	for _, endpoint := range added {
		seen[endpoint.Address] = endpoint.Flags
	}
	if seen[netip.MustParseAddr("10.0.0.1")] != mptcpDefaultEndpointFlags {
		t.Fatalf("IPv4 endpoint flags = %d, want %d", seen[netip.MustParseAddr("10.0.0.1")], mptcpDefaultEndpointFlags)
	}
	if seen[netip.MustParseAddr("2001:db8::1")] != mptcpDefaultEndpointFlags {
		t.Fatalf("IPv6 endpoint flags = %d, want %d", seen[netip.MustParseAddr("2001:db8::1")], mptcpDefaultEndpointFlags)
	}
	health := control.health()
	if health.Status != mptcpStatusEnabled || health.Endpoints != 2 {
		t.Fatalf("health = %+v, want enabled with 2 endpoints", health)
	}
}

func TestMptcpReconcileIsIdempotent(t *testing.T) {
	client := &fakeMptcpPMClient{}
	control := newFakeMptcpControl(client, true)
	record := mptcpTestRecord("a", "10.0.0.1/30")
	control.upsertTunnel(record)
	if err := control.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := control.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	added, deleted := client.snapshot()
	if len(added) != 1 || len(deleted) != 0 {
		t.Fatalf("second reconcile changed the kernel: added=%d deleted=%d", len(added), len(deleted))
	}
}

func TestMptcpOrphanCleanupOnlyDeletesOwnedAddresses(t *testing.T) {
	client := &fakeMptcpPMClient{
		endpoints: []mptcpEndpoint{
			{ID: 1, Address: netip.MustParseAddr("10.0.0.1"), Flags: mptcpDefaultEndpointFlags},
			{ID: 2, Address: netip.MustParseAddr("192.0.2.99"), Flags: mptcpPMAddrFlagSubflow},
		},
	}
	control := newFakeMptcpControl(client, false)
	// 10.0.0.1 belongs to a TH tunnel but the tunnel is inactive; the
	// other endpoint was registered by someone else and must survive.
	record := mptcpTestRecord("a", "10.0.0.1/30")
	control.removeTunnel(record)

	if err := control.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, deleted := client.snapshot()
	if len(deleted) != 1 || deleted[0] != 1 {
		t.Fatalf("deleted IDs = %v, want [1] only", deleted)
	}
	remaining, _ := client.list(context.Background())
	if len(remaining) != 1 || remaining[0].Address != netip.MustParseAddr("192.0.2.99") {
		t.Fatalf("remaining endpoints = %+v, want the foreign one untouched", remaining)
	}
	health := control.health()
	if health.Status != mptcpStatusDisabled {
		t.Fatalf("health status = %q, want disabled", health.Status)
	}
}

func TestMptcpUnsupportedDegradesWithoutTouchingKernel(t *testing.T) {
	client := &fakeMptcpPMClient{}
	control := newFakeMptcpControl(client, true)
	control.supported = false
	control.unsupportedMsg = "kernel too old (need Linux >= 5.6)"
	control.upsertTunnel(mptcpTestRecord("a", "10.0.0.1/30"))

	if err := control.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	added, deleted := client.snapshot()
	if len(added) != 0 || len(deleted) != 0 {
		t.Fatalf("unsupported kernel still changed endpoints: added=%d deleted=%d", len(added), len(deleted))
	}
	health := control.health()
	if health.Status != mptcpStatusUnsupported || health.Supported {
		t.Fatalf("health = %+v, want unsupported", health)
	}
	if !strings.Contains(health.Message, "5.6") {
		t.Fatalf("unsupported message = %q, want the version reason", health.Message)
	}
}

func TestMptcpDisabledNeverWritesScheduler(t *testing.T) {
	// mptcp.enabled=false must produce zero sysctl writes even when a
	// scheduler is configured: the global switch gates the write.
	client := &fakeMptcpPMClient{}
	control := newFakeMptcpControl(client, false)
	control.settings.Scheduler = "roundrobin"
	control.upsertTunnel(mptcpTestRecord("a", "10.0.0.1/30"))
	if err := control.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if control.schedulerWarn != "" {
		t.Fatalf("disabled MPTCP must not attempt the scheduler, warning = %q", control.schedulerWarn)
	}
	if control.message != "" {
		t.Fatalf("disabled MPTCP must not report scheduler problems, message = %q", control.message)
	}
	added, deleted := client.snapshot()
	if len(added) != 0 || len(deleted) != 0 {
		t.Fatalf("disabled MPTCP still changed endpoints: added=%d deleted=%d", len(added), len(deleted))
	}
}

func TestMptcpPerTunnelOptOut(t *testing.T) {
	client := &fakeMptcpPMClient{}
	control := newFakeMptcpControl(client, true)
	record := mptcpTestRecord("a", "10.0.0.1/30")
	optOut := false
	record.Spec.Mptcp = &model.MptcpTunnelConfig{Endpoint: &optOut}
	control.upsertTunnel(record)

	if err := control.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	added, _ := client.snapshot()
	if len(added) != 0 {
		t.Fatalf("opt-out tunnel registered %d endpoints, want 0", len(added))
	}
}

func TestMptcpPerTunnelOptInOverridesGlobalOff(t *testing.T) {
	client := &fakeMptcpPMClient{}
	control := newFakeMptcpControl(client, false)
	record := mptcpTestRecord("a", "10.0.0.1/30")
	optIn := true
	record.Spec.Mptcp = &model.MptcpTunnelConfig{Endpoint: &optIn}
	control.upsertTunnel(record)

	if err := control.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	added, _ := client.snapshot()
	if len(added) != 1 {
		t.Fatalf("opt-in tunnel with global off registered %d endpoints, want 1", len(added))
	}
}

func TestMptcpRemoveTunnelWithdrawsEndpoints(t *testing.T) {
	client := &fakeMptcpPMClient{}
	control := newFakeMptcpControl(client, true)
	record := mptcpTestRecord("a", "10.0.0.1/30")
	control.upsertTunnel(record)
	if err := control.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	control.removeTunnel(record)
	if err := control.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, deleted := client.snapshot()
	if len(deleted) != 1 {
		t.Fatalf("deleted %d endpoints after remove, want 1", len(deleted))
	}
	remaining, _ := client.list(context.Background())
	if len(remaining) != 0 {
		t.Fatalf("endpoints remain after remove: %+v", remaining)
	}
}

func TestMptcpReconcileAllSyncsRecords(t *testing.T) {
	client := &fakeMptcpPMClient{}
	control := newFakeMptcpControl(client, true)
	first := mptcpTestRecord("a", "10.0.0.1/30")
	second := mptcpTestRecord("b", "10.0.1.1/30")

	if err := control.reconcileAll(context.Background(), []model.Tunnel{first, second}); err != nil {
		t.Fatal(err)
	}
	added, _ := client.snapshot()
	if len(added) != 2 {
		t.Fatalf("reconcileAll registered %d endpoints, want 2", len(added))
	}

	// Withdrawal happens at Remove time (before the record disappears):
	// the endpoint is deleted while the ownership entry still exists.
	control.removeTunnel(second)
	if err := control.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Once the record is gone from the authoritative list, the surviving
	// tunnel's endpoint stays and the removed one stays gone.
	if err := control.reconcileAll(context.Background(), []model.Tunnel{first}); err != nil {
		t.Fatal(err)
	}
	remaining, _ := client.list(context.Background())
	if len(remaining) != 1 || remaining[0].Address != netip.MustParseAddr("10.0.0.1") {
		t.Fatalf("remaining = %+v, want only the surviving tunnel's endpoint", remaining)
	}
}

func TestMptcpObservationDetails(t *testing.T) {
	client := &fakeMptcpPMClient{}
	control := newFakeMptcpControl(client, true)
	control.upsertTunnel(mptcpTestRecord("a", "10.0.0.1/30"))
	if err := control.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	details := control.observationDetails()
	if details["mptcp"] != mptcpStatusEnabled || details["mptcp_endpoints"] != "1" {
		t.Fatalf("observation details = %+v", details)
	}

	control.supported = false
	control.unsupportedMsg = "family missing"
	_ = control.reconcile(context.Background())
	details = control.observationDetails()
	if !strings.Contains(details["mptcp"], "unsupported") || !strings.Contains(details["mptcp"], "family missing") {
		t.Fatalf("unsupported observation details = %+v", details)
	}
}

func TestApplyMPTCPScheduler(t *testing.T) {
	dir := t.TempDir()
	availablePath := dir + "/available"
	schedulerPath := dir + "/scheduler"
	if err := writeTestFile(availablePath, "default roundrobin blest"); err != nil {
		t.Fatal(err)
	}

	if warning := applyMPTCPScheduler("", availablePath, schedulerPath); warning != "" {
		t.Fatalf("empty scheduler must not write anything: %q", warning)
	}
	if warning := applyMPTCPScheduler("roundrobin", availablePath, schedulerPath); warning != "" {
		t.Fatalf("known scheduler must apply: %q", warning)
	}
	if data, err := readTestFile(schedulerPath); err != nil || data != "roundrobin" {
		t.Fatalf("scheduler file = %q, err = %v", data, err)
	}
	if warning := applyMPTCPScheduler("binder", availablePath, schedulerPath); warning == "" {
		t.Fatal("unknown scheduler must warn")
	}
	if warning := applyMPTCPScheduler("roundrobin", dir+"/missing", schedulerPath); warning == "" {
		t.Fatal("missing available_schedulers must warn")
	}
}

func TestMptcpSchedulerAvailable(t *testing.T) {
	if !mptcpSchedulerAvailable("default roundrobin", "roundrobin") {
		t.Fatal("roundrobin must be available")
	}
	if mptcpSchedulerAvailable("default roundrobin", "blest") {
		t.Fatal("blest must not be available")
	}
	if mptcpSchedulerAvailable("", "default") {
		t.Fatal("empty list must not contain anything")
	}
}

func TestParseKernelVersion(t *testing.T) {
	cases := []struct {
		release      string
		major, minor int
		ok           bool
	}{
		{"5.6.0-rc1", 5, 6, true},
		{"6.12.3-arch1-1", 6, 12, true},
		{"5.15.0-91-generic", 5, 15, true},
		{"not-a-version", 0, 0, false},
		{"5", 0, 0, false},
	}
	for _, tc := range cases {
		major, minor, ok := parseKernelVersion(tc.release)
		if major != tc.major || minor != tc.minor || ok != tc.ok {
			t.Errorf("parseKernelVersion(%q) = (%d, %d, %v), want (%d, %d, %v)", tc.release, major, minor, ok, tc.major, tc.minor, tc.ok)
		}
	}
}

func TestMptcpGenlEncodeDecode(t *testing.T) {
	data, err := encodeMptcpAddAddress(netip.MustParseAddr("10.0.0.1"), mptcpDefaultEndpointFlags)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("encoded add payload is empty")
	}

	// Decode the payload as if it were a dump response to verify the
	// address and flags survive the wire format.
	parsed, err := parseMptcpEndpoints([]genetlink.Message{{Data: data}})
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed) != 1 || parsed[0].Address != netip.MustParseAddr("10.0.0.1") || parsed[0].Flags != mptcpDefaultEndpointFlags {
		t.Fatalf("decoded endpoints = %+v", parsed)
	}
}

func writeTestFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0)
}

func readTestFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	return string(data), err
}
