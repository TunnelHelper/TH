package core

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/TunnelHelper/TH/internal/model"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestBundlePlanAndApplyLifecycle(t *testing.T) {
	alpha := batchGRE(t, "11111111-1111-4111-8111-111111111111", "alpha", "gre-a", true)
	bravo := batchGRE(t, "22222222-2222-4222-8222-222222222222", "bravo", "gre-b", false)
	remove := batchGRE(t, "33333333-3333-4333-8333-333333333333", "remove", "gre-c", false)
	records := newMemoryStore(alpha, bravo, remove)
	backend := newFakeBackend()
	manager := NewManager(records, NewReconciler(records, backend, time.Hour))

	alphaDesired, _ := model.Clone(alpha)
	alphaDesired.Name = "alpha-updated"
	alphaDesired.Enabled = false
	newRecord := model.Tunnel{
		Name: "charlie", Kind: model.KindGRE, Interface: "gre-d", Enabled: true,
		Spec: model.Spec{GRE: &model.GRESpec{Local: netip.MustParseAddr("192.0.2.5"), Remote: netip.MustParseAddr("192.0.2.6")}},
	}
	bundle := model.Bundle{BundleVersion: model.BundleVersion, Tunnels: []model.Tunnel{alphaDesired, bravo, newRecord}}
	plan, err := manager.PlanBundle(bundle, true)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Summary.Create != 1 || plan.Summary.Update != 1 || plan.Summary.Delete != 1 || plan.Summary.Unchanged != 1 {
		t.Fatalf("plan summary = %+v", plan.Summary)
	}
	if stored, _ := records.Get(alpha.ID); stored.Name != alpha.Name || stored.Generation != alpha.Generation {
		t.Fatalf("plan mutated state: %+v", stored)
	}

	result, err := manager.ApplyBundle(context.Background(), bundle, true, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Tunnels) != 3 {
		t.Fatalf("applied tunnels = %+v", result.Tunnels)
	}
	updated, err := records.Get(alpha.ID)
	if err != nil || updated.Name != "alpha-updated" || updated.Enabled || updated.Generation != alpha.Generation+1 {
		t.Fatalf("updated alpha = %+v, %v", updated, err)
	}
	if _, err := records.Get(remove.ID); err == nil {
		t.Fatal("pruned record remains")
	}
	createdID := ""
	for _, operation := range result.Plan.Operations {
		if operation.Action == BundleCreate {
			createdID = operation.ID
		}
	}
	if !model.ValidID(createdID) {
		t.Fatalf("created operation id = %q", createdID)
	}
	created, err := records.Get(createdID)
	if err != nil || created.Name != "charlie" {
		t.Fatalf("created record = %+v, %v", created, err)
	}
	if status := manager.reconciler.Status(created); status.Phase != model.PhaseReady {
		t.Fatalf("waited create status = %+v", status)
	}
}

func TestBundlePlanMergesRedactedSecretsAsUnchanged(t *testing.T) {
	record := lifecycleInputs(t)[2]
	record.ID = "44444444-4444-4444-8444-444444444444"
	record.SchemaVersion = 0
	record.Generation = 0
	record.CreatedAt = time.Time{}
	record.UpdatedAt = time.Time{}
	if err := model.PrepareNew(&record, time.Now()); err != nil {
		t.Fatal(err)
	}
	redacted, _ := model.Redact(record)
	records := newMemoryStore(record)
	manager := NewManager(records, NewReconciler(records, newFakeBackend(), time.Hour))
	plan, err := manager.PlanBundle(model.Bundle{BundleVersion: model.BundleVersion, Tunnels: []model.Tunnel{redacted}}, false)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Summary.Unchanged != 1 || plan.Summary.Update != 0 {
		t.Fatalf("redacted plan = %+v", plan)
	}
}

func TestBundlePlanRejectsFinalOwnershipConflict(t *testing.T) {
	bundle := model.Bundle{BundleVersion: model.BundleVersion, Tunnels: []model.Tunnel{
		{Name: "one", Kind: model.KindGRE, Interface: "same0", Spec: model.Spec{GRE: &model.GRESpec{Local: netip.MustParseAddr("192.0.2.1"), Remote: netip.MustParseAddr("192.0.2.2")}}},
		{Name: "two", Kind: model.KindGRE, Interface: "same0", Spec: model.Spec{GRE: &model.GRESpec{Local: netip.MustParseAddr("192.0.2.3"), Remote: netip.MustParseAddr("192.0.2.4")}}},
	}}
	records := newMemoryStore()
	manager := NewManager(records, NewReconciler(records, newFakeBackend(), time.Hour))
	if _, err := manager.PlanBundle(bundle, false); !IsInvalidRequest(err) {
		t.Fatalf("ownership conflict = %v", err)
	}
}

func TestValidateRecordSetDetectsRouteConflictsInEitherOrder(t *testing.T) {
	peer, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	wg := model.Tunnel{
		Name: "wg-routes", Kind: model.KindWireGuard, Interface: "wg-routes",
		Spec: model.Spec{WireGuard: &model.WireGuardSpec{
			RouteAllowedIPs: true,
			RouteTable:      1000,
			Peers: []model.WireGuardPeer{{
				PublicKey:  peer.PublicKey().String(),
				AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")},
			}},
		}},
	}
	if err := model.PrepareNew(&wg, time.Now()); err != nil {
		t.Fatal(err)
	}
	srv6 := model.Tunnel{
		Name: "srv6-routes", Kind: model.KindSRv6,
		Spec: model.Spec{SRv6: &model.SRv6Spec{
			BaseURL: "https://routes.example/", UnderlayInterface: "eth0", Table: 1000,
			Sources: []model.SRv6Source{{Name: "carrier", SIDv4: coreAddrPointer("2001:db8::1"), MTU: 1500}},
		}},
	}
	if err := model.PrepareNew(&srv6, time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, records := range [][]model.Tunnel{{wg, srv6}, {srv6, wg}} {
		if err := validateRecordSet(records); err == nil {
			t.Fatalf("route conflict was accepted in order %s, %s", records[0].Name, records[1].Name)
		}
	}
}

func TestValidateRecordSetRejectsTooManyRecords(t *testing.T) {
	if err := validateRecordSet(make([]model.Tunnel, model.MaxTunnelRecords+1)); err == nil {
		t.Fatal("oversized record set was accepted")
	}
}

func TestBundleApplyRollsBackDesiredStateOnFailure(t *testing.T) {
	original := batchGRE(t, "55555555-5555-4555-8555-555555555555", "original", "gre-r", false)
	base := newMemoryStore(original)
	records := &failingBatchStore{memoryStore: base, failCreateName: "fail-create"}
	manager := NewManager(records, NewReconciler(records, newFakeBackend(), time.Hour))
	updated, _ := model.Clone(original)
	updated.Name = "renamed"
	bundle := model.Bundle{BundleVersion: model.BundleVersion, Tunnels: []model.Tunnel{
		updated,
		{Name: "fail-create", Kind: model.KindGRE, Interface: "gre-f", Spec: model.Spec{GRE: &model.GRESpec{Local: netip.MustParseAddr("198.51.100.1"), Remote: netip.MustParseAddr("198.51.100.2")}}},
	}}
	if _, err := manager.ApplyBundle(context.Background(), bundle, false, false); !IsOperationFailed(err) {
		t.Fatalf("apply error = %v, want operation failure", err)
	}
	restored, err := records.Get(original.ID)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Name != original.Name || restored.Interface != original.Interface || restored.Generation != original.Generation+2 {
		t.Fatalf("restored record = %+v", restored)
	}
	listed, err := records.List()
	if err != nil || len(listed) != 1 {
		t.Fatalf("records after rollback = %+v, %v", listed, err)
	}
}

func batchGRE(t *testing.T, id, name, iface string, enabled bool) model.Tunnel {
	t.Helper()
	record := model.Tunnel{
		ID: id, Name: name, Kind: model.KindGRE, Interface: iface, Enabled: enabled,
		Spec: model.Spec{GRE: &model.GRESpec{Local: netip.MustParseAddr("192.0.2.1"), Remote: netip.MustParseAddr("192.0.2.2")}},
	}
	if err := model.PrepareNew(&record, time.Now()); err != nil {
		t.Fatal(err)
	}
	return record
}

type failingBatchStore struct {
	*memoryStore
	failCreateName string
}

func (s *failingBatchStore) Create(record model.Tunnel) error {
	if record.Name == s.failCreateName {
		return errors.New("injected create failure")
	}
	return s.memoryStore.Create(record)
}
