package core

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/TunnelHelper/TH/internal/model"
	"github.com/TunnelHelper/TH/internal/store"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestManagerLifecycleAndSecretRedaction(t *testing.T) {
	records := newMemoryStore()
	backend := newFakeBackend()
	reconciler := NewReconciler(records, backend, time.Hour)
	manager := NewManager(records, reconciler)
	peer, _ := wgtypes.GeneratePrivateKey()
	psk, _ := wgtypes.GenerateKey()
	record := model.Tunnel{
		Name: "wg", Kind: model.KindWireGuard, Interface: "wg0", Enabled: true,
		Spec: model.Spec{WireGuard: &model.WireGuardSpec{Peers: []model.WireGuardPeer{{PublicKey: peer.PublicKey().String(), PresharedKey: psk.String()}}}},
	}
	subscription := manager.SubscribeEvents(0)
	defer subscription.Cancel()
	view, err := manager.Create(context.Background(), record)
	if err != nil {
		t.Fatal(err)
	}
	if backend.applyCalls != 0 || view.Status.Phase != model.PhasePending {
		t.Fatalf("apply calls/status = %d/%s", backend.applyCalls, view.Status.Phase)
	}
	view, err = manager.Reconcile(context.Background(), view.Tunnel.ID)
	if err != nil || backend.applyCalls != 1 || view.Status.Phase != model.PhaseReady {
		t.Fatalf("waited apply calls/status/error = %d/%s/%v", backend.applyCalls, view.Status.Phase, err)
	}
	if view.Tunnel.Spec.WireGuard.PrivateKey != "" || view.Tunnel.Spec.WireGuard.Peers[0].PresharedKey != "" {
		t.Fatal("manager returned secrets")
	}
	select {
	case event := <-subscription.Events:
		if event.Type != EventStatus || event.Status == nil || event.TunnelID != view.Tunnel.ID {
			t.Fatalf("status event = %+v", event)
		}
	default:
		t.Fatal("queued status event was not published")
	}
	raw, err := records.Get(view.Tunnel.ID)
	if err != nil || raw.Spec.WireGuard.PrivateKey == "" || raw.Spec.WireGuard.Peers[0].PresharedKey == "" {
		t.Fatalf("stored secrets missing: %+v, %v", raw, err)
	}
	if _, err := manager.Update(context.Background(), raw.ID, raw.Generation+1, raw); !IsConflict(err) {
		t.Fatalf("stale update = %v, want conflict", err)
	}
	disabled, err := manager.SetEnabled(context.Background(), raw.ID, raw.Generation, false)
	if err != nil {
		t.Fatal(err)
	}
	if disabled.Tunnel.Enabled || disabled.Status.Phase != model.PhasePending || backend.removeCalls != 0 {
		t.Fatalf("unexpected disabled view/calls: %+v, %d", disabled, backend.removeCalls)
	}
	disabled, err = manager.Reconcile(context.Background(), disabled.Tunnel.ID)
	if err != nil || disabled.Status.Phase != model.PhaseDisabled || backend.removeCalls != 1 {
		t.Fatalf("waited disable view/calls/error: %+v, %d, %v", disabled, backend.removeCalls, err)
	}
	if err := manager.Delete(context.Background(), raw.ID, disabled.Tunnel.Generation); err != nil {
		t.Fatal(err)
	}
	if backend.removeCalls != 2 {
		t.Fatalf("remove calls = %d, want 2", backend.removeCalls)
	}
	if _, err := records.Get(raw.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("record remains after delete: %v", err)
	}
}

func TestManagerObserveRefreshesStatusWithoutApplyingDesiredState(t *testing.T) {
	records := newMemoryStore()
	backend := newFakeBackend()
	manager := NewManager(records, NewReconciler(records, backend, time.Hour))
	created, err := manager.Create(context.Background(), model.Tunnel{
		Name: "observe", Kind: model.KindGRE, Interface: "gre-observe", Enabled: true,
		Spec: model.Spec{GRE: &model.GRESpec{
			Local: netip.MustParseAddr("192.0.2.1"), Remote: netip.MustParseAddr("192.0.2.2"),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	observed, err := manager.Observe(context.Background(), created.Tunnel.ID)
	if err != nil {
		t.Fatal(err)
	}
	if backend.observeCalls != 1 || backend.applyCalls != 0 || observed.Status.Phase != model.PhasePending || observed.Status.ObservedGeneration != 0 {
		t.Fatalf("observe/apply/status = %d/%d/%s", backend.observeCalls, backend.applyCalls, observed.Status.Phase)
	}
}

func TestManagerAllocatesPersistentSRv6RulePrioritiesBeforeMain(t *testing.T) {
	records := newMemoryStore()
	manager := NewManager(records, NewReconciler(records, newFakeBackend(), time.Hour))
	priorities := make([]int, 0, 2)
	for index := range 2 {
		view, err := manager.Create(context.Background(), model.Tunnel{
			Name: fmt.Sprintf("srv6-%d", index), Kind: model.KindSRv6, Enabled: true,
			Spec: model.Spec{SRv6: &model.SRv6Spec{
				UnderlayInterface: "eth0", Table: 1000 + index,
				Sources: []model.SRv6Source{{Name: "source1", Family: model.SRv6FamilyIPv4, PrefixURL: "https://routes.example/v4.txt", SID: netip.MustParseAddr("2001:db8::1"), Priority: 100, MTU: 1500}},
			}},
		})
		if err != nil {
			t.Fatal(err)
		}
		priorities = append(priorities, view.Tunnel.Spec.SRv6.RulePriority)
	}
	if priorities[0] != model.SRv6AutoRulePriorityMin || priorities[1] != model.SRv6AutoRulePriorityMin+1 || priorities[1] >= model.MainRulePriority {
		t.Fatalf("allocated SRv6 priorities = %v", priorities)
	}
}

func TestManagerObserveAllRefreshesEveryStatusWithoutApplyingDesiredState(t *testing.T) {
	records := newMemoryStore()
	backend := newFakeBackend()
	manager := NewManager(records, NewReconciler(records, backend, time.Hour))
	for index, name := range []string{"observe-one", "observe-two"} {
		_, err := manager.Create(context.Background(), model.Tunnel{
			Name: name, Kind: model.KindGRE, Interface: fmt.Sprintf("gre-observe-%d", index), Enabled: true,
			Spec: model.Spec{GRE: &model.GRESpec{
				Local: netip.MustParseAddr("192.0.2.1"), Remote: netip.MustParseAddr("192.0.2.2"),
			}},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	observed, err := manager.ObserveAll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if backend.observeCalls != 2 || backend.applyCalls != 0 || len(observed) != 2 {
		t.Fatalf("observe/apply/views = %d/%d/%d", backend.observeCalls, backend.applyCalls, len(observed))
	}
	for _, view := range observed {
		if view.Status.Phase != model.PhasePending || view.Status.ObservedGeneration != 0 {
			t.Fatalf("observed status = %s", view.Status.Phase)
		}
	}
}

func TestManagerObserveReportsMissingManagedInterface(t *testing.T) {
	records := newMemoryStore()
	backend := newFakeBackend()
	backend.observe = &Observation{}
	manager := NewManager(records, NewReconciler(records, backend, time.Hour))
	created, err := manager.Create(context.Background(), model.Tunnel{
		Name: "missing", Kind: model.KindGRE, Interface: "gre-missing", Enabled: true,
		Spec: model.Spec{GRE: &model.GRESpec{
			Local: netip.MustParseAddr("192.0.2.1"), Remote: netip.MustParseAddr("192.0.2.2"),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	observed, err := manager.Observe(context.Background(), created.Tunnel.ID)
	if err != nil {
		t.Fatal(err)
	}
	if observed.Status.Phase != model.PhaseError || len(observed.Status.Conditions) == 0 || !strings.Contains(observed.Status.Conditions[0].Message, "is missing") {
		t.Fatalf("missing-interface status = %+v", observed.Status)
	}
}

func TestObservePreservesSuccessfulReconcileMetadataAndDetails(t *testing.T) {
	records := newMemoryStore()
	backend := newFakeBackend()
	backend.apply = &Observation{InterfaceExists: true, InterfaceUp: true, Details: map[string]string{"cache": "fresh"}}
	manager := NewManager(records, NewReconciler(records, backend, time.Hour))
	created, err := manager.Create(context.Background(), model.Tunnel{
		Name: "observed", Kind: model.KindGRE, Interface: "gre-observed", Enabled: true,
		Spec: model.Spec{GRE: &model.GRESpec{Local: netip.MustParseAddr("192.0.2.1"), Remote: netip.MustParseAddr("192.0.2.2")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	reconciled, err := manager.Reconcile(context.Background(), created.Tunnel.ID)
	if err != nil {
		t.Fatal(err)
	}
	backend.observe = &Observation{InterfaceExists: true, InterfaceUp: true, Details: map[string]string{"managed_routes": "3"}}
	observed, err := manager.Observe(context.Background(), created.Tunnel.ID)
	if err != nil {
		t.Fatal(err)
	}
	if observed.Status.Phase != model.PhaseReady || observed.Status.ObservedGeneration != reconciled.Status.ObservedGeneration {
		t.Fatalf("observation changed reconciled phase/generation: %+v", observed.Status)
	}
	if observed.Status.LastReconcileTime != reconciled.Status.LastReconcileTime || observed.Status.LastSuccessfulTime != reconciled.Status.LastSuccessfulTime {
		t.Fatalf("observation changed reconcile timestamps: before=%+v after=%+v", reconciled.Status, observed.Status)
	}
	if observed.Status.LastObservationTime.Before(reconciled.Status.LastObservationTime) || observed.Status.Details["cache"] != "fresh" || observed.Status.Details["managed_routes"] != "3" {
		t.Fatalf("observation did not merge live details: %+v", observed.Status)
	}
}

func TestSuccessfulObserveDoesNotEraseReconcileFailure(t *testing.T) {
	records := newMemoryStore()
	backend := newFakeBackend()
	backend.applyErr = errors.New("apply failed")
	manager := NewManager(records, NewReconciler(records, backend, time.Hour))
	created, err := manager.Create(context.Background(), model.Tunnel{
		Name: "failed", Kind: model.KindGRE, Interface: "gre-failed", Enabled: true,
		Spec: model.Spec{GRE: &model.GRESpec{Local: netip.MustParseAddr("192.0.2.1"), Remote: netip.MustParseAddr("192.0.2.2")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	failed, err := manager.Reconcile(context.Background(), created.Tunnel.ID)
	if err != nil {
		t.Fatal(err)
	}
	backend.observe = &Observation{InterfaceExists: true, InterfaceUp: true}
	observed, err := manager.Observe(context.Background(), created.Tunnel.ID)
	if err != nil {
		t.Fatal(err)
	}
	if failed.Status.Phase != model.PhaseError || observed.Status.Phase != model.PhaseError || observed.Status.ObservedGeneration != 0 {
		t.Fatalf("successful observation erased reconcile failure: before=%+v after=%+v", failed.Status, observed.Status)
	}
	if len(observed.Status.Conditions) == 0 || !strings.Contains(observed.Status.Conditions[0].Message, "apply failed") {
		t.Fatalf("reconcile failure condition was not preserved: %+v", observed.Status.Conditions)
	}
}

func TestObserveMarksDriftWithoutAdvancingReconcileMetadata(t *testing.T) {
	records := newMemoryStore()
	backend := newFakeBackend()
	manager := NewManager(records, NewReconciler(records, backend, time.Hour))
	created, err := manager.Create(context.Background(), model.Tunnel{
		Name: "drift", Kind: model.KindGRE, Interface: "gre-drift", Enabled: true,
		Spec: model.Spec{GRE: &model.GRESpec{Local: netip.MustParseAddr("192.0.2.1"), Remote: netip.MustParseAddr("192.0.2.2")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	reconciled, err := manager.Reconcile(context.Background(), created.Tunnel.ID)
	if err != nil {
		t.Fatal(err)
	}
	backend.observeErr = fmt.Errorf("%w: route missing", ErrDriftDetected)
	observed, err := manager.Observe(context.Background(), created.Tunnel.ID)
	if err != nil {
		t.Fatal(err)
	}
	if observed.Status.Phase != model.PhaseError || observed.Status.ObservedGeneration != reconciled.Status.ObservedGeneration || observed.Status.LastReconcileTime != reconciled.Status.LastReconcileTime {
		t.Fatalf("drift observation changed reconcile metadata incorrectly: before=%+v after=%+v", reconciled.Status, observed.Status)
	}
	if len(observed.Status.Conditions) == 0 || observed.Status.Conditions[0].Reason != "DriftDetected" {
		t.Fatalf("drift condition = %+v", observed.Status.Conditions)
	}
}

func TestManagerLifecycleForEveryTunnelKind(t *testing.T) {
	for _, input := range lifecycleInputs(t) {
		input := input
		t.Run(string(input.Kind), func(t *testing.T) {
			records := newMemoryStore()
			backend := newFakeBackend()
			reconciler := NewReconciler(records, backend, time.Hour)
			manager := NewManager(records, reconciler)
			created, err := manager.Create(context.Background(), input)
			if err != nil {
				t.Fatalf("create: %v", err)
			}
			if created.Status.Phase != model.PhasePending || created.Tunnel.Enabled {
				t.Fatalf("created state = %+v", created.Status)
			}
			created, err = manager.Reconcile(context.Background(), created.Tunnel.ID)
			if err != nil || created.Status.Phase != model.PhaseDisabled {
				t.Fatalf("waited created state/error = %+v, %v", created.Status, err)
			}
			enabled, err := manager.SetEnabled(context.Background(), created.Tunnel.ID, created.Tunnel.Generation, true)
			if err != nil {
				t.Fatalf("enable: %v", err)
			}
			if enabled.Status.Phase != model.PhasePending || !enabled.Tunnel.Enabled {
				t.Fatalf("enabled state = %+v", enabled.Status)
			}
			enabled, err = manager.Reconcile(context.Background(), enabled.Tunnel.ID)
			if err != nil || enabled.Status.Phase != model.PhaseReady {
				t.Fatalf("waited enabled state/error = %+v, %v", enabled.Status, err)
			}
			next := enabled.Tunnel
			next.Name += "-updated"
			updated, err := manager.Update(context.Background(), next.ID, next.Generation, next)
			if err != nil {
				t.Fatalf("update: %v", err)
			}
			if updated.Tunnel.Name != next.Name || updated.Status.Phase != model.PhasePending {
				t.Fatalf("updated state = %+v", updated)
			}
			updated, err = manager.Reconcile(context.Background(), updated.Tunnel.ID)
			if err != nil || updated.Status.ObservedGeneration != updated.Tunnel.Generation {
				t.Fatalf("waited updated state/error = %+v, %v", updated, err)
			}
			disabled, err := manager.SetEnabled(context.Background(), updated.Tunnel.ID, updated.Tunnel.Generation, false)
			if err != nil {
				t.Fatalf("disable: %v", err)
			}
			if disabled.Status.Phase != model.PhasePending {
				t.Fatalf("disabled state = %+v", disabled.Status)
			}
			disabled, err = manager.Reconcile(context.Background(), disabled.Tunnel.ID)
			if err != nil || disabled.Status.Phase != model.PhaseDisabled {
				t.Fatalf("waited disabled state/error = %+v, %v", disabled.Status, err)
			}
			if err := manager.Delete(context.Background(), disabled.Tunnel.ID, disabled.Tunnel.Generation); err != nil {
				t.Fatalf("delete: %v", err)
			}
		})
	}
}

func TestManagerIKEUpdateRetainsOldGenerationWhenCleanupFails(t *testing.T) {
	records := newMemoryStore()
	backend := newFakeBackend()
	reconciler := NewReconciler(records, backend, time.Hour)
	manager := NewManager(records, reconciler)
	input := lifecycleInputs(t)[5]
	input.Enabled = true
	created, err := manager.Create(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := records.Get(created.Tunnel.ID)
	if err != nil {
		t.Fatal(err)
	}
	backend.mu.Lock()
	backend.removeErr = errors.New("VICI unavailable")
	backend.mu.Unlock()
	next, err := model.Clone(raw)
	if err != nil {
		t.Fatal(err)
	}
	next.Name = "ike-updated"
	if _, err := manager.Update(context.Background(), raw.ID, raw.Generation, next); !IsOperationFailed(err) {
		t.Fatalf("IKEv2 update error = %v, want operation failure", err)
	}
	stored, err := records.Get(raw.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Generation != raw.Generation || stored.Name != raw.Name {
		t.Fatalf("stored record changed after failed cleanup: %+v", stored)
	}
}

func TestManagerCleansOldAutomaticWireGuardRouteTableBeforeUpdate(t *testing.T) {
	peer, _ := wgtypes.GeneratePrivateKey()
	records := newMemoryStore()
	backend := newFakeBackend()
	reconciler := NewReconciler(records, backend, time.Hour)
	manager := NewManager(records, reconciler)
	created, err := manager.Create(context.Background(), model.Tunnel{
		Name: "wg-routes", Kind: model.KindWireGuard, Interface: "wg-routes", Enabled: true,
		Spec: model.Spec{WireGuard: &model.WireGuardSpec{
			RouteAllowedIPs: true,
			Peers: []model.WireGuardPeer{{
				PublicKey:  peer.PublicKey().String(),
				AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Reconcile(context.Background(), created.Tunnel.ID); err != nil {
		t.Fatal(err)
	}
	raw, err := records.Get(created.Tunnel.ID)
	if err != nil {
		t.Fatal(err)
	}
	next, err := model.Clone(raw)
	if err != nil {
		t.Fatal(err)
	}
	next.Spec.WireGuard.Peers[0].AllowedIPs = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}
	if _, err := manager.Update(context.Background(), raw.ID, raw.Generation, next); err != nil {
		t.Fatal(err)
	}
	backend.mu.Lock()
	removeCalls := backend.removeCalls
	backend.mu.Unlock()
	if removeCalls != 1 {
		t.Fatalf("route-table-changing update remove calls = %d, want 1", removeCalls)
	}
}

func TestReconcilerStartupAndEventRetry(t *testing.T) {
	record := preparedCoreGRE(t, true)
	records := newMemoryStore(record)
	backend := newFakeBackend()
	backend.applyErr = errors.New("temporary failure")
	reconciler := NewReconciler(records, backend, time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		reconciler.Run(ctx)
		close(done)
	}()
	waitForStatus(t, reconciler, record, func(status model.Status) bool {
		return status.Phase == model.PhaseError && status.ObservedGeneration == 0
	})
	backend.mu.Lock()
	backend.applyErr = nil
	backend.mu.Unlock()
	backend.events <- BackendEvent{RecordID: record.ID, Type: BackendEventLink}
	waitForStatus(t, reconciler, record, func(status model.Status) bool {
		return status.Phase == model.PhaseReady && status.ObservedGeneration == record.Generation
	})
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("reconciler did not stop")
	}
}

func TestReconcilerRunWaitsForManagerMutation(t *testing.T) {
	record := preparedCoreGRE(t, true)
	records := newMemoryStore(record)
	backend := newFakeBackend()
	reconciler := NewReconciler(records, backend, time.Hour)
	manager := NewManager(records, reconciler)

	manager.mutationMu.Lock()
	locked := true
	defer func() {
		if locked {
			manager.mutationMu.Unlock()
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		reconciler.Run(ctx)
	}()

	select {
	case <-backend.called:
		t.Fatal("backend was called while a desired-state mutation was in progress")
	case <-time.After(50 * time.Millisecond):
	}

	manager.mutationMu.Unlock()
	locked = false
	select {
	case <-backend.called:
	case <-time.After(time.Second):
		t.Fatal("backend was not called after the desired-state mutation completed")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("reconciler did not stop")
	}
}

func TestReconcilerTargetsBackendEventToOneRecord(t *testing.T) {
	first := preparedCoreGRE(t, true)
	second := preparedCoreGRE(t, true)
	second.ID = "22222222-2222-4222-8222-222222222222"
	second.Name = "second"
	second.Interface = "gre1"
	records := newMemoryStore(first, second)
	backend := newFakeBackend()
	reconciler := NewReconciler(records, backend, time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go reconciler.Run(ctx)
	waitForCall(t, backend.called)
	waitForCall(t, backend.called)

	backend.mu.Lock()
	firstBefore := backend.applyByID[first.ID]
	secondBefore := backend.applyByID[second.ID]
	backend.mu.Unlock()
	backend.events <- BackendEvent{Type: BackendEventLink, RecordID: first.ID, Interface: first.Interface}
	waitForCall(t, backend.called)
	time.Sleep(50 * time.Millisecond)
	backend.mu.Lock()
	firstAfter := backend.applyByID[first.ID]
	secondAfter := backend.applyByID[second.ID]
	backend.mu.Unlock()
	if firstAfter != firstBefore+1 || secondAfter != secondBefore {
		t.Fatalf("targeted apply counts = first %d->%d, second %d->%d", firstBefore, firstAfter, secondBefore, secondAfter)
	}
}

func TestBackendEventMatchesRouteAndXFRMOwnership(t *testing.T) {
	wg := lifecycleInputs(t)[2]
	wg.ID = "33333333-3333-4333-8333-333333333333"
	wg.Spec.WireGuard.RouteAllowedIPs = true
	wg.Spec.WireGuard.RouteTable = 1234
	wg.Spec.WireGuard.Peers = []model.WireGuardPeer{{AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}}}
	if !backendEventMatches(BackendEvent{Type: BackendEventRoute, RouteTable: 1234}, wg) {
		t.Fatal("WireGuard route-table event did not match")
	}
	xfrm := lifecycleInputs(t)[4]
	if !backendEventMatches(BackendEvent{Type: BackendEventXFRM, XFRMIfID: xfrm.Spec.XFRMStatic.IfID}, xfrm) {
		t.Fatal("XFRM if_id event did not match")
	}
	if backendEventMatches(BackendEvent{Type: BackendEventXFRM, XFRMIfID: xfrm.Spec.XFRMStatic.IfID + 1}, xfrm) {
		t.Fatal("unrelated XFRM if_id event matched")
	}
}

func TestReconcilerSerializesOneTunnel(t *testing.T) {
	record := preparedCoreGRE(t, true)
	records := newMemoryStore(record)
	backend := newFakeBackend()
	backend.block = make(chan struct{})
	reconciler := NewReconciler(records, backend, time.Hour)
	done := make(chan struct{}, 2)
	for range 2 {
		go func() {
			_ = reconciler.Reconcile(context.Background(), record.ID)
			done <- struct{}{}
		}()
	}
	waitForCall(t, backend.called)
	time.Sleep(20 * time.Millisecond)
	backend.mu.Lock()
	maxActive := backend.maxActive
	backend.mu.Unlock()
	if maxActive != 1 {
		t.Fatalf("max concurrent applies = %d, want 1", maxActive)
	}
	close(backend.block)
	for range 2 {
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("reconcile remained blocked")
		}
	}
}

func TestStaleReconcileSnapshotCannotRecreateDeletedTunnel(t *testing.T) {
	record := preparedCoreGRE(t, true)
	records := newMemoryStore(record)
	backend := newFakeBackend()
	reconciler := NewReconciler(records, backend, time.Hour)
	if err := reconciler.Delete(context.Background(), record.ID, record.Generation); err != nil {
		t.Fatal(err)
	}
	if err := reconciler.reconcileRecord(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	backend.mu.Lock()
	applyCalls, removeCalls := backend.applyCalls, backend.removeCalls
	backend.mu.Unlock()
	if applyCalls != 0 || removeCalls != 1 {
		t.Fatalf("backend calls after stale reconcile = apply %d, remove %d", applyCalls, removeCalls)
	}
}
