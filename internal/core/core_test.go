package core

import (
	"context"
	"errors"
	"net/netip"
	"sync"
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
	waitForCall(t, backend.called)
	if status := reconciler.Status(record); status.Phase != model.PhaseError || status.ObservedGeneration != 0 {
		t.Fatalf("failure status = %+v", status)
	}
	backend.mu.Lock()
	backend.applyErr = nil
	backend.mu.Unlock()
	backend.events <- BackendEvent{RecordID: record.ID, Type: BackendEventLink}
	waitForCall(t, backend.called)
	if status := reconciler.Status(record); status.Phase != model.PhaseReady || status.ObservedGeneration != record.Generation {
		t.Fatalf("recovered status = %+v", status)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
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

type fakeBackend struct {
	mu          sync.Mutex
	applyCalls  int
	removeCalls int
	active      int
	maxActive   int
	applyErr    error
	removeErr   error
	block       chan struct{}
	called      chan struct{}
	events      chan BackendEvent
	applyByID   map[string]int
}

func newFakeBackend() *fakeBackend {
	return &fakeBackend{called: make(chan struct{}, 32), events: make(chan BackendEvent, 16), applyByID: make(map[string]int)}
}

func (b *fakeBackend) Apply(ctx context.Context, record model.Tunnel) (Observation, error) {
	b.mu.Lock()
	b.applyCalls++
	b.applyByID[record.ID]++
	b.active++
	if b.active > b.maxActive {
		b.maxActive = b.active
	}
	err := b.applyErr
	block := b.block
	b.mu.Unlock()
	b.called <- struct{}{}
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			err = ctx.Err()
		}
	}
	b.mu.Lock()
	b.active--
	b.mu.Unlock()
	return Observation{InterfaceExists: err == nil, InterfaceUp: err == nil}, err
}

func (b *fakeBackend) Remove(context.Context, model.Tunnel) (Observation, error) {
	b.mu.Lock()
	b.removeCalls++
	err := b.removeErr
	b.mu.Unlock()
	b.called <- struct{}{}
	return Observation{}, err
}

func (b *fakeBackend) Observe(context.Context, model.Tunnel) (Observation, error) {
	return Observation{InterfaceExists: true, InterfaceUp: true}, nil
}

func (b *fakeBackend) Health(context.Context) map[model.Kind]BackendHealth {
	return map[model.Kind]BackendHealth{model.KindGRE: {Available: true}}
}

func (b *fakeBackend) Events() <-chan BackendEvent { return b.events }
func (b *fakeBackend) Close() error                { return nil }

type memoryStore struct {
	mu      sync.Mutex
	records map[string]model.Tunnel
}

func newMemoryStore(records ...model.Tunnel) *memoryStore {
	result := &memoryStore{records: make(map[string]model.Tunnel)}
	for _, record := range records {
		result.records[record.ID] = record
	}
	return result
}

func (s *memoryStore) List() ([]model.Tunnel, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]model.Tunnel, 0, len(s.records))
	for _, record := range s.records {
		result = append(result, record)
	}
	return result, nil
}

func (s *memoryStore) Get(id string) (model.Tunnel, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[id]
	if !ok {
		return model.Tunnel{}, store.ErrNotFound
	}
	return record, nil
}

func (s *memoryStore) Create(record model.Tunnel) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.records[record.ID]; ok {
		return store.ErrConflict
	}
	s.records[record.ID] = record
	return nil
}

func (s *memoryStore) Update(record model.Tunnel, expected uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.records[record.ID]
	if !ok {
		return store.ErrNotFound
	}
	if current.Generation != expected || record.Generation != expected+1 {
		return store.ErrConflict
	}
	s.records[record.ID] = record
	return nil
}

func (s *memoryStore) Delete(id string, expected uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.records[id]
	if !ok {
		return store.ErrNotFound
	}
	if current.Generation != expected {
		return store.ErrConflict
	}
	delete(s.records, id)
	return nil
}

func preparedCoreGRE(t *testing.T, enabled bool) model.Tunnel {
	t.Helper()
	record := model.Tunnel{
		Name: "gre", Kind: model.KindGRE, Interface: "gre0", Enabled: enabled,
		Spec: model.Spec{GRE: &model.GRESpec{Local: netip.MustParseAddr("192.0.2.1"), Remote: netip.MustParseAddr("192.0.2.2")}},
	}
	if err := model.PrepareNew(&record, time.Now()); err != nil {
		t.Fatal(err)
	}
	return record
}

func lifecycleInputs(t *testing.T) []model.Tunnel {
	t.Helper()
	return []model.Tunnel{
		{Name: "gre", Kind: model.KindGRE, Interface: "gre0", Spec: model.Spec{GRE: &model.GRESpec{Local: netip.MustParseAddr("192.0.2.1"), Remote: netip.MustParseAddr("192.0.2.2")}}},
		{Name: "vxlan", Kind: model.KindVXLAN, Interface: "vx0", Spec: model.Spec{VXLAN: &model.VXLANSpec{VNI: 100, UnderlayInterface: "eth0", Local: netip.MustParseAddr("192.0.2.1"), Remote: netip.MustParseAddr("192.0.2.2")}}},
		{Name: "wg", Kind: model.KindWireGuard, Interface: "wg0", Spec: model.Spec{WireGuard: &model.WireGuardSpec{}}},
		{Name: "awg", Kind: model.KindAmneziaWG, Interface: "awg0", Spec: model.Spec{AmneziaWG: &model.AmneziaWGSpec{}}},
		{Name: "static", Kind: model.KindXFRMStatic, Interface: "xs0", Spec: model.Spec{XFRMStatic: &model.XFRMStaticSpec{UnderlayInterface: "eth0", Local: netip.MustParseAddr("192.0.2.1"), Remote: netip.MustParseAddr("192.0.2.2")}}},
		{Name: "ike", Kind: model.KindXFRMIKEv2, Interface: "xi0", Spec: model.Spec{XFRMIKEv2: &model.XFRMIKEv2Spec{UnderlayInterface: "eth0", LocalAddress: "192.0.2.1", RemoteAddress: "192.0.2.2", LocalID: "left", RemoteID: "right", AuthMethod: model.IKEAuthPSK}}},
		{Name: "srv6", Kind: model.KindSRv6, Spec: model.Spec{SRv6: &model.SRv6Spec{BaseURL: "https://routes.example/", UnderlayInterface: "eth0", Table: 100, Sources: []model.SRv6Source{{Name: "carrier", SIDv4: coreAddrPointer("2001:db8::1"), MTU: 1500}}}}},
	}
}

func coreAddrPointer(value string) *netip.Addr {
	address := netip.MustParseAddr(value)
	return &address
}

func waitForCall(t *testing.T, calls <-chan struct{}) {
	t.Helper()
	select {
	case <-calls:
	case <-time.After(2 * time.Second):
		t.Fatal("backend was not called")
	}
}
