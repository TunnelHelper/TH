package core

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/TunnelHelper/TH/internal/model"
	"github.com/TunnelHelper/TH/internal/store"
)

type fakeBackend struct {
	mu           sync.Mutex
	applyCalls   int
	removeCalls  int
	observeCalls int
	active       int
	maxActive    int
	applyErr     error
	apply        *Observation
	removeErr    error
	observe      *Observation
	observeErr   error
	block        chan struct{}
	called       chan struct{}
	events       chan BackendEvent
	applyByID    map[string]int
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
	observation := b.apply
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
	if observation != nil {
		return *observation, err
	}
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
	b.mu.Lock()
	b.observeCalls++
	observation := b.observe
	err := b.observeErr
	b.mu.Unlock()
	if observation != nil {
		return *observation, err
	}
	if err != nil {
		return Observation{}, err
	}
	return Observation{InterfaceExists: true, InterfaceUp: true}, nil
}

func (b *fakeBackend) Health(context.Context) map[model.Kind]BackendHealth {
	return map[model.Kind]BackendHealth{model.KindGRE: {Available: true}}
}

func (b *fakeBackend) ReconcileGlobal(context.Context, []model.Tunnel) error { return nil }
func (b *fakeBackend) MptcpHealth() MptcpHealth                              { return MptcpHealth{} }
func (b *fakeBackend) Events() <-chan BackendEvent                           { return b.events }
func (b *fakeBackend) Close() error                                          { return nil }

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
		{Name: "srv6", Kind: model.KindSRv6, Spec: model.Spec{SRv6: &model.SRv6Spec{UnderlayInterface: "eth0", Table: 100, Sources: []model.SRv6Source{{Name: "source1", Family: model.SRv6FamilyIPv4, PrefixURL: "https://routes.example/edge-v4.txt", SID: netip.MustParseAddr("2001:db8::1"), Priority: 100, MTU: 1500}}}}},
	}
}

func waitForCall(t *testing.T, calls <-chan struct{}) {
	t.Helper()
	select {
	case <-calls:
	case <-time.After(2 * time.Second):
		t.Fatal("backend was not called")
	}
}

func waitForStatus(t *testing.T, reconciler *Reconciler, record model.Tunnel, ready func(model.Status) bool) {
	t.Helper()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		status := reconciler.Status(record)
		if ready(status) {
			return
		}
		select {
		case <-deadline.C:
			t.Fatalf("timed out waiting for reconciler status; last status = %+v", status)
		case <-ticker.C:
		}
	}
}
