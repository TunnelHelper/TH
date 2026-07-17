package core

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/sudogeeker/tunnel-helper/internal/model"
	"github.com/sudogeeker/tunnel-helper/internal/store"
)

var (
	ErrInvalidRequest  = errors.New("invalid request")
	ErrOperationFailed = errors.New("operation failed")
)

type Manager struct {
	store      Store
	reconciler *Reconciler
	now        func() time.Time
}

func NewManager(records Store, reconciler *Reconciler) *Manager {
	return &Manager{store: records, reconciler: reconciler, now: time.Now}
}

func (m *Manager) List() ([]model.TunnelView, error) {
	records, err := m.store.List()
	if err != nil {
		return nil, err
	}
	views := make([]model.TunnelView, 0, len(records))
	for _, record := range records {
		views = append(views, m.view(record))
	}
	return views, nil
}

func (m *Manager) Get(id string) (model.TunnelView, error) {
	record, err := m.store.Get(id)
	if err != nil {
		return model.TunnelView{}, err
	}
	return m.view(record), nil
}

func (m *Manager) Create(ctx context.Context, record model.Tunnel) (model.TunnelView, error) {
	// Identity and revision metadata belong to the daemon, not API callers.
	record.ID = ""
	record.SchemaVersion = 0
	record.Generation = 0
	record.CreatedAt = time.Time{}
	record.UpdatedAt = time.Time{}
	if err := model.PrepareNew(&record, m.now()); err != nil {
		return model.TunnelView{}, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	if err := m.store.Create(record); err != nil {
		return model.TunnelView{}, err
	}
	_ = m.reconciler.Reconcile(ctx, record.ID)
	stored, err := m.store.Get(record.ID)
	if err != nil {
		return model.TunnelView{}, err
	}
	return m.view(stored), nil
}

func (m *Manager) Update(ctx context.Context, id string, expected uint64, next model.Tunnel) (model.TunnelView, error) {
	current, err := m.store.Get(id)
	if err != nil {
		return model.TunnelView{}, err
	}
	if current.Generation != expected {
		return model.TunnelView{}, store.ErrConflict
	}
	if next.Kind != current.Kind {
		return model.TunnelView{}, fmt.Errorf("%w: tunnel kind is immutable; delete and recreate the tunnel", ErrInvalidRequest)
	}
	if next.Interface != current.Interface {
		return model.TunnelView{}, fmt.Errorf("%w: interface name is immutable; delete and recreate the tunnel", ErrInvalidRequest)
	}
	if err := model.PrepareUpdate(&next, &current, m.now()); err != nil {
		return model.TunnelView{}, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	if err := validateStableOwnership(current, next); err != nil {
		return model.TunnelView{}, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	cleanupBeforeUpdate := requiresCleanupBeforeUpdate(current, next)
	if cleanupBeforeUpdate {
		// The old record is the only durable source of the previous private-key
		// fingerprint or route table. Do not commit a new generation until old
		// objects that the new record cannot identify have been removed.
		if err := m.reconciler.Remove(ctx, current); err != nil {
			return model.TunnelView{}, fmt.Errorf("%w: remove previous %s objects before update: %v", ErrOperationFailed, current.Kind, err)
		}
	}
	if err := m.store.Update(next, expected); err != nil {
		if cleanupBeforeUpdate {
			// A concurrent update or storage failure left the old desired record in
			// place. Restore whichever generation is currently authoritative.
			_ = m.reconciler.Reconcile(ctx, id)
		}
		return model.TunnelView{}, err
	}
	_ = m.reconciler.Reconcile(ctx, id)
	return m.Get(id)
}

func requiresCleanupBeforeUpdate(current, next model.Tunnel) bool {
	if current.Kind == model.KindXFRMIKEv2 {
		return true
	}
	currentSpec, nextSpec := wireGuardRouteSpecs(current), wireGuardRouteSpecs(next)
	if currentSpec == nil || nextSpec == nil || !currentSpec.RouteAllowedIPs {
		return false
	}
	return model.WireGuardRouteTable(current, currentSpec) != model.WireGuardRouteTable(next, nextSpec)
}

func wireGuardRouteSpecs(record model.Tunnel) *model.WireGuardSpec {
	switch record.Kind {
	case model.KindWireGuard:
		return record.Spec.WireGuard
	case model.KindAmneziaWG:
		if record.Spec.AmneziaWG != nil {
			return &record.Spec.AmneziaWG.WireGuardSpec
		}
	}
	return nil
}

func validateStableOwnership(current, next model.Tunnel) error {
	switch current.Kind {
	case model.KindXFRMStatic:
		if current.Spec.XFRMStatic.IfID != next.Spec.XFRMStatic.IfID || current.Spec.XFRMStatic.ReqID != next.Spec.XFRMStatic.ReqID {
			return errors.New("XFRM if_id and req_id are immutable; delete and recreate the tunnel")
		}
	case model.KindXFRMIKEv2:
		if current.Spec.XFRMIKEv2.IfID != next.Spec.XFRMIKEv2.IfID || current.Spec.XFRMIKEv2.ReqID != next.Spec.XFRMIKEv2.ReqID {
			return errors.New("XFRM if_id and req_id are immutable; delete and recreate the tunnel")
		}
	case model.KindSRv6:
		if current.Spec.SRv6.Table != next.Spec.SRv6.Table {
			return errors.New("SRv6 table is immutable; delete and recreate the tunnel")
		}
	}
	return nil
}

func (m *Manager) SetEnabled(ctx context.Context, id string, expected uint64, enabled bool) (model.TunnelView, error) {
	current, err := m.store.Get(id)
	if err != nil {
		return model.TunnelView{}, err
	}
	if current.Generation != expected {
		return model.TunnelView{}, store.ErrConflict
	}
	next, err := model.Clone(current)
	if err != nil {
		return model.TunnelView{}, err
	}
	next.Enabled = enabled
	if err := model.PrepareUpdate(&next, &current, m.now()); err != nil {
		return model.TunnelView{}, err
	}
	if err := m.store.Update(next, expected); err != nil {
		return model.TunnelView{}, err
	}
	_ = m.reconciler.Reconcile(ctx, id)
	return m.Get(id)
}

func (m *Manager) Delete(ctx context.Context, id string, expected uint64) error {
	return m.reconciler.Delete(ctx, id, expected)
}

func (m *Manager) Reconcile(ctx context.Context, id string) (model.TunnelView, error) {
	if err := m.reconciler.Reconcile(ctx, id); err != nil && !IsNotFound(err) {
		view, getErr := m.Get(id)
		if getErr != nil {
			return model.TunnelView{}, err
		}
		return view, nil
	}
	return m.Get(id)
}

func (m *Manager) ReconcileAll(ctx context.Context) ([]model.TunnelView, error) {
	_ = m.reconciler.ReconcileAll(ctx)
	return m.List()
}

func (m *Manager) Health(ctx context.Context) map[model.Kind]BackendHealth {
	return m.reconciler.Health(ctx)
}

func (m *Manager) view(record model.Tunnel) model.TunnelView {
	redacted, fields := model.Redact(record)
	return model.TunnelView{
		Tunnel:       redacted,
		SecretFields: fields,
		Status:       m.reconciler.Status(record),
	}
}
