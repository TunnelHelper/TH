package core

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/TunnelHelper/TH/internal/model"
	"github.com/TunnelHelper/TH/internal/store"
)

type Reconciler struct {
	store    Store
	backend  Backend
	interval time.Duration
	now      func() time.Time

	statusMu sync.RWMutex
	statuses map[string]model.Status
	locksMu  sync.Mutex
	locks    map[string]*sync.Mutex
}

func NewReconciler(records Store, backend Backend, interval time.Duration) *Reconciler {
	return &Reconciler{
		store:    records,
		backend:  backend,
		interval: interval,
		now:      time.Now,
		statuses: make(map[string]model.Status),
		locks:    make(map[string]*sync.Mutex),
	}
}

func (r *Reconciler) Run(ctx context.Context) {
	_ = r.ReconcileAll(ctx)
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	events := r.backend.Events()
	var (
		debounce  *time.Timer
		debounced <-chan time.Time
	)
	stopDebounce := func() {
		if debounce != nil && !debounce.Stop() {
			select {
			case <-debounce.C:
			default:
			}
		}
	}
	defer stopDebounce()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = r.ReconcileAll(ctx)
		case _, ok := <-events:
			if !ok {
				events = nil
				continue
			}
			stopDebounce()
			debounce = time.NewTimer(250 * time.Millisecond)
			debounced = debounce.C
		case <-debounced:
			debounced = nil
			_ = r.ReconcileAll(ctx)
		}
	}
}

func (r *Reconciler) ReconcileAll(ctx context.Context) error {
	records, err := r.store.List()
	if err != nil {
		return err
	}
	var joined error
	for _, record := range records {
		if err := r.reconcileRecord(ctx, record); err != nil {
			joined = errors.Join(joined, fmt.Errorf("%s: %w", record.Name, err))
		}
	}
	return joined
}

func (r *Reconciler) Reconcile(ctx context.Context, id string) error {
	record, err := r.store.Get(id)
	if err != nil {
		return err
	}
	return r.reconcileRecord(ctx, record)
}

func (r *Reconciler) Remove(ctx context.Context, record model.Tunnel) error {
	lock := r.lockFor(record.ID)
	lock.Lock()
	defer lock.Unlock()
	current, err := r.store.Get(record.ID)
	if err != nil {
		return err
	}
	if current.Generation != record.Generation {
		return store.ErrConflict
	}
	observation, err := r.backend.Remove(ctx, record)
	r.setResult(record, observation, err, model.PhaseDisabled)
	return err
}

func (r *Reconciler) Delete(ctx context.Context, id string, expected uint64) error {
	lock := r.lockFor(id)
	lock.Lock()
	record, err := r.store.Get(id)
	if err != nil {
		lock.Unlock()
		return err
	}
	if record.Generation != expected {
		lock.Unlock()
		return store.ErrConflict
	}
	observation, removeErr := r.backend.Remove(ctx, record)
	r.setResult(record, observation, removeErr, model.PhaseDisabled)
	if removeErr != nil {
		lock.Unlock()
		return fmt.Errorf("%w: remove managed objects before deleting record: %v", ErrOperationFailed, removeErr)
	}
	deleteErr := r.store.Delete(id, expected)
	lock.Unlock()
	if deleteErr != nil {
		// A concurrent mutation won the generation race after teardown. Its
		// desired state remains authoritative and must be restored.
		_ = r.Reconcile(ctx, id)
		return deleteErr
	}
	r.Forget(id)
	return nil
}

func (r *Reconciler) Observe(ctx context.Context, id string) error {
	lock := r.lockFor(id)
	lock.Lock()
	defer lock.Unlock()
	record, err := r.store.Get(id)
	if err != nil {
		return err
	}
	observation, err := r.backend.Observe(ctx, record)
	phase := model.PhaseReady
	if !record.Enabled {
		phase = model.PhaseDisabled
	}
	r.setResult(record, observation, err, phase)
	return err
}

func (r *Reconciler) Status(record model.Tunnel) model.Status {
	r.statusMu.RLock()
	status, ok := r.statuses[record.ID]
	r.statusMu.RUnlock()
	if ok {
		status.DesiredGeneration = record.Generation
		return status
	}
	phase := model.PhasePending
	if !record.Enabled {
		phase = model.PhaseDisabled
	}
	return model.Status{
		TunnelID:          record.ID,
		DesiredGeneration: record.Generation,
		Phase:             phase,
	}
}

func (r *Reconciler) Forget(id string) {
	r.statusMu.Lock()
	delete(r.statuses, id)
	r.statusMu.Unlock()
	r.locksMu.Lock()
	delete(r.locks, id)
	r.locksMu.Unlock()
}

func (r *Reconciler) Health(ctx context.Context) map[model.Kind]BackendHealth {
	return r.backend.Health(ctx)
}

func (r *Reconciler) Close() error {
	return r.backend.Close()
}

func (r *Reconciler) reconcileRecord(ctx context.Context, record model.Tunnel) error {
	lock := r.lockFor(record.ID)
	lock.Lock()
	defer lock.Unlock()

	current, err := r.store.Get(record.ID)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	record = current

	var (
		observation  Observation
		reconcileErr error
		phase        model.Phase
	)
	if record.Enabled {
		observation, reconcileErr = r.backend.Apply(ctx, record)
		phase = model.PhaseReady
	} else {
		observation, reconcileErr = r.backend.Remove(ctx, record)
		phase = model.PhaseDisabled
	}
	r.setResult(record, observation, reconcileErr, phase)
	return reconcileErr
}

func (r *Reconciler) setResult(record model.Tunnel, observation Observation, err error, successPhase model.Phase) {
	now := r.now().UTC()
	r.statusMu.Lock()
	defer r.statusMu.Unlock()
	previous := r.statuses[record.ID]
	status := model.Status{
		TunnelID:           record.ID,
		DesiredGeneration:  record.Generation,
		ObservedGeneration: previous.ObservedGeneration,
		Phase:              successPhase,
		InterfaceExists:    observation.InterfaceExists,
		InterfaceUp:        observation.InterfaceUp,
		LastReconcileTime:  now,
		LastSuccessfulTime: previous.LastSuccessfulTime,
		Details:            observation.Details,
	}
	if err != nil {
		status.Phase = model.PhaseError
		status.Conditions = []model.Condition{{
			Type:               "Ready",
			Status:             false,
			Reason:             "ReconcileFailed",
			Message:            err.Error(),
			LastTransitionTime: transitionTime(previous, false, now),
		}}
	} else {
		status.ObservedGeneration = record.Generation
		status.LastSuccessfulTime = now
		status.Conditions = []model.Condition{{
			Type:               "Ready",
			Status:             successPhase == model.PhaseReady,
			Reason:             string(successPhase),
			LastTransitionTime: transitionTime(previous, successPhase == model.PhaseReady, now),
		}}
	}
	r.statuses[record.ID] = status
}

func transitionTime(previous model.Status, next bool, now time.Time) time.Time {
	for _, condition := range previous.Conditions {
		if condition.Type == "Ready" && condition.Status == next && !condition.LastTransitionTime.IsZero() {
			return condition.LastTransitionTime
		}
	}
	return now
}

func (r *Reconciler) lockFor(id string) *sync.Mutex {
	r.locksMu.Lock()
	defer r.locksMu.Unlock()
	lock := r.locks[id]
	if lock == nil {
		lock = &sync.Mutex{}
		r.locks[id] = lock
	}
	return lock
}

func IsNotFound(err error) bool {
	return errors.Is(err, store.ErrNotFound)
}

func IsConflict(err error) bool {
	return errors.Is(err, store.ErrConflict)
}

func IsInvalidRequest(err error) bool {
	return errors.Is(err, ErrInvalidRequest)
}

func IsOperationFailed(err error) bool {
	return errors.Is(err, ErrOperationFailed)
}
