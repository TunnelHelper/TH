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

	mutationGate *sync.RWMutex

	statusMu sync.RWMutex
	statuses map[string]model.Status
	locksMu  sync.Mutex
	locks    map[string]*sync.Mutex
	queueMu  sync.Mutex
	queueAll bool
	queued   map[string]struct{}
	wake     chan struct{}
	events   *EventHub
}

func (r *Reconciler) setMutationGate(gate *sync.RWMutex) {
	r.mutationGate = gate
}

func (r *Reconciler) withMutationRead(fn func()) {
	if r.mutationGate == nil {
		fn()
		return
	}
	r.mutationGate.RLock()
	defer r.mutationGate.RUnlock()
	fn()
}

func NewReconciler(records Store, backend Backend, interval time.Duration) *Reconciler {
	return &Reconciler{
		store:    records,
		backend:  backend,
		interval: interval,
		now:      time.Now,
		statuses: make(map[string]model.Status),
		locks:    make(map[string]*sync.Mutex),
		queued:   make(map[string]struct{}),
		wake:     make(chan struct{}, 1),
		events:   NewEventHub(1024),
	}
}

func (r *Reconciler) Run(ctx context.Context) {
	r.EnqueueAll()
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	events := r.backend.Events()
	var (
		debounce      *time.Timer
		debounced     <-chan time.Time
		backendEvents = make(map[BackendEvent]struct{})
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
			r.EnqueueAll()
		case <-r.wake:
			r.withMutationRead(func() {
				r.processQueue(ctx)
			})
		case event, ok := <-events:
			if !ok {
				events = nil
				continue
			}
			if len(backendEvents) >= 1024 {
				clear(backendEvents)
				backendEvents[BackendEvent{}] = struct{}{}
			} else {
				backendEvents[event] = struct{}{}
			}
			stopDebounce()
			debounce = time.NewTimer(250 * time.Millisecond)
			debounced = debounce.C
		case <-debounced:
			debounced = nil
			r.withMutationRead(func() {
				for event := range backendEvents {
					r.enqueueBackendEvent(event)
				}
			})
			clear(backendEvents)
		}
	}
}

func (r *Reconciler) Enqueue(id string) {
	if id == "" {
		r.EnqueueAll()
		return
	}
	r.queueMu.Lock()
	if !r.queueAll {
		r.queued[id] = struct{}{}
	}
	r.queueMu.Unlock()
	r.signalQueue()
}

func (r *Reconciler) EnqueueAll() {
	r.queueMu.Lock()
	r.queueAll = true
	clear(r.queued)
	r.queueMu.Unlock()
	r.signalQueue()
}

func (r *Reconciler) signalQueue() {
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

func (r *Reconciler) processQueue(ctx context.Context) {
	r.queueMu.Lock()
	all := r.queueAll
	r.queueAll = false
	ids := make([]string, 0, len(r.queued))
	for id := range r.queued {
		ids = append(ids, id)
	}
	clear(r.queued)
	r.queueMu.Unlock()
	if all {
		_ = r.ReconcileAll(ctx)
		return
	}
	r.reconcileIDs(ctx, ids)
}

func (r *Reconciler) reconcileIDs(ctx context.Context, ids []string) {
	if len(ids) == 0 {
		return
	}
	workers := min(4, len(ids))
	jobs := make(chan string)
	var workersDone sync.WaitGroup
	workersDone.Add(workers)
	for range workers {
		go func() {
			defer workersDone.Done()
			for id := range jobs {
				_ = r.Reconcile(ctx, id)
			}
		}()
	}
send:
	for _, id := range ids {
		select {
		case jobs <- id:
		case <-ctx.Done():
			break send
		}
	}
	close(jobs)
	workersDone.Wait()
}

func (r *Reconciler) enqueueBackendEvent(event BackendEvent) {
	if event == (BackendEvent{}) {
		r.EnqueueAll()
		return
	}
	if event.RecordID != "" {
		r.Enqueue(event.RecordID)
		return
	}
	records, err := r.store.List()
	if err != nil {
		r.EnqueueAll()
		return
	}
	for _, record := range records {
		if backendEventMatches(event, record) {
			r.Enqueue(record.ID)
		}
	}
}

func backendEventMatches(event BackendEvent, record model.Tunnel) bool {
	if event.Interface != "" && event.Interface == record.Interface {
		return true
	}
	if event.RouteTable != 0 {
		for _, claim := range model.ManagedRouteClaims(record) {
			if claim.Table == event.RouteTable {
				return true
			}
		}
		for _, table := range model.ExclusiveRouteTables(record) {
			if table == event.RouteTable {
				return true
			}
		}
	}
	switch event.Type {
	case BackendEventVICI:
		return record.Kind == model.KindXFRMIKEv2
	case BackendEventXFRM:
		switch record.Kind {
		case model.KindXFRMStatic:
			return event.XFRMIfID == 0 || record.Spec.XFRMStatic.IfID == event.XFRMIfID
		case model.KindXFRMIKEv2:
			return event.XFRMIfID == 0 || record.Spec.XFRMIKEv2.IfID == event.XFRMIfID
		}
	}
	return false
}

func (r *Reconciler) ReconcileAll(ctx context.Context) error {
	records, err := r.store.List()
	if err != nil {
		return err
	}
	if len(records) == 0 {
		return nil
	}
	workers := min(4, len(records))
	jobs := make(chan model.Tunnel)
	var (
		workersDone sync.WaitGroup
		errorsMu    sync.Mutex
		joined      error
	)
	workersDone.Add(workers)
	for range workers {
		go func() {
			defer workersDone.Done()
			for record := range jobs {
				if err := r.reconcileRecord(ctx, record); err != nil {
					errorsMu.Lock()
					joined = errors.Join(joined, fmt.Errorf("%s: %w", record.Name, err))
					errorsMu.Unlock()
				}
			}
		}()
	}
send:
	for _, record := range records {
		select {
		case jobs <- record:
		case <-ctx.Done():
			errorsMu.Lock()
			joined = errors.Join(joined, ctx.Err())
			errorsMu.Unlock()
			break send
		}
	}
	close(jobs)
	workersDone.Wait()
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
	r.events.Publish(Event{
		Type:       EventDeleted,
		TunnelID:   record.ID,
		TunnelName: record.Name,
		Generation: record.Generation,
		Phase:      model.PhaseDisabled,
	})
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

func (r *Reconciler) MarkPending(record model.Tunnel) {
	now := r.now().UTC()
	r.statusMu.Lock()
	previous := r.statuses[record.ID]
	status := model.Status{
		TunnelID:           record.ID,
		DesiredGeneration:  record.Generation,
		ObservedGeneration: previous.ObservedGeneration,
		Phase:              model.PhasePending,
		InterfaceExists:    previous.InterfaceExists,
		InterfaceUp:        previous.InterfaceUp,
		LastReconcileTime:  previous.LastReconcileTime,
		LastSuccessfulTime: previous.LastSuccessfulTime,
		Details:            previous.Details,
		Peers:              previous.Peers,
		Conditions: []model.Condition{{
			Type:               "Ready",
			Status:             false,
			Reason:             "Queued",
			Message:            "reconciliation queued",
			LastTransitionTime: transitionTime(previous, false, now),
		}},
	}
	r.statuses[record.ID] = status
	r.statusMu.Unlock()
	r.publishStatus(record, status)
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
		Peers:              observation.Peers,
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
	r.statusMu.Unlock()
	r.publishStatus(record, status)
}

func (r *Reconciler) publishStatus(record model.Tunnel, status model.Status) {
	message := ""
	if len(status.Conditions) != 0 {
		message = status.Conditions[0].Message
	}
	r.events.Publish(Event{
		Type:       EventStatus,
		TunnelID:   record.ID,
		TunnelName: record.Name,
		TunnelKind: record.Kind,
		Enabled:    record.Enabled,
		Generation: record.Generation,
		Phase:      status.Phase,
		Message:    message,
		Status:     &status,
	})
}

func (r *Reconciler) SubscribeEvents(after uint64) EventSubscription {
	return r.events.Subscribe(after)
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
