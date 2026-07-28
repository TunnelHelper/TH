package core

import (
	"errors"
	"sync"
	"time"

	"github.com/TunnelHelper/TH/internal/model"
	"github.com/TunnelHelper/TH/internal/store"
)

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
