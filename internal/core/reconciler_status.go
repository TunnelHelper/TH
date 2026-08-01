package core

import (
	"errors"
	"sync"
	"time"

	"github.com/TunnelHelper/TH/internal/model"
	"github.com/TunnelHelper/TH/internal/store"
)

func (r *Reconciler) setReconcileResult(record model.Tunnel, observation Observation, err error, successPhase model.Phase) {
	now := r.now().UTC()
	r.statusMu.Lock()
	previous := r.statuses[record.ID]
	status := model.Status{
		TunnelID:            record.ID,
		DesiredGeneration:   record.Generation,
		ObservedGeneration:  previous.ObservedGeneration,
		Phase:               successPhase,
		InterfaceExists:     observation.InterfaceExists,
		InterfaceUp:         observation.InterfaceUp,
		LastReconcileTime:   now,
		LastObservationTime: now,
		LastSuccessfulTime:  previous.LastSuccessfulTime,
		Details:             observation.Details,
		Peers:               observation.Peers,
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

func (r *Reconciler) setObservationResult(record model.Tunnel, observation Observation, observationErr error) {
	now := r.now().UTC()
	r.statusMu.Lock()
	previous, exists := r.statuses[record.ID]
	if !exists {
		phase := model.PhasePending
		if !record.Enabled {
			phase = model.PhaseDisabled
		}
		previous = model.Status{
			TunnelID: record.ID, DesiredGeneration: record.Generation, Phase: phase,
		}
	}
	status := previous
	status.DesiredGeneration = record.Generation
	status.InterfaceExists = observation.InterfaceExists
	status.InterfaceUp = observation.InterfaceUp
	status.LastObservationTime = now
	status.Details = mergeObservationDetails(previous.Details, observation.Details)
	status.Peers = observation.Peers
	if observationErr != nil {
		reason := "ObservationFailed"
		if errors.Is(observationErr, ErrDriftDetected) {
			reason = "DriftDetected"
		}
		status.Phase = model.PhaseError
		status.Conditions = []model.Condition{{
			Type: "Ready", Status: false, Reason: reason, Message: observationErr.Error(),
			LastTransitionTime: transitionTime(previous, false, now),
		}}
	}
	r.statuses[record.ID] = status
	r.statusMu.Unlock()
	r.publishStatus(record, status)
}

func mergeObservationDetails(previous, observed map[string]string) map[string]string {
	if len(previous) == 0 && len(observed) == 0 {
		return nil
	}
	merged := make(map[string]string, len(previous)+len(observed))
	for key, value := range previous {
		merged[key] = value
	}
	for key, value := range observed {
		merged[key] = value
	}
	return merged
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
