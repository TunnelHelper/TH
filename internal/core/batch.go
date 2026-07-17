package core

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"sort"

	"github.com/TunnelHelper/TH/internal/model"
)

type BundleAction string

const (
	BundleCreate    BundleAction = "create"
	BundleUpdate    BundleAction = "update"
	BundleDelete    BundleAction = "delete"
	BundleUnchanged BundleAction = "unchanged"
)

type BundleOperation struct {
	Action  BundleAction `json:"action"`
	ID      string       `json:"id,omitempty"`
	Name    string       `json:"name"`
	Kind    model.Kind   `json:"kind"`
	Changes []string     `json:"changes,omitempty"`
}

type BundlePlanSummary struct {
	Create    int `json:"create"`
	Update    int `json:"update"`
	Delete    int `json:"delete"`
	Unchanged int `json:"unchanged"`
}

type BundlePlan struct {
	BundleVersion int               `json:"bundle_version"`
	Prune         bool              `json:"prune"`
	Summary       BundlePlanSummary `json:"summary"`
	Operations    []BundleOperation `json:"operations"`
}

type BundleApplyResult struct {
	Plan    BundlePlan         `json:"plan"`
	Tunnels []model.TunnelView `json:"tunnels"`
}

type plannedBundleChange struct {
	operation BundleOperation
	before    *model.Tunnel
	after     *model.Tunnel
}

func (m *Manager) PlanBundle(bundle model.Bundle, prune bool) (BundlePlan, error) {
	m.mutationMu.RLock()
	defer m.mutationMu.RUnlock()
	plan, _, err := m.buildBundlePlanLocked(bundle, prune)
	return plan, err
}

func (m *Manager) ApplyBundle(ctx context.Context, bundle model.Bundle, prune, wait bool) (BundleApplyResult, error) {
	m.mutationMu.Lock()
	defer m.mutationMu.Unlock()
	plan, changes, err := m.buildBundlePlanLocked(bundle, prune)
	if err != nil {
		return BundleApplyResult{}, err
	}

	ordered := orderBundleChanges(changes)
	applied := make([]plannedBundleChange, 0, len(ordered))
	for _, change := range ordered {
		if change.operation.Action == BundleUnchanged {
			continue
		}
		if err := m.applyBundleChangeLocked(ctx, change); err != nil {
			rollbackErr := m.rollbackBundleChangesLocked(ctx, applied)
			return BundleApplyResult{}, fmt.Errorf("%w: apply %s %q: %v", ErrOperationFailed, change.operation.Action, change.operation.Name, errors.Join(err, rollbackErr))
		}
		applied = append(applied, change)
	}

	for index := range applied {
		change := &applied[index]
		if change.after == nil || change.operation.Action == BundleDelete {
			continue
		}
		m.reconciler.MarkPending(*change.after)
		m.reconciler.Enqueue(change.after.ID)
		if change.operation.Action == BundleCreate {
			for operationIndex := range plan.Operations {
				operation := &plan.Operations[operationIndex]
				if operation.Action == BundleCreate && operation.Name == change.after.Name {
					operation.ID = change.after.ID
					break
				}
			}
		}
	}
	if wait {
		for _, change := range applied {
			if change.after != nil && change.operation.Action != BundleDelete {
				_ = m.reconciler.Reconcile(ctx, change.after.ID)
			}
		}
	}
	views := make([]model.TunnelView, 0, len(plan.Operations))
	for _, operation := range plan.Operations {
		if operation.Action == BundleDelete {
			continue
		}
		view, err := m.getLocked(operation.ID)
		if err != nil {
			return BundleApplyResult{}, err
		}
		views = append(views, view)
	}
	return BundleApplyResult{Plan: plan, Tunnels: views}, nil
}

func (m *Manager) buildBundlePlanLocked(bundle model.Bundle, prune bool) (BundlePlan, []plannedBundleChange, error) {
	if bundle.BundleVersion != model.BundleVersion {
		return BundlePlan{}, nil, fmt.Errorf("%w: bundle_version must be %d", ErrInvalidRequest, model.BundleVersion)
	}
	if len(bundle.Tunnels) == 0 {
		return BundlePlan{}, nil, fmt.Errorf("%w: bundle must contain at least one tunnel", ErrInvalidRequest)
	}
	if len(bundle.Tunnels) > model.MaxTunnelRecords {
		return BundlePlan{}, nil, fmt.Errorf("%w: bundle exceeds %d tunnels", ErrInvalidRequest, model.MaxTunnelRecords)
	}
	current, err := m.store.List()
	if err != nil {
		return BundlePlan{}, nil, err
	}
	byID := make(map[string]model.Tunnel, len(current))
	byName := make(map[string]model.Tunnel, len(current))
	for _, record := range current {
		byID[record.ID] = record
		byName[record.Name] = record
	}
	matched := make(map[string]struct{}, len(bundle.Tunnels))
	inputNames := make(map[string]struct{}, len(bundle.Tunnels))
	inputIDs := make(map[string]struct{}, len(bundle.Tunnels))
	changes := make([]plannedBundleChange, 0, len(bundle.Tunnels)+len(current))
	finalRecords := make([]model.Tunnel, 0, len(bundle.Tunnels)+len(current))

	for index, desired := range bundle.Tunnels {
		if desired.Name == "" {
			return BundlePlan{}, nil, fmt.Errorf("%w: tunnels[%d].name is required", ErrInvalidRequest, index)
		}
		if _, exists := inputNames[desired.Name]; exists {
			return BundlePlan{}, nil, fmt.Errorf("%w: duplicate bundle tunnel name %q", ErrInvalidRequest, desired.Name)
		}
		inputNames[desired.Name] = struct{}{}
		if desired.ID != "" {
			if !model.ValidID(desired.ID) {
				return BundlePlan{}, nil, fmt.Errorf("%w: tunnels[%d].id must be empty or a lowercase UUID", ErrInvalidRequest, index)
			}
			if _, exists := inputIDs[desired.ID]; exists {
				return BundlePlan{}, nil, fmt.Errorf("%w: duplicate bundle tunnel id %q", ErrInvalidRequest, desired.ID)
			}
			inputIDs[desired.ID] = struct{}{}
		}

		var existing *model.Tunnel
		if record, ok := byID[desired.ID]; desired.ID != "" && ok {
			existing = cloneTunnelPointer(record)
			if named, nameExists := byName[desired.Name]; nameExists && named.ID != record.ID {
				return BundlePlan{}, nil, fmt.Errorf("%w: tunnel id %s and name %q identify different records", ErrInvalidRequest, desired.ID, desired.Name)
			}
		} else if record, ok := byName[desired.Name]; ok {
			existing = cloneTunnelPointer(record)
		}
		if existing != nil {
			if _, duplicate := matched[existing.ID]; duplicate {
				return BundlePlan{}, nil, fmt.Errorf("%w: multiple bundle entries target tunnel %q", ErrInvalidRequest, existing.Name)
			}
			matched[existing.ID] = struct{}{}
			if desired.Kind != existing.Kind {
				return BundlePlan{}, nil, fmt.Errorf("%w: tunnel %q kind is immutable", ErrInvalidRequest, existing.Name)
			}
			if desired.Interface != existing.Interface {
				return BundlePlan{}, nil, fmt.Errorf("%w: tunnel %q interface is immutable", ErrInvalidRequest, existing.Name)
			}
			candidate, cloneErr := model.Clone(desired)
			if cloneErr != nil {
				return BundlePlan{}, nil, cloneErr
			}
			if err := model.PrepareUpdate(&candidate, existing, m.now()); err != nil {
				return BundlePlan{}, nil, fmt.Errorf("%w: tunnel %q: %v", ErrInvalidRequest, desired.Name, err)
			}
			if err := validateStableOwnership(*existing, candidate); err != nil {
				return BundlePlan{}, nil, fmt.Errorf("%w: tunnel %q: %v", ErrInvalidRequest, desired.Name, err)
			}
			action := BundleUpdate
			if tunnelDesiredEqual(*existing, candidate) {
				action = BundleUnchanged
				candidate = *existing
			}
			operation := BundleOperation{Action: action, ID: existing.ID, Name: candidate.Name, Kind: candidate.Kind}
			if action == BundleUpdate {
				operation.Changes = tunnelChanges(*existing, candidate)
			}
			changes = append(changes, plannedBundleChange{operation: operation, before: existing, after: cloneTunnelPointer(candidate)})
			finalRecords = append(finalRecords, candidate)
			continue
		}

		candidate, cloneErr := model.Clone(desired)
		if cloneErr != nil {
			return BundlePlan{}, nil, cloneErr
		}
		candidate.ID = ""
		candidate.SchemaVersion = 0
		candidate.Generation = 0
		if err := model.PrepareNew(&candidate, m.now()); err != nil {
			return BundlePlan{}, nil, fmt.Errorf("%w: tunnel %q: %v", ErrInvalidRequest, desired.Name, err)
		}
		operation := BundleOperation{Action: BundleCreate, Name: candidate.Name, Kind: candidate.Kind}
		changes = append(changes, plannedBundleChange{operation: operation, after: cloneTunnelPointer(candidate)})
		finalRecords = append(finalRecords, candidate)
	}

	for _, record := range current {
		if _, ok := matched[record.ID]; ok {
			continue
		}
		if prune {
			before := cloneTunnelPointer(record)
			changes = append(changes, plannedBundleChange{
				operation: BundleOperation{Action: BundleDelete, ID: record.ID, Name: record.Name, Kind: record.Kind},
				before:    before,
			})
		} else {
			finalRecords = append(finalRecords, record)
		}
	}
	if err := validateRecordSet(finalRecords); err != nil {
		return BundlePlan{}, nil, fmt.Errorf("%w: final bundle conflicts: %v", ErrInvalidRequest, err)
	}
	plan := BundlePlan{BundleVersion: model.BundleVersion, Prune: prune, Operations: make([]BundleOperation, 0, len(changes))}
	for _, change := range changes {
		plan.Operations = append(plan.Operations, change.operation)
		switch change.operation.Action {
		case BundleCreate:
			plan.Summary.Create++
		case BundleUpdate:
			plan.Summary.Update++
		case BundleDelete:
			plan.Summary.Delete++
		case BundleUnchanged:
			plan.Summary.Unchanged++
		}
	}
	return plan, changes, nil
}

func orderBundleChanges(changes []plannedBundleChange) []plannedBundleChange {
	ordered := append([]plannedBundleChange(nil), changes...)
	priority := map[BundleAction]int{BundleUnchanged: 0, BundleDelete: 1, BundleUpdate: 2, BundleCreate: 3}
	sort.SliceStable(ordered, func(i, j int) bool {
		return priority[ordered[i].operation.Action] < priority[ordered[j].operation.Action]
	})
	return ordered
}

func (m *Manager) applyBundleChangeLocked(ctx context.Context, change plannedBundleChange) error {
	switch change.operation.Action {
	case BundleUpdate:
		current, next := *change.before, *change.after
		cleanup := requiresCleanupBeforeUpdate(current, next)
		if cleanup {
			if err := m.reconciler.Remove(ctx, current); err != nil {
				return err
			}
		}
		if err := m.store.Update(next, current.Generation); err != nil {
			if cleanup {
				m.reconciler.Enqueue(current.ID)
			}
			return err
		}
		return nil
	case BundleCreate:
		return m.store.Create(*change.after)
	case BundleDelete:
		return m.reconciler.Delete(ctx, change.before.ID, change.before.Generation)
	default:
		return nil
	}
}

func (m *Manager) rollbackBundleChangesLocked(ctx context.Context, applied []plannedBundleChange) error {
	var rollbackErr error
	for index := len(applied) - 1; index >= 0; index-- {
		change := applied[index]
		switch change.operation.Action {
		case BundleCreate:
			current, err := m.store.Get(change.after.ID)
			if err == nil {
				err = m.store.Delete(current.ID, current.Generation)
				m.reconciler.Forget(current.ID)
			}
			rollbackErr = errors.Join(rollbackErr, err)
		case BundleUpdate:
			current, err := m.store.Get(change.after.ID)
			if err != nil {
				rollbackErr = errors.Join(rollbackErr, err)
				continue
			}
			restored, err := model.Clone(*change.before)
			if err == nil {
				err = model.PrepareUpdate(&restored, &current, m.now())
			}
			if err == nil {
				err = m.store.Update(restored, current.Generation)
			}
			if err == nil {
				m.reconciler.MarkPending(restored)
				m.reconciler.Enqueue(restored.ID)
			}
			rollbackErr = errors.Join(rollbackErr, err)
		case BundleDelete:
			err := m.store.Create(*change.before)
			if err == nil {
				m.reconciler.MarkPending(*change.before)
				m.reconciler.Enqueue(change.before.ID)
			}
			rollbackErr = errors.Join(rollbackErr, err)
		}
	}
	if rollbackErr != nil {
		return fmt.Errorf("rollback desired state: %w", rollbackErr)
	}
	return nil
}

func tunnelDesiredEqual(current, candidate model.Tunnel) bool {
	return current.Name == candidate.Name &&
		current.Kind == candidate.Kind &&
		current.Interface == candidate.Interface &&
		current.Enabled == candidate.Enabled &&
		reflect.DeepEqual(current.Spec, candidate.Spec)
}

func tunnelChanges(current, candidate model.Tunnel) []string {
	changes := make([]string, 0, 3)
	if current.Name != candidate.Name {
		changes = append(changes, "name")
	}
	if current.Enabled != candidate.Enabled {
		changes = append(changes, "enabled")
	}
	if !reflect.DeepEqual(current.Spec, candidate.Spec) {
		changes = append(changes, "spec")
	}
	return changes
}

func cloneTunnelPointer(record model.Tunnel) *model.Tunnel {
	copy := record
	return &copy
}

func validateRecordSet(records []model.Tunnel) error {
	if len(records) > model.MaxTunnelRecords {
		return fmt.Errorf("record set exceeds %d tunnels", model.MaxTunnelRecords)
	}
	ids := make(map[string]string, len(records))
	names := make(map[string]string, len(records))
	interfaces := make(map[string]string, len(records))
	xfrmIfIDs := make(map[uint32]string)
	xfrmReqIDs := make(map[uint32]string)
	srv6Tables := make(map[int]string)
	rulePriorities := make(map[int]string)
	type routeClaimKey struct {
		table  int
		prefix netip.Prefix
	}
	routeClaims := make(map[routeClaimKey]string)
	exclusiveRouteTables := make(map[int]string)
	usedRouteTables := make(map[int]string)
	totalRouteClaims := 0
	for index := range records {
		record := &records[index]
		if err := model.Validate(record); err != nil {
			return fmt.Errorf("%s: %w", record.Name, err)
		}
		if owner, ok := ids[record.ID]; ok {
			return fmt.Errorf("id %s is shared by %q and %q", record.ID, owner, record.Name)
		}
		ids[record.ID] = record.Name
		if owner, ok := names[record.Name]; ok {
			return fmt.Errorf("name %q is shared by ids %s and %s", record.Name, owner, record.ID)
		}
		names[record.Name] = record.ID
		if record.Interface != "" {
			if owner, ok := interfaces[record.Interface]; ok {
				return fmt.Errorf("interface %q is shared by %q and %q", record.Interface, owner, record.Name)
			}
			interfaces[record.Interface] = record.Name
		}
		var ifID, reqID uint32
		switch record.Kind {
		case model.KindXFRMStatic:
			ifID, reqID = record.Spec.XFRMStatic.IfID, record.Spec.XFRMStatic.ReqID
		case model.KindXFRMIKEv2:
			ifID, reqID = record.Spec.XFRMIKEv2.IfID, record.Spec.XFRMIKEv2.ReqID
		case model.KindSRv6:
			table := record.Spec.SRv6.Table
			if owner, ok := srv6Tables[table]; ok {
				return fmt.Errorf("SRv6 table %d is shared by %q and %q", table, owner, record.Name)
			}
			srv6Tables[table] = record.Name
		}
		if ifID != 0 {
			if owner, ok := xfrmIfIDs[ifID]; ok {
				return fmt.Errorf("XFRM if_id %d is shared by %q and %q", ifID, owner, record.Name)
			}
			xfrmIfIDs[ifID] = record.Name
		}
		if reqID != 0 {
			if owner, ok := xfrmReqIDs[reqID]; ok {
				return fmt.Errorf("XFRM req_id %d is shared by %q and %q", reqID, owner, record.Name)
			}
			xfrmReqIDs[reqID] = record.Name
		}
		for _, priority := range model.ManagedRulePriorities(*record) {
			if owner, ok := rulePriorities[priority]; ok {
				return fmt.Errorf("policy-rule priority %d is shared by %q and %q", priority, owner, record.Name)
			}
			rulePriorities[priority] = record.Name
		}
		for _, table := range model.ExclusiveRouteTables(*record) {
			if owner, ok := usedRouteTables[table]; ok && owner != record.Name {
				return fmt.Errorf("managed routes collide between %q and %q", owner, record.Name)
			}
			exclusiveRouteTables[table] = record.Name
			usedRouteTables[table] = record.Name
		}
		claims := model.ManagedRouteClaims(*record)
		totalRouteClaims += len(claims)
		if totalRouteClaims > model.MaxManagedRouteClaims {
			return fmt.Errorf("record set exceeds %d managed route claims", model.MaxManagedRouteClaims)
		}
		for _, claim := range claims {
			if owner, ok := exclusiveRouteTables[claim.Table]; ok && owner != record.Name {
				return fmt.Errorf("managed routes collide between %q and %q", owner, record.Name)
			}
			key := routeClaimKey{table: claim.Table, prefix: claim.Prefix}
			if owner, ok := routeClaims[key]; ok && owner != record.Name {
				return fmt.Errorf("managed routes collide between %q and %q", owner, record.Name)
			}
			routeClaims[key] = record.Name
			if _, ok := usedRouteTables[claim.Table]; !ok {
				usedRouteTables[claim.Table] = record.Name
			}
		}
	}
	return nil
}
