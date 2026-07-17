package core

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"time"

	"github.com/TunnelHelper/TH/internal/backup"
	"github.com/TunnelHelper/TH/internal/model"
	"github.com/TunnelHelper/TH/internal/version"
)

type RestoreAction string

const (
	RestoreCreate    RestoreAction = "create"
	RestoreReplace   RestoreAction = "replace"
	RestoreDelete    RestoreAction = "delete"
	RestoreUnchanged RestoreAction = "unchanged"
)

type RestoreOperation struct {
	Action RestoreAction `json:"action"`
	ID     string        `json:"id"`
	Name   string        `json:"name"`
	Kind   model.Kind    `json:"kind"`
}

type RestoreSummary struct {
	Create    int `json:"create"`
	Replace   int `json:"replace"`
	Delete    int `json:"delete"`
	Unchanged int `json:"unchanged"`
}

type RestoreResult struct {
	FormatVersion        int                `json:"format_version"`
	SourceProductVersion string             `json:"source_product_version"`
	SchemaVersion        int                `json:"schema_version"`
	ArchiveCreatedAt     time.Time          `json:"archive_created_at"`
	Applied              bool               `json:"applied"`
	Summary              RestoreSummary     `json:"summary"`
	Operations           []RestoreOperation `json:"operations"`
}

func (m *Manager) BuildBackup() (backup.Archive, error) {
	m.mutationMu.RLock()
	defer m.mutationMu.RUnlock()
	records, err := m.store.List()
	if err != nil {
		return backup.Archive{}, err
	}
	archive := backup.Archive{
		FormatVersion:  backup.FormatVersion,
		ProductVersion: version.Current().Version,
		SchemaVersion:  model.SchemaVersion,
		CreatedAt:      m.now().UTC(),
		Tunnels:        records,
	}
	if err := backup.SealArchive(&archive); err != nil {
		return backup.Archive{}, err
	}
	return archive, nil
}

func (m *Manager) RestoreBackup(ctx context.Context, archive backup.Archive, check, wait bool) (RestoreResult, error) {
	m.mutationMu.Lock()
	defer m.mutationMu.Unlock()
	result, current, desiredByID, err := m.planRestoreLocked(archive)
	if err != nil || check {
		return result, err
	}

	currentByID := make(map[string]model.Tunnel, len(current))
	for _, record := range current {
		currentByID[record.ID] = record
	}
	deleted := make([]model.Tunnel, 0, result.Summary.Delete+result.Summary.Replace)
	created := make([]model.Tunnel, 0, result.Summary.Create+result.Summary.Replace)
	rollback := func(applyErr error) (RestoreResult, error) {
		rollbackErr := m.rollbackRestoreLocked(created, deleted)
		return RestoreResult{}, fmt.Errorf("%w: restore backup: %v", ErrOperationFailed, errors.Join(applyErr, rollbackErr))
	}

	for _, operation := range result.Operations {
		if operation.Action != RestoreDelete && operation.Action != RestoreReplace {
			continue
		}
		record := currentByID[operation.ID]
		if err := m.reconciler.Delete(ctx, record.ID, record.Generation); err != nil {
			return rollback(err)
		}
		deleted = append(deleted, record)
	}
	for _, operation := range result.Operations {
		if operation.Action != RestoreCreate && operation.Action != RestoreReplace {
			continue
		}
		record := desiredByID[operation.ID]
		if err := m.store.Create(record); err != nil {
			return rollback(err)
		}
		created = append(created, record)
	}
	for _, record := range created {
		m.reconciler.MarkPending(record)
		m.reconciler.Enqueue(record.ID)
	}
	if wait {
		for _, record := range created {
			_ = m.reconciler.Reconcile(ctx, record.ID)
		}
	}
	result.Applied = true
	return result, nil
}

func (m *Manager) planRestoreLocked(archive backup.Archive) (RestoreResult, []model.Tunnel, map[string]model.Tunnel, error) {
	if err := backup.ValidateArchive(archive); err != nil {
		return RestoreResult{}, nil, nil, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	if err := validateRecordSet(archive.Tunnels); err != nil {
		return RestoreResult{}, nil, nil, fmt.Errorf("%w: backup ownership conflict: %v", ErrInvalidRequest, err)
	}
	current, err := m.store.List()
	if err != nil {
		return RestoreResult{}, nil, nil, err
	}
	currentByID := make(map[string]model.Tunnel, len(current))
	desiredByID := make(map[string]model.Tunnel, len(archive.Tunnels))
	for _, record := range current {
		currentByID[record.ID] = record
	}
	for _, record := range archive.Tunnels {
		desiredByID[record.ID] = record
	}
	result := RestoreResult{
		FormatVersion:        archive.FormatVersion,
		SourceProductVersion: archive.ProductVersion,
		SchemaVersion:        archive.SchemaVersion,
		ArchiveCreatedAt:     archive.CreatedAt,
		Operations:           make([]RestoreOperation, 0, len(current)+len(archive.Tunnels)),
	}
	for _, desired := range archive.Tunnels {
		action := RestoreCreate
		if existing, ok := currentByID[desired.ID]; ok {
			action = RestoreReplace
			if reflect.DeepEqual(existing, desired) {
				action = RestoreUnchanged
			}
		}
		result.Operations = append(result.Operations, RestoreOperation{Action: action, ID: desired.ID, Name: desired.Name, Kind: desired.Kind})
		switch action {
		case RestoreCreate:
			result.Summary.Create++
		case RestoreReplace:
			result.Summary.Replace++
		case RestoreUnchanged:
			result.Summary.Unchanged++
		}
	}
	for _, existing := range current {
		if _, ok := desiredByID[existing.ID]; ok {
			continue
		}
		result.Operations = append(result.Operations, RestoreOperation{Action: RestoreDelete, ID: existing.ID, Name: existing.Name, Kind: existing.Kind})
		result.Summary.Delete++
	}
	sort.SliceStable(result.Operations, func(i, j int) bool {
		priority := map[RestoreAction]int{RestoreUnchanged: 0, RestoreDelete: 1, RestoreReplace: 2, RestoreCreate: 3}
		left, right := result.Operations[i], result.Operations[j]
		if priority[left.Action] != priority[right.Action] {
			return priority[left.Action] < priority[right.Action]
		}
		return left.Name < right.Name
	})
	return result, current, desiredByID, nil
}

func (m *Manager) rollbackRestoreLocked(created, deleted []model.Tunnel) error {
	var rollbackErr error
	for index := len(created) - 1; index >= 0; index-- {
		record := created[index]
		err := m.store.Delete(record.ID, record.Generation)
		if err == nil {
			m.reconciler.Forget(record.ID)
		}
		rollbackErr = errors.Join(rollbackErr, err)
	}
	for _, record := range deleted {
		err := m.store.Create(record)
		if err == nil {
			m.reconciler.MarkPending(record)
			m.reconciler.Enqueue(record.ID)
		}
		rollbackErr = errors.Join(rollbackErr, err)
	}
	if rollbackErr != nil {
		return fmt.Errorf("rollback restore: %w", rollbackErr)
	}
	return nil
}
