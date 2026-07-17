package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/TunnelHelper/TH/internal/backup"
	"github.com/TunnelHelper/TH/internal/model"
	"github.com/TunnelHelper/TH/internal/store"
)

func TestBuildBackupContainsStoredSecrets(t *testing.T) {
	record := lifecycleInputs(t)[2]
	records := newMemoryStore()
	manager := NewManager(records, NewReconciler(records, newFakeBackend(), time.Hour))
	created, err := manager.Create(context.Background(), record)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := manager.BuildBackup()
	if err != nil {
		t.Fatal(err)
	}
	if len(archive.Tunnels) != 1 || archive.Tunnels[0].ID != created.Tunnel.ID || archive.Tunnels[0].Spec.WireGuard.PrivateKey == "" {
		t.Fatalf("backup archive = %+v", archive)
	}
}

func TestRestoreCheckAndApplyPreserveArchiveIdentity(t *testing.T) {
	current := batchGRE(t, "11111111-1111-4111-8111-111111111111", "current", "gre-old", false)
	desired := batchGRE(t, "22222222-2222-4222-8222-222222222222", "desired", "gre-new", true)
	records := newMemoryStore(current)
	backend := newFakeBackend()
	manager := NewManager(records, NewReconciler(records, backend, time.Hour))
	archive := testBackupArchive(desired)

	checked, err := manager.RestoreBackup(context.Background(), archive, true, true)
	if err != nil {
		t.Fatal(err)
	}
	if checked.Applied || checked.Summary.Create != 1 || checked.Summary.Delete != 1 {
		t.Fatalf("restore check = %+v", checked)
	}
	if _, err := records.Get(current.ID); err != nil {
		t.Fatalf("check mutated current state: %v", err)
	}

	applied, err := manager.RestoreBackup(context.Background(), archive, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if !applied.Applied {
		t.Fatalf("restore result = %+v", applied)
	}
	if _, err := records.Get(current.ID); err == nil {
		t.Fatal("old record remains after restore")
	}
	restored, err := records.Get(desired.ID)
	if err != nil || restored.Name != desired.Name || restored.Generation != desired.Generation {
		t.Fatalf("restored record = %+v, %v", restored, err)
	}
	if status := manager.reconciler.Status(restored); status.Phase != model.PhaseReady {
		t.Fatalf("waited restore status = %+v", status)
	}
}

func TestRestoreRollsBackDeletedStateWhenCreateFails(t *testing.T) {
	current := batchGRE(t, "33333333-3333-4333-8333-333333333333", "current", "gre-old", false)
	desired := batchGRE(t, "44444444-4444-4444-8444-444444444444", "fail-restore", "gre-new", false)
	base := newMemoryStore(current)
	records := &failingBatchStore{memoryStore: base, failCreateName: desired.Name}
	manager := NewManager(records, NewReconciler(records, newFakeBackend(), time.Hour))

	if _, err := manager.RestoreBackup(context.Background(), testBackupArchive(desired), false, false); !IsOperationFailed(err) {
		t.Fatalf("restore error = %v", err)
	}
	restored, err := records.Get(current.ID)
	if err != nil || restored.Name != current.Name || restored.Generation != current.Generation {
		t.Fatalf("rolled back record = %+v, %v", restored, err)
	}
	if _, err := records.Get(desired.ID); !errors.Is(err, store.ErrNotFound) {
		if err == nil {
			t.Fatal("failed restore record remains")
		}
	}
}

func testBackupArchive(records ...model.Tunnel) backup.Archive {
	archive := backup.Archive{
		FormatVersion: backup.FormatVersion, ProductVersion: "test", SchemaVersion: model.SchemaVersion,
		CreatedAt: time.Now().UTC(), Tunnels: records,
	}
	if err := backup.SealArchive(&archive); err != nil {
		panic(err)
	}
	return archive
}
