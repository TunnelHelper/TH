package core

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TunnelHelper/TH/internal/config"
)

func newSettingsManager(t *testing.T, configPath string, write func(string, config.Settings) error) *Manager {
	t.Helper()
	manager := NewManager(newMemoryStore(), NewReconciler(newMemoryStore(), newFakeBackend(), time.Minute))
	manager.settingsPath = configPath
	manager.writeSettings = write
	return manager
}

func writeCoreSettingsFixture(t *testing.T, path, stateDir, runtimeDir string) {
	t.Helper()
	content := `{
		"state_dir": "` + stateDir + `",
		"runtime_dir": "` + runtimeDir + `",
		"socket_path": "` + filepath.Join(runtimeDir, "control.sock") + `",
		"socket_group": "th"
	}`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func settingsFixtureDirs(t *testing.T) (stateDir, runtimeDir, configPath string) {
	t.Helper()
	root := t.TempDir()
	stateDir = filepath.Join(root, "state")
	runtimeDir = filepath.Join(root, "run")
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(runtimeDir, 0700); err != nil {
		t.Fatal(err)
	}
	configPath = filepath.Join(root, "thd.json")
	writeCoreSettingsFixture(t, configPath, stateDir, runtimeDir)
	return stateDir, runtimeDir, configPath
}

func TestManagerSettingsHonorsStateDirOverride(t *testing.T) {
	stateDir, runtimeDir, configPath := settingsFixtureDirs(t)
	override := config.Defaults()
	override.StateDir = stateDir
	override.RuntimeDir = runtimeDir
	override.SocketPath = filepath.Join(runtimeDir, "control.sock")
	override.Babel.RouterID = "aabbccddeeff0011"
	if err := writeSettings(config.SettingsOverridePath(stateDir), override); err != nil {
		t.Fatal(err)
	}

	manager := newSettingsManager(t, configPath, writeSettings)
	settings, err := manager.Settings()
	if err != nil {
		t.Fatal(err)
	}
	if settings.Babel.RouterID != "aabbccddeeff0011" {
		t.Fatalf("override must win, router id = %q", settings.Babel.RouterID)
	}
}

func TestManagerUpdateSettingsFallsBackToReadOnlyConfig(t *testing.T) {
	_, _, configPath := settingsFixtureDirs(t)
	var applied config.Settings
	// Only the configured path is unwritable; the state-directory override
	// must still be written by the real writer.
	manager := newSettingsManager(t, configPath, func(path string, settings config.Settings) error {
		if path == configPath {
			return errors.New("simulated read-only filesystem")
		}
		return writeSettings(path, settings)
	})
	manager.applySettings = func(_ context.Context, settings config.Settings) error {
		applied = settings
		return nil
	}

	next := config.Defaults()
	next.Babel.RouterID = "0011223344556677"
	next.Mptcp.Enabled = true
	if err := manager.UpdateSettings(context.Background(), next); err != nil {
		t.Fatalf("update must fall back to the state-directory override: %v", err)
	}

	loaded, err := config.LoadDaemon(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Babel.RouterID != "0011223344556677" || !loaded.Mptcp.Enabled {
		t.Fatalf("override content = %+v", loaded)
	}
	if applied.Babel.RouterID != "0011223344556677" || !applied.Mptcp.Enabled {
		t.Fatalf("applied settings = %+v", applied)
	}

	// The override must be picked up by subsequent reads too.
	settings, err := manager.Settings()
	if err != nil {
		t.Fatal(err)
	}
	if settings.Babel.RouterID != "0011223344556677" {
		t.Fatalf("Settings() after fallback = %+v", settings)
	}
}

func TestManagerUpdateSettingsRollsBackFailedRuntimeApply(t *testing.T) {
	_, _, configPath := settingsFixtureDirs(t)
	manager := newSettingsManager(t, configPath, writeSettings)
	var applied []string
	manager.applySettings = func(_ context.Context, settings config.Settings) error {
		applied = append(applied, settings.Babel.RouterID)
		if settings.Babel.RouterID == "0011223344556677" {
			return errors.New("simulated runtime failure")
		}
		return nil
	}

	next := config.Defaults()
	next.Babel.RouterID = "0011223344556677"
	err := manager.UpdateSettings(context.Background(), next)
	if err == nil || !strings.Contains(err.Error(), "simulated runtime failure") {
		t.Fatalf("update error = %v, want runtime failure", err)
	}
	if len(applied) != 2 || applied[0] != next.Babel.RouterID || applied[1] != "" {
		t.Fatalf("applied router IDs = %v, want new then rollback", applied)
	}
	loaded, loadErr := config.LoadDaemon(configPath)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if loaded.Babel.RouterID != "" {
		t.Fatalf("failed runtime update changed persisted settings: %+v", loaded.Babel)
	}
}

func TestManagerUpdateSettingsRollsBackRuntimeAfterPersistFailure(t *testing.T) {
	_, _, configPath := settingsFixtureDirs(t)
	manager := newSettingsManager(t, configPath, func(path string, settings config.Settings) error {
		if settings.Babel.RouterID == "0011223344556677" {
			return errors.New("simulated persist failure")
		}
		return writeSettings(path, settings)
	})
	var applied []string
	manager.applySettings = func(_ context.Context, settings config.Settings) error {
		applied = append(applied, settings.Babel.RouterID)
		return nil
	}

	next := config.Defaults()
	next.Babel.RouterID = "0011223344556677"
	err := manager.UpdateSettings(context.Background(), next)
	if err == nil || !strings.Contains(err.Error(), "simulated persist failure") {
		t.Fatalf("update error = %v, want persist failure", err)
	}
	if len(applied) != 2 || applied[0] != next.Babel.RouterID || applied[1] != "" {
		t.Fatalf("applied router IDs = %v, want new then rollback", applied)
	}
}

func TestManagerUpdateSettingsReportsStaleOverrideRemovalFailure(t *testing.T) {
	stateDir, runtimeDir, configPath := settingsFixtureDirs(t)
	override := config.Defaults()
	override.StateDir = stateDir
	override.RuntimeDir = runtimeDir
	override.SocketPath = filepath.Join(runtimeDir, "control.sock")
	override.Babel.RouterID = "aabbccddeeff0011"
	if err := writeSettings(config.SettingsOverridePath(stateDir), override); err != nil {
		t.Fatal(err)
	}

	manager := newSettingsManager(t, configPath, writeSettings)
	manager.removeSettingsOverride = func(string) error { return errors.New("simulated remove failure") }
	var applied []string
	manager.applySettings = func(_ context.Context, settings config.Settings) error {
		applied = append(applied, settings.Babel.RouterID)
		return nil
	}
	next := config.Defaults()
	next.Babel.RouterID = "0011223344556677"
	err := manager.UpdateSettings(context.Background(), next)
	if err == nil || !strings.Contains(err.Error(), "simulated remove failure") {
		t.Fatalf("update error = %v, want stale override removal failure", err)
	}
	loaded, loadErr := manager.Settings()
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if loaded.Babel.RouterID != override.Babel.RouterID {
		t.Fatalf("authoritative settings = %q, want old override %q", loaded.Babel.RouterID, override.Babel.RouterID)
	}
	if len(applied) != 2 || applied[0] != next.Babel.RouterID || applied[1] != override.Babel.RouterID {
		t.Fatalf("applied router IDs = %v, want new then old override", applied)
	}
}

func TestManagerUpdateSettingsSerializesConcurrentUpdates(t *testing.T) {
	_, _, configPath := settingsFixtureDirs(t)
	manager := newSettingsManager(t, configPath, writeSettings)
	var inFlight atomic.Int32
	var maxInFlight atomic.Int32
	manager.applySettings = func(_ context.Context, _ config.Settings) error {
		current := inFlight.Add(1)
		for current > maxInFlight.Load() && !maxInFlight.CompareAndSwap(maxInFlight.Load(), current) {
		}
		time.Sleep(10 * time.Millisecond)
		inFlight.Add(-1)
		return nil
	}

	first := config.Defaults()
	first.Babel.RouterID = "0011223344556677"
	second := config.Defaults()
	second.Babel.RouterID = "aabbccddeeff0011"
	var workers sync.WaitGroup
	for _, settings := range []config.Settings{first, second} {
		settings := settings
		workers.Add(1)
		go func() {
			defer workers.Done()
			if err := manager.UpdateSettings(context.Background(), settings); err != nil {
				t.Errorf("concurrent update: %v", err)
			}
		}()
	}
	workers.Wait()
	if got := maxInFlight.Load(); got != 1 {
		t.Fatalf("maximum concurrent settings applies = %d, want 1", got)
	}
}

func TestManagerUpdateSettingsRemovesStaleOverride(t *testing.T) {
	stateDir, runtimeDir, configPath := settingsFixtureDirs(t)
	override := config.Defaults()
	override.StateDir = stateDir
	override.RuntimeDir = runtimeDir
	override.SocketPath = filepath.Join(runtimeDir, "control.sock")
	override.Babel.RouterID = "aabbccddeeff0011"
	if err := writeSettings(config.SettingsOverridePath(stateDir), override); err != nil {
		t.Fatal(err)
	}

	manager := newSettingsManager(t, configPath, writeSettings)
	next := config.Defaults()
	next.Babel.RouterID = "0011223344556677"
	if err := manager.UpdateSettings(context.Background(), next); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(config.SettingsOverridePath(stateDir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale override must be removed once the configured path is writable, stat err = %v", err)
	}
	settings, err := manager.Settings()
	if err != nil {
		t.Fatal(err)
	}
	if settings.Babel.RouterID != "0011223344556677" {
		t.Fatalf("configured file must be authoritative after override removal, got %q", settings.Babel.RouterID)
	}
}

func TestManagerUpdateSettingsReportsUnrecoverableWrite(t *testing.T) {
	_, _, configPath := settingsFixtureDirs(t)
	manager := newSettingsManager(t, configPath, func(string, config.Settings) error {
		return errors.New("simulated read-only filesystem")
	})
	err := manager.UpdateSettings(context.Background(), config.Defaults())
	if err == nil {
		t.Fatal("update must fail when both the configured path and the override are unwritable")
	}
	if !strings.Contains(err.Error(), "simulated read-only filesystem") {
		t.Fatalf("error must include the root cause: %v", err)
	}
}
