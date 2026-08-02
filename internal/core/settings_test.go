package core

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
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
	manager.applySettings = func(settings config.Settings) error {
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
