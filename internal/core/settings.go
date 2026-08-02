package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/TunnelHelper/TH/internal/config"
)

// settingsApplier applies a new daemon settings snapshot to the running
// backend (Babel and MPTCP sections).
type settingsApplier func(context.Context, config.Settings) error

// NewManagerWithSettings returns a manager that can read and update the
// daemon settings file and push settings changes to the backend.
func NewManagerWithSettings(records Store, reconciler *Reconciler, settingsPath string, apply settingsApplier) *Manager {
	manager := NewManager(records, reconciler)
	manager.settingsPath = settingsPath
	manager.applySettings = apply
	manager.writeSettings = writeSettings
	return manager
}

// Settings returns the operator-editable daemon settings (Babel and MPTCP
// sections), honoring a state-directory override when the configured
// settings path cannot be written.
func (m *Manager) Settings() (config.Settings, error) {
	m.mutationMu.RLock()
	defer m.mutationMu.RUnlock()
	if m.settingsPath == "" {
		return config.Settings{}, errors.New("daemon settings are not configured")
	}
	settings, err := config.LoadDaemon(m.settingsPath)
	if err != nil {
		return config.Settings{}, fmt.Errorf("load daemon settings: %w", err)
	}
	return settings, nil
}

// UpdateSettings validates, persists and applies new daemon settings.
func (m *Manager) UpdateSettings(ctx context.Context, next config.Settings) error {
	m.mutationMu.Lock()
	defer m.mutationMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if m.settingsPath == "" {
		return errors.New("daemon settings are not configured")
	}
	if err := next.Validate(); err != nil {
		return fmt.Errorf("invalid daemon settings: %w", err)
	}
	current, err := config.LoadDaemon(m.settingsPath)
	if err != nil {
		return fmt.Errorf("load daemon settings: %w", err)
	}
	// The operator-editable surface is the Babel and MPTCP sections;
	// filesystem layout fields stay owned by the daemon command line.
	settings := current
	settings.Babel = next.Babel
	settings.Mptcp = next.Mptcp
	if m.applySettings != nil {
		if err := m.applySettings(ctx, settings); err != nil {
			rollbackErr := m.applySettingsRollback(current)
			return fmt.Errorf("apply daemon settings: %w", errors.Join(err, wrapSettingsRollback("runtime", rollbackErr)))
		}
	}
	if err := m.saveSettings(m.settingsPath, settings); err != nil {
		restoreErr := m.saveSettings(m.settingsPath, current)
		rollbackErr := m.applySettingsRollback(current)
		return fmt.Errorf("persist daemon settings: %w", errors.Join(err,
			wrapSettingsRollback("disk", restoreErr), wrapSettingsRollback("runtime", rollbackErr)))
	}
	return nil
}

func (m *Manager) applySettingsRollback(settings config.Settings) error {
	if m.applySettings == nil {
		return nil
	}
	timeout := settings.RequestTimeout()
	rollbackContext, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return m.applySettings(rollbackContext, settings)
}

func wrapSettingsRollback(target string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("rollback %s settings: %w", target, err)
}

// saveSettings persists the settings to the configured path. When that
// path is not writable (read-only root filesystem, missing config
// directory), it falls back to a daemon-owned override in the state
// directory so the TUI/API settings editor still works. The override is
// removed automatically once the configured path is writable again.
func (m *Manager) saveSettings(path string, settings config.Settings) error {
	overridePath := config.SettingsOverridePath(settings.StateDir)
	write := m.settingsWriter()
	if err := write(path, settings); err == nil {
		if removeErr := m.settingsOverrideRemover()(overridePath); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return fmt.Errorf("remove stale daemon settings override %s: %w", overridePath, removeErr)
		}
		return nil
	} else {
		slog.Warn("daemon settings path is not writable; falling back to the state-directory override",
			"path", path, "error", err, "override", overridePath)
		if overrideErr := write(overridePath, settings); overrideErr != nil {
			return errors.Join(err, overrideErr)
		}
		return nil
	}
}

func (m *Manager) settingsOverrideRemover() func(string) error {
	if m.removeSettingsOverride != nil {
		return m.removeSettingsOverride
	}
	return os.Remove
}

func (m *Manager) settingsWriter() func(string, config.Settings) error {
	if m.writeSettings != nil {
		return m.writeSettings
	}
	return writeSettings
}

func writeSettings(path string, settings config.Settings) error {
	dir := filepath.Dir(path)
	temporary, err := os.CreateTemp(dir, ".thd-*.json")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryName)
		}
	}()
	if err := temporary.Chmod(0600); err != nil {
		return err
	}
	encoder := json.NewEncoder(temporary)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(settings); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, path); err != nil {
		return err
	}
	committed = true
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
