package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/TunnelHelper/TH/internal/config"
)

// settingsApplier applies a new daemon settings snapshot to the running
// backend (Babel and MPTCP sections).
type settingsApplier func(config.Settings) error

// NewManagerWithSettings returns a manager that can read and update the
// daemon settings file and push settings changes to the backend.
func NewManagerWithSettings(records Store, reconciler *Reconciler, settingsPath string, apply settingsApplier) *Manager {
	manager := NewManager(records, reconciler)
	manager.settingsPath = settingsPath
	manager.applySettings = apply
	return manager
}

// Settings returns the operator-editable daemon settings (Babel and MPTCP
// sections) from the daemon settings file.
func (m *Manager) Settings() (config.Settings, error) {
	if m.settingsPath == "" {
		return config.Settings{}, errors.New("daemon settings are not configured")
	}
	settings, err := config.Load(m.settingsPath)
	if err != nil {
		return config.Settings{}, fmt.Errorf("load daemon settings: %w", err)
	}
	return settings, nil
}

// UpdateSettings validates, persists and applies new daemon settings.
func (m *Manager) UpdateSettings(ctx context.Context, next config.Settings) error {
	if m.settingsPath == "" {
		return errors.New("daemon settings are not configured")
	}
	if err := next.Validate(); err != nil {
		return fmt.Errorf("invalid daemon settings: %w", err)
	}
	current, err := config.Load(m.settingsPath)
	if err != nil {
		return fmt.Errorf("load daemon settings: %w", err)
	}
	// The operator-editable surface is the Babel and MPTCP sections;
	// filesystem layout fields stay owned by the daemon command line.
	settings := current
	settings.Babel = next.Babel
	settings.Mptcp = next.Mptcp
	if err := writeSettings(m.settingsPath, settings); err != nil {
		return fmt.Errorf("persist daemon settings: %w", err)
	}
	if m.applySettings != nil {
		if err := m.applySettings(settings); err != nil {
			return fmt.Errorf("apply daemon settings: %w", err)
		}
	}
	return nil
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
