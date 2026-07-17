package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDefaultsAndPartialSettings(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.json")
	settings, err := Load(missing)
	if err != nil {
		t.Fatal(err)
	}
	if settings.StateDir != "/var/lib/tunnel-helper" || settings.SocketGroup != "tunnel-helper" || settings.SocketGID != -1 {
		t.Fatalf("unexpected defaults: %+v", settings)
	}
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(path, []byte(`{"request_timeout_seconds":42,"socket_group":"root"}`), 0600); err != nil {
		t.Fatal(err)
	}
	settings, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if settings.RequestTimeoutSeconds != 42 || settings.SocketGroup != "root" || settings.RuntimeDir != "/run/tunnel-helper" {
		t.Fatalf("partial settings did not preserve defaults: %+v", settings)
	}
	if err := settings.ResolveSocketGID(); err != nil || settings.SocketGID < 0 {
		t.Fatalf("resolve root group = %d, %v", settings.SocketGID, err)
	}
}

func TestLoadRejectsUnknownAndMultipleValues(t *testing.T) {
	for name, data := range map[string]string{
		"unknown":  `{"not_a_setting":true}`,
		"multiple": `{} {}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "settings.json")
			if err := os.WriteFile(path, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil {
				t.Fatal("invalid settings were accepted")
			}
		})
	}
}

func TestValidateRejectsSocketOutsideRuntimeDirectory(t *testing.T) {
	settings := Defaults()
	settings.SocketPath = "/tmp/control.sock"
	if err := settings.Validate(); err == nil {
		t.Fatal("socket outside runtime directory was accepted")
	}
}

func TestLoadRejectsUnsafeSettingsFile(t *testing.T) {
	root := t.TempDir()
	unsafe := filepath.Join(root, "unsafe.json")
	if err := os.WriteFile(unsafe, []byte(`{}`), 0666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafe, 0666); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(unsafe); err == nil {
		t.Fatal("group/world-writable settings were accepted")
	}
	target := filepath.Join(root, "target.json")
	if err := os.WriteFile(target, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "settings.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(link); err == nil {
		t.Fatal("symlink settings were accepted")
	}
}

func TestValidateRejectsDangerousDirectoryLayouts(t *testing.T) {
	settings := Defaults()
	settings.StateDir = "/"
	if err := settings.Validate(); err == nil {
		t.Fatal("filesystem root was accepted as state_dir")
	}
	settings = Defaults()
	settings.RuntimeDir = filepath.Join(settings.StateDir, "run")
	settings.SocketPath = filepath.Join(settings.RuntimeDir, "control.sock")
	if err := settings.Validate(); err == nil {
		t.Fatal("overlapping state and runtime directories were accepted")
	}
}
