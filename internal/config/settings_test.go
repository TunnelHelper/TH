package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLoadMissingSettingsUsesAllDefaults(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.json")
	settings, err := Load(missing)
	if err != nil {
		t.Fatal(err)
	}
	if defaults := Defaults(); !reflect.DeepEqual(settings, defaults) {
		t.Fatalf("missing settings = %+v, want defaults %+v", settings, defaults)
	}
}

func TestLoadPartialSettingsPreservesDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(path, []byte(`{"request_timeout_seconds":42,"socket_group":"root"}`), 0600); err != nil {
		t.Fatal(err)
	}
	settings, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if settings.RequestTimeoutSeconds != 42 || settings.SocketGroup != "root" || settings.RuntimeDir != "/run/th" {
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

func TestBabelSettingsWeightExponents(t *testing.T) {
	settings := Defaults()
	if settings.Babel.WeightBandwidthExponent != 1 || settings.Babel.WeightRTTExponent != 1 {
		t.Fatalf("default weight exponents = (%v, %v), want (1, 1)", settings.Babel.WeightBandwidthExponent, settings.Babel.WeightRTTExponent)
	}
	settings.Babel.WeightBandwidthExponent = 5
	if err := settings.Validate(); err == nil {
		t.Fatal("alpha above 4 must be rejected")
	}
	settings.Babel.WeightBandwidthExponent = 1.5
	settings.Babel.WeightRTTExponent = 2
	if err := settings.Validate(); err != nil {
		t.Fatalf("valid exponents must pass: %v", err)
	}
}

func TestMptcpSettingsDefaults(t *testing.T) {
	settings := Defaults()
	if settings.Mptcp.Enabled {
		t.Fatal("MPTCP must be disabled by default")
	}
	if settings.Mptcp.Scheduler != "" {
		t.Fatalf("default MPTCP scheduler = %q, want empty", settings.Mptcp.Scheduler)
	}
	if err := settings.Validate(); err != nil {
		t.Fatalf("defaults must validate: %v", err)
	}
}

func TestMptcpSettingsSchedulerWhitelist(t *testing.T) {
	for _, scheduler := range []string{"default", "roundrobin", "blest"} {
		settings := Defaults()
		settings.Mptcp.Scheduler = scheduler
		if err := settings.Validate(); err != nil {
			t.Errorf("scheduler %q must be accepted: %v", scheduler, err)
		}
	}
	for _, scheduler := range []string{"min_rtt", "evil", "default\nreboot", "/proc/1/cmdline", ""} {
		settings := Defaults()
		settings.Mptcp.Scheduler = scheduler
		if scheduler == "" {
			if err := settings.Validate(); err != nil {
				t.Errorf("empty scheduler must be accepted: %v", err)
			}
			continue
		}
		if err := settings.Validate(); err == nil {
			t.Errorf("scheduler %q must be rejected", scheduler)
		}
	}
}

func TestMptcpSettingsRoundTripThroughLoad(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "thd.json")
	if err := os.WriteFile(path, []byte(`{
		"state_dir": "/var/lib/th",
		"runtime_dir": "/run/th",
		"socket_path": "/run/th/control.sock",
		"socket_group": "th",
		"mptcp": {"enabled": true, "scheduler": "roundrobin"}
	}`), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("load MPTCP settings: %v", err)
	}
	if !loaded.Mptcp.Enabled || loaded.Mptcp.Scheduler != "roundrobin" {
		t.Fatalf("loaded MPTCP settings = %+v, want enabled roundrobin", loaded.Mptcp)
	}
}
