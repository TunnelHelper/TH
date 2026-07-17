package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const DefaultConfigPath = "/etc/tunnel-helper/tunnel-helperd.json"

type Settings struct {
	StateDir                 string `json:"state_dir"`
	RuntimeDir               string `json:"runtime_dir"`
	SocketPath               string `json:"socket_path"`
	SocketMode               uint32 `json:"socket_mode"`
	SocketGroup              string `json:"socket_group"`
	SocketGID                int    `json:"-"`
	VICISocketPath           string `json:"vici_socket_path"`
	ReconcileIntervalSeconds int    `json:"reconcile_interval_seconds"`
	RequestTimeoutSeconds    int    `json:"request_timeout_seconds"`
}

func Defaults() Settings {
	return Settings{
		StateDir:                 "/var/lib/tunnel-helper",
		RuntimeDir:               "/run/tunnel-helper",
		SocketPath:               "/run/tunnel-helper/control.sock",
		SocketMode:               0660,
		SocketGroup:              "tunnel-helper",
		SocketGID:                -1,
		VICISocketPath:           "/run/charon.vici",
		ReconcileIntervalSeconds: 30,
		RequestTimeoutSeconds:    15,
	}
}

func Load(path string) (Settings, error) {
	settings := Defaults()
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return settings, nil
	}
	if err != nil {
		return Settings{}, fmt.Errorf("inspect daemon settings: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return Settings{}, errors.New("daemon settings must be a regular file, not a symlink")
	}
	if info.Mode().Perm()&0022 != 0 {
		return Settings{}, fmt.Errorf("daemon settings have unsafe mode %04o", info.Mode().Perm())
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return Settings{}, errors.New("daemon settings must be owned by the daemon user")
	}
	file, err := os.Open(path)
	if err != nil {
		return Settings{}, fmt.Errorf("open daemon settings: %w", err)
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil {
		return Settings{}, fmt.Errorf("read daemon settings: %w", err)
	}
	if len(data) > 1<<20 {
		return Settings{}, errors.New("daemon settings exceed 1 MiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&settings); err != nil {
		return Settings{}, fmt.Errorf("decode daemon settings: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return Settings{}, errors.New("daemon settings must contain exactly one JSON value")
	}
	if err := settings.Validate(); err != nil {
		return Settings{}, err
	}
	return settings, nil
}

func (s Settings) Validate() error {
	for name, value := range map[string]string{
		"state_dir":        s.StateDir,
		"runtime_dir":      s.RuntimeDir,
		"socket_path":      s.SocketPath,
		"vici_socket_path": s.VICISocketPath,
	} {
		if !filepath.IsAbs(value) {
			return fmt.Errorf("%s must be an absolute path", name)
		}
		if strings.ContainsRune(value, '\x00') {
			return fmt.Errorf("%s must not contain NUL", name)
		}
	}
	stateDir := filepath.Clean(s.StateDir)
	runtimeDir := filepath.Clean(s.RuntimeDir)
	if stateDir == string(filepath.Separator) || runtimeDir == string(filepath.Separator) {
		return errors.New("state_dir and runtime_dir must not be the filesystem root")
	}
	if pathsOverlap(stateDir, runtimeDir) {
		return errors.New("state_dir and runtime_dir must not overlap")
	}
	socketDir := filepath.Clean(filepath.Dir(s.SocketPath))
	if socketDir != runtimeDir {
		return errors.New("socket_path must be directly inside runtime_dir")
	}
	if len(s.SocketPath) > 107 {
		return errors.New("socket_path exceeds the Linux Unix-socket path limit")
	}
	if s.SocketMode == 0 || s.SocketMode > 0777 {
		return errors.New("socket_mode must be between 0001 and 0777")
	}
	if s.SocketGID < -1 {
		return errors.New("resolved socket GID must be -1 or non-negative")
	}
	if s.SocketGID == -1 {
		if s.SocketGroup == "" || len(s.SocketGroup) > 64 || strings.ContainsAny(s.SocketGroup, "/:\t\r\n ") {
			return errors.New("socket_group must be a valid local group name")
		}
	}
	if s.ReconcileIntervalSeconds < 1 || s.ReconcileIntervalSeconds > 3600 {
		return errors.New("reconcile_interval_seconds must be between 1 and 3600")
	}
	if s.RequestTimeoutSeconds < 1 || s.RequestTimeoutSeconds > 300 {
		return errors.New("request_timeout_seconds must be between 1 and 300")
	}
	return nil
}

func pathsOverlap(a, b string) bool {
	return pathContains(a, b) || pathContains(b, a)
}

func pathContains(parent, child string) bool {
	relative, err := filepath.Rel(parent, child)
	if err != nil {
		return false
	}
	return relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}

func (s *Settings) ResolveSocketGID() error {
	if s.SocketGID >= 0 {
		return nil
	}
	group, err := user.LookupGroup(s.SocketGroup)
	if err != nil {
		return fmt.Errorf("look up socket group %q: %w", s.SocketGroup, err)
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil || gid < 0 {
		return fmt.Errorf("group %q has invalid GID %q", s.SocketGroup, group.Gid)
	}
	s.SocketGID = gid
	return nil
}

func (s Settings) ReconcileInterval() time.Duration {
	return time.Duration(s.ReconcileIntervalSeconds) * time.Second
}

func (s Settings) RequestTimeout() time.Duration {
	return time.Duration(s.RequestTimeoutSeconds) * time.Second
}
