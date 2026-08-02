package config

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const DefaultConfigPath = "/etc/th/thd.json"

// SettingsOverrideName is the file name inside the state directory that
// shadows the configured daemon settings file when that path is not
// writable (for example on a read-only root filesystem). The daemon writes
// it only when persisting to the configured path fails and removes it
// again once the configured path is writable.
const SettingsOverrideName = "thd.json"

// SettingsOverridePath returns the state-directory override path for the
// daemon settings.
func SettingsOverridePath(stateDir string) string {
	return filepath.Join(stateDir, SettingsOverrideName)
}

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

	// Babel configures the daemon-wide Babel routing engine. Participation
	// itself is controlled per tunnel; this section holds node-global
	// settings such as the router identifier and prefix advertisement.
	Babel BabelSettings `json:"babel,omitempty"`

	// Mptcp configures the daemon-wide MPTCP endpoint management. TH only
	// registers MPTCP endpoints when Enabled is true and the kernel exposes
	// the mptcp_pm generic-netlink family; otherwise everything degrades
	// gracefully and tunnels/Babel keep working.
	Mptcp MptcpSettings `json:"mptcp,omitempty"`
}

// MptcpSettings are the node-global MPTCP infrastructure controls. They
// manage the endpoint set (which is derived from enabled tunnels), not the
// applications' use of MPTCP.
type MptcpSettings struct {
	// Enabled turns on endpoint registration for tunnels that follow the
	// global switch. When false (the default) TH registers no endpoint and
	// changes no MPTCP sysctl.
	Enabled bool `json:"enabled,omitempty"`

	// Scheduler optionally selects the node-global MPTCP packet scheduler
	// written to net.mptcp.scheduler. Empty leaves the system setting
	// untouched. A non-empty value must be one of the well-known kernel
	// scheduler names; whether the running kernel actually provides it is
	// checked during capability detection and only warns on mismatch.
	Scheduler string `json:"scheduler,omitempty"`
}

// KnownMPTCPSchedulers is the allowlist of scheduler names TH may write to
// net.mptcp.scheduler. The kernel may also report a value not listed here
// (for example from an out-of-tree module); TH treats those as unsupported
// at configuration time rather than risking a node-global side effect.
var KnownMPTCPSchedulers = []string{"default", "roundrobin", "blest"}

// BabelSettings are the node-global Babel controls.
type BabelSettings struct {
	// RouterID is the stable 8-octet router identifier as 16 lowercase hex
	// characters. When empty, the daemon generates one and persists it in
	// the state directory so it stays stable across restarts.
	RouterID string `json:"router_id,omitempty"`

	// RouteTable is the kernel table Babel-installed routes are written
	// to. Zero means the main table.
	RouteTable int `json:"route_table,omitempty"`

	// DelayMetric enables the RFC 9616 delay-based metric: link cost is
	// derived from measured RTT instead of the fixed nominal cost.
	DelayMetric *bool `json:"delay_metric,omitempty"`

	// UnicastHelloSeconds is the unicast Hello interval used on all
	// non-multicast tunnel links. Zero means the default (4 seconds).
	UnicastHelloSeconds int `json:"unicast_hello_seconds,omitempty"`

	// DelayProbeIntervalMillis controls active RFC 9616 timestamp exchanges
	// independently from the Hello/IHU liveness cadence.
	DelayProbeIntervalMillis int `json:"delay_probe_interval_milliseconds,omitempty"`

	// DelaySampleMaxAgeMillis is the freshness deadline of an RTT estimate.
	DelaySampleMaxAgeMillis int `json:"delay_sample_max_age_milliseconds,omitempty"`

	// DelaySmoothingTimeConstantMillis controls the time-aware EWMA mean and
	// variance response independently from the probe interval.
	DelaySmoothingTimeConstantMillis int `json:"delay_smoothing_time_constant_milliseconds,omitempty"`

	// MultipathMaxPaths caps the number of next hops installed for one
	// prefix. Zero means the default (4).
	MultipathMaxPaths int `json:"multipath_max_paths,omitempty"`

	// MultipathSlack is the maximum extra cost for which an additional
	// feasible route is still used as a multipath candidate. Zero means
	// equal-cost multipath only.
	MultipathSlack int `json:"multipath_slack,omitempty"`

	// WeightBandwidthExponent, WeightRTTExponent and WeightJitterExponent
	// control the dimensionless ECMP score. Defaults of (1, 1, 1) balance
	// capacity, latency and delay variation; larger values make the
	// corresponding signal more influential.
	WeightBandwidthExponent float64 `json:"weight_bandwidth_exponent,omitempty"`
	WeightRTTExponent       float64 `json:"weight_rtt_exponent,omitempty"`
	WeightJitterExponent    float64 `json:"weight_jitter_exponent,omitempty"`

	// WeightBottleneckPenalty (K) optionally adds K / local_link_bw once per
	// hop so bandwidth participates in primary-path selection.
	// Zero (the default) keeps selection purely delay-based.
	WeightBottleneckPenalty float64 `json:"weight_bottleneck_penalty,omitempty"`

	// Interfaces declares external point-to-point interfaces (created
	// outside TH) that participate in Babel with BIRD-style explicit
	// configuration.
	Interfaces map[string]BabelExternalInterface `json:"interfaces,omitempty"`

	// Advertise controls which local prefixes are announced into Babel.
	Advertise BabelAdvertiseSettings `json:"advertise,omitempty"`
}

// BabelAdvertiseSettings selects the prefixes the local node originates.
// Either an explicit list or loopback discovery plus filters can be used.
type BabelAdvertiseSettings struct {
	// SourceInterfaces are the interfaces whose addresses are discovered
	// for advertisement. Defaults to ["lo"]. Ignored when
	// AdvertisedPrefixes is non-empty.
	SourceInterfaces []string `json:"source_interfaces,omitempty"`

	// AdvertisedPrefixes, when non-empty, is an explicit allowlist that
	// replaces interface discovery entirely.
	AdvertisedPrefixes []netip.Prefix `json:"advertised_prefixes,omitempty"`

	// Include, when non-empty, is an allowlist: a discovered prefix is
	// advertised only when it is contained in one of these prefixes.
	Include []netip.Prefix `json:"include,omitempty"`

	// Exclude always wins over Include and discovery.
	Exclude []netip.Prefix `json:"exclude,omitempty"`
}

// BabelExternalInterface is an interface created outside TH that
// participates in Babel. TH only runs the protocol on it; the creator owns
// its lifecycle.
type BabelExternalInterface struct {
	// BandwidthMbps is the declared usable bandwidth of this link. Zero
	// means unset (unlimited).
	BandwidthMbps int `json:"bandwidth_mbps,omitempty"`

	// Multicast enables multicast Babel hellos/updates on this interface.
	// Disable it on links without multicast support and provide
	// Neighbours instead.
	Multicast bool `json:"multicast,omitempty"`

	// Neighbours are the unicast Babel neighbours on this interface.
	Neighbours []netip.Addr `json:"neighbours,omitempty"`
}

func Defaults() Settings {
	return Settings{
		StateDir:                 "/var/lib/th",
		RuntimeDir:               "/run/th",
		SocketPath:               "/run/th/control.sock",
		SocketMode:               0660,
		SocketGroup:              "th",
		SocketGID:                -1,
		VICISocketPath:           "/run/charon.vici",
		ReconcileIntervalSeconds: 30,
		RequestTimeoutSeconds:    15,
		Babel: BabelSettings{
			UnicastHelloSeconds:              4,
			DelayProbeIntervalMillis:         2000,
			DelaySampleMaxAgeMillis:          10000,
			DelaySmoothingTimeConstantMillis: 30000,
			MultipathMaxPaths:                4,
			MultipathSlack:                   512,
			WeightBandwidthExponent:          1,
			WeightRTTExponent:                1,
			WeightJitterExponent:             1,
			Advertise: BabelAdvertiseSettings{
				SourceInterfaces: []string{"lo"},
			},
		},
		Mptcp: MptcpSettings{Enabled: false},
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

// LoadDaemon loads daemon settings from path, honoring a state-directory
// override written when the configured path could not be updated (read-only
// root filesystem or missing config directory). A missing, non-regular or
// invalid override falls back to the configured file.
func LoadDaemon(path string) (Settings, error) {
	base, err := Load(path)
	if err != nil {
		return Settings{}, err
	}
	overridePath := SettingsOverridePath(base.StateDir)
	info, err := os.Lstat(overridePath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return base, nil
	}
	override, err := Load(overridePath)
	if err != nil {
		return base, nil
	}
	return override, nil
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
	if err := s.Babel.Validate(); err != nil {
		return fmt.Errorf("babel: %w", err)
	}
	if err := s.Mptcp.Validate(); err != nil {
		return fmt.Errorf("mptcp: %w", err)
	}
	return nil
}

// Validate checks the MPTCP settings. The scheduler is restricted to the
// well-known kernel scheduler names so an operator typo is rejected before
// it can change a node-global sysctl.
func (m MptcpSettings) Validate() error {
	if m.Scheduler == "" {
		return nil
	}
	if len(m.Scheduler) > 64 || strings.ContainsAny(m.Scheduler, "/\x00 \t\r\n") {
		return errors.New("scheduler must be a plain scheduler name without path or whitespace")
	}
	for _, known := range KnownMPTCPSchedulers {
		if m.Scheduler == known {
			return nil
		}
	}
	return fmt.Errorf("scheduler must be one of %v", KnownMPTCPSchedulers)
}

// Validate checks the Babel settings.
func (b BabelSettings) Validate() error {
	if b.RouterID != "" {
		if len(b.RouterID) != 16 {
			return errors.New("router_id must be exactly 16 lowercase hex characters")
		}
		decoded, err := hex.DecodeString(b.RouterID)
		if err != nil {
			return errors.New("router_id must be 16 hex characters")
		}
		if allBytesEqual(decoded, 0) || allBytesEqual(decoded, 0xff) {
			return errors.New("router_id must not be all zeroes or all ones")
		}
	}
	if b.RouteTable < 0 || int64(b.RouteTable) > 2147483647 {
		return errors.New("route_table must be between 0 and 2147483647")
	}
	if b.UnicastHelloSeconds < 0 || b.UnicastHelloSeconds > 3600 {
		return errors.New("unicast_hello_seconds must be between 0 and 3600")
	}
	if b.DelayProbeIntervalMillis < 250 || b.DelayProbeIntervalMillis > 60000 {
		return errors.New("delay_probe_interval_milliseconds must be between 250 and 60000")
	}
	if b.DelaySampleMaxAgeMillis <= b.DelayProbeIntervalMillis || b.DelaySampleMaxAgeMillis > 600000 {
		return errors.New("delay_sample_max_age_milliseconds must be greater than the probe interval and at most 600000")
	}
	if b.DelaySmoothingTimeConstantMillis < 1000 || b.DelaySmoothingTimeConstantMillis > 600000 {
		return errors.New("delay_smoothing_time_constant_milliseconds must be between 1000 and 600000")
	}
	if b.MultipathMaxPaths < 0 || b.MultipathMaxPaths > 8 {
		return errors.New("multipath_max_paths must be between 0 and 8")
	}
	if b.MultipathSlack < 0 || b.MultipathSlack > 65534 {
		return errors.New("multipath_slack must be between 0 and 65534")
	}
	if !finiteInRange(b.WeightBandwidthExponent, 0, 4) ||
		!finiteInRange(b.WeightRTTExponent, 0, 4) ||
		!finiteInRange(b.WeightJitterExponent, 0, 4) {
		return errors.New("weight bandwidth, RTT and jitter exponents must be finite and between 0 and 4")
	}
	if math.IsNaN(b.WeightBottleneckPenalty) || math.IsInf(b.WeightBottleneckPenalty, 0) || b.WeightBottleneckPenalty < 0 || b.WeightBottleneckPenalty > 1e9 {
		return errors.New("weight_bottleneck_penalty must be finite and between 0 and 1000000000")
	}
	for name, external := range b.Interfaces {
		if len(name) == 0 || len(name) > 15 || strings.ContainsAny(name, "/ \t\r\n") {
			return fmt.Errorf("interfaces contains invalid interface %q", name)
		}
		if err := validateExternalInterface(name, external); err != nil {
			return err
		}
	}
	for _, name := range b.Advertise.SourceInterfaces {
		if len(name) == 0 || len(name) > 15 || strings.ContainsAny(name, "/ \t\r\n") {
			return fmt.Errorf("advertise.source_interfaces contains invalid interface %q", name)
		}
	}
	for field, prefixes := range map[string][]netip.Prefix{
		"advertised_prefixes": b.Advertise.AdvertisedPrefixes,
		"include":             b.Advertise.Include,
		"exclude":             b.Advertise.Exclude,
	} {
		seen := make(map[netip.Prefix]struct{}, len(prefixes))
		for _, prefix := range prefixes {
			if !prefix.IsValid() {
				return fmt.Errorf("advertise.%s contains an invalid prefix", field)
			}
			prefix = prefix.Masked()
			if _, ok := seen[prefix]; ok {
				return fmt.Errorf("advertise.%s contains duplicate prefix %s", field, prefix)
			}
			seen[prefix] = struct{}{}
		}
	}
	return nil
}

func finiteInRange(value, low, high float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) && value >= low && value <= high
}

// DelayMetricEnabled reports whether RFC 9616 delay-based cost is active.
func (b BabelSettings) DelayMetricEnabled() bool {
	return b.DelayMetric == nil || *b.DelayMetric
}

func validateExternalInterface(name string, external BabelExternalInterface) error {
	if external.BandwidthMbps < 0 || external.BandwidthMbps > 400000 {
		return fmt.Errorf("interfaces[%q].bandwidth_mbps must be between 0 and 400000", name)
	}
	seen := make(map[netip.Addr]struct{}, len(external.Neighbours))
	for _, addr := range external.Neighbours {
		if !addr.IsValid() || addr.IsUnspecified() {
			return fmt.Errorf("interfaces[%q].neighbours contains an invalid address", name)
		}
		if _, ok := seen[addr]; ok {
			return fmt.Errorf("interfaces[%q].neighbours contains duplicate address %s", name, addr)
		}
		seen[addr] = struct{}{}
	}
	if !external.Multicast && len(external.Neighbours) == 0 {
		return fmt.Errorf("interfaces[%q] must have neighbours when multicast is disabled", name)
	}
	return nil
}

func allBytesEqual(b []byte, value byte) bool {
	for _, current := range b {
		if current != value {
			return false
		}
	}
	return true
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

func (b BabelSettings) DelayProbeInterval() time.Duration {
	return time.Duration(b.DelayProbeIntervalMillis) * time.Millisecond
}

func (b BabelSettings) DelaySampleMaxAge() time.Duration {
	return time.Duration(b.DelaySampleMaxAgeMillis) * time.Millisecond
}

func (b BabelSettings) DelaySmoothingTimeConstant() time.Duration {
	return time.Duration(b.DelaySmoothingTimeConstantMillis) * time.Millisecond
}
