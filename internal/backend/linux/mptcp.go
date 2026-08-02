//go:build linux

package linux

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/TunnelHelper/TH/internal/config"
	"github.com/TunnelHelper/TH/internal/core"
	"github.com/TunnelHelper/TH/internal/model"
	"github.com/mdlayher/genetlink"
	mdnetlink "github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

const mptcpFamilyName = "mptcp_pm"

// mptcpPMCommand and attribute numbers used here are the intersection of
// the legacy (kernel 5.7-5.9) and modern (5.10+) mptcp_pm ABIs: the
// commands ADD_ADDR/DEL_ADDR/GET_ADDR and the address attributes
// FAMILY/ID/ADDR4/ADDR6/FLAGS keep their numbers in both generations.
const (
	mptcpPMCmdUnspec uint8 = iota
	mptcpPMCmdAddAddr
	mptcpPMCmdDelAddr
	mptcpPMCmdGetAddr
)

const (
	mptcpPMAttrUnspec uint16 = iota
	mptcpPMAttrAddr
	mptcpPMAttrRcvAddAddrs
	mptcpPMAttrSubflows
	mptcpPMAttrToken
	mptcpPMAttrLocID
	mptcpPMAttrAddrRemote
)

const (
	mptcpPMAddrAttrUnspec uint16 = iota
	mptcpPMAddrAttrFamily
	mptcpPMAddrAttrID
	mptcpPMAddrAttrAddr4
	mptcpPMAddrAttrAddr6
	mptcpPMAddrAttrPort
	mptcpPMAddrAttrFlags
	mptcpPMAddrAttrIfIdx
)

const (
	mptcpPMAddrFlagSignal  uint32 = 1 << 0
	mptcpPMAddrFlagSubflow uint32 = 1 << 1
)

// mptcpDefaultEndpointFlags is what TH registers on every tunnel address:
// SUBFLOW lets the kernel initiate subflows with the address as source and
// SIGNAL announces it via ADD_ADDR so the peer can open reverse subflows.
const mptcpDefaultEndpointFlags = mptcpPMAddrFlagSubflow | mptcpPMAddrFlagSignal

const (
	mptcpStatusDisabled    = "disabled"
	mptcpStatusEnabled     = "enabled"
	mptcpStatusUnsupported = "unsupported"
	mptcpStatusError       = "error"
)

const (
	mptcpSchedulerPath           = "/proc/sys/net/mptcp/scheduler"
	mptcpAvailableSchedulersPath = "/proc/sys/net/mptcp/available_schedulers"
	mptcpRequiredKernelMajor     = 5
	mptcpRequiredKernelMinor     = 6
)

// mptcpEndpoint is one endpoint reported by the kernel path manager.
type mptcpEndpoint struct {
	ID      uint8
	Address netip.Addr
	Flags   uint32
}

// mptcpPMClient is the kernel-facing subset of the mptcp_pm generic
// netlink API. The real implementation talks to the kernel; tests inject a
// fake to exercise the reconcile diff and ownership rules.
type mptcpPMClient interface {
	list(ctx context.Context) ([]mptcpEndpoint, error)
	add(ctx context.Context, addr netip.Addr, flags uint32) error
	delByID(ctx context.Context, id uint8) error
}

// mptcpTunnel is the engine's view of one tunnel record. Entries stay in
// the registry after a tunnel is disabled (or being removed) so its
// addresses remain identifiable as TH-owned long enough to withdraw their
// endpoints; the authoritative global reconcile purges entries whose
// records no longer exist.
type mptcpTunnel struct {
	recordID      string
	interfaceName string
	addresses     []netip.Addr
	endpoint      *bool
	enabled       bool
}

func (t mptcpTunnel) fingerprint() string {
	parts := make([]string, 0, len(t.addresses)+3)
	parts = append(parts, t.recordID, t.interfaceName, strconv.FormatBool(t.enabled))
	if t.endpoint != nil {
		parts = append(parts, strconv.FormatBool(*t.endpoint))
	}
	for _, addr := range t.addresses {
		parts = append(parts, addr.String())
	}
	sort.Strings(parts)
	return fmt.Sprint(parts)
}

// mptcpControl manages the MPTCP endpoint set. TH treats endpoint
// management as best-effort infrastructure: capability failures, genl
// errors and scheduler write failures are reported through health and
// observation but never block tunnel or Babel reconciliation.
type mptcpControl struct {
	backend  *Backend
	settings config.MptcpSettings
	client   mptcpPMClient

	mu             sync.Mutex
	tunnels        map[string]mptcpTunnel
	supported      bool
	unsupportedMsg string
	schedulerWarn  string
	status         string
	message        string
	endpoints      int
	lastDetection  time.Time
}

func newMptcpControl(backend *Backend) *mptcpControl {
	control := &mptcpControl{
		backend:  backend,
		settings: backend.settings.Mptcp,
		tunnels:  make(map[string]mptcpTunnel),
		status:   mptcpStatusDisabled,
	}
	control.refreshDetection(context.Background())
	return control
}

// upsertTunnel records (or updates) a tunnel's MPTCP participation.
func (c *mptcpControl) upsertTunnel(record model.Tunnel) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.upsertTunnelLocked(record)
}

func (c *mptcpControl) upsertTunnelLocked(record model.Tunnel) {
	entry := mptcpTunnelFromRecord(record)
	if existing, ok := c.tunnels[record.ID]; ok && existing.fingerprint() == entry.fingerprint() {
		return
	}
	c.tunnels[record.ID] = entry
}

// removeTunnel marks a tunnel inactive so its endpoints are withdrawn, but
// keeps the ownership entry (its addresses stay TH-owned) so the deletion
// is still possible after the record's enabled flag is gone. The next
// authoritative global reconcile purges records that no longer exist.
func (c *mptcpControl) removeTunnel(record model.Tunnel) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.tunnels[record.ID]
	if !ok {
		entry = mptcpTunnelFromRecord(record)
	}
	entry.enabled = false
	c.tunnels[record.ID] = entry
}

func (c *mptcpControl) refreshSettings(ctx context.Context, settings config.MptcpSettings) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	c.settings = settings
	c.mu.Unlock()
	c.refreshDetection(ctx)
	return c.reconcile(ctx)
}

// reconcileAll rebuilds the registry from the authoritative record list,
// re-runs capability detection, and reconciles the endpoint set. It is the
// startup and periodic reconciliation entry point.
func (c *mptcpControl) reconcileAll(ctx context.Context, records []model.Tunnel) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.syncRecordsLocked(records)
	c.refreshDetectionLocked(ctx)
	return c.reconcileLocked(ctx)
}

func (c *mptcpControl) syncRecordsLocked(records []model.Tunnel) {
	next := make(map[string]mptcpTunnel, len(records))
	for _, record := range records {
		next[record.ID] = mptcpTunnelFromRecord(record)
	}
	c.tunnels = next
}

// reconcile applies the current desired endpoint set for the registry. It
// uses the cached capability result; detection is refreshed on startup,
// on settings updates and on every authoritative global reconcile.
func (c *mptcpControl) reconcile(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reconcileLocked(ctx)
}

func (c *mptcpControl) reconcileLocked(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.message = ""
	c.schedulerWarn = ""
	if !c.supported {
		c.status = mptcpStatusDisabled
		if c.settings.Enabled {
			c.status = mptcpStatusUnsupported
		}
		c.message = c.unsupportedMsg
		c.endpoints = 0
		return nil
	}
	c.status = mptcpStatusEnabled
	if !c.settings.Enabled {
		c.status = mptcpStatusDisabled
	}

	// The scheduler is a node-global sysctl and is only ever written when
	// MPTCP management is explicitly enabled AND a scheduler was chosen
	// (mptcp.enabled=false means zero sysctl writes).
	if c.settings.Enabled && c.settings.Scheduler != "" {
		c.schedulerWarn = applyMPTCPScheduler(c.settings.Scheduler, mptcpAvailableSchedulersPath, mptcpSchedulerPath)
		if c.schedulerWarn != "" {
			slog.Warn("MPTCP scheduler not applied", slog.String("scheduler", c.settings.Scheduler), slog.String("reason", c.schedulerWarn))
		}
	}

	desired := c.desiredSetLocked()
	current, err := c.client.list(ctx)
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return contextErr
		}
		c.status = mptcpStatusError
		c.message = fmt.Sprintf("list MPTCP endpoints: %v", err)
		c.endpoints = 0
		slog.Warn("MPTCP endpoint reconcile failed", slog.String("error", err.Error()))
		return nil
	}

	// Missing endpoints are added with the default SUBFLOW|SIGNAL flags;
	// endpoints with stale flags are replaced because the kernel API has no
	// in-place flag update operation.
	for addr, flags := range desired {
		if endpoint, exists := findEndpoint(current, addr); exists {
			if endpoint.Flags == flags {
				continue
			}
			if err := c.client.delByID(ctx, endpoint.ID); err != nil {
				if contextErr := ctx.Err(); contextErr != nil {
					return contextErr
				}
				c.status = mptcpStatusError
				c.message = fmt.Sprintf("replace MPTCP endpoint %s flags: %v", addr, err)
				slog.Warn("MPTCP endpoint flag replacement failed", slog.String("address", addr.String()), slog.String("error", err.Error()))
				continue
			}
		}
		if err := c.client.add(ctx, addr, flags); err != nil {
			if contextErr := ctx.Err(); contextErr != nil {
				return contextErr
			}
			c.status = mptcpStatusError
			c.message = fmt.Sprintf("add MPTCP endpoint %s: %v", addr, err)
			slog.Warn("MPTCP endpoint add failed", slog.String("address", addr.String()), slog.String("error", err.Error()))
			continue
		}
	}

	// Orphan cleanup deletes only endpoints whose address belongs to a TH
	// tunnel record; user-registered endpoints are never touched.
	for _, endpoint := range current {
		if _, keep := desired[endpoint.Address.Unmap()]; keep {
			continue
		}
		if !c.ownedLocked(endpoint.Address) {
			continue
		}
		if err := c.client.delByID(ctx, endpoint.ID); err != nil {
			if contextErr := ctx.Err(); contextErr != nil {
				return contextErr
			}
			c.status = mptcpStatusError
			c.message = fmt.Sprintf("delete MPTCP endpoint %s: %v", endpoint.Address, err)
			slog.Warn("MPTCP endpoint delete failed", slog.String("address", endpoint.Address.String()), slog.String("error", err.Error()))
			continue
		}
	}

	// Re-list so the reported endpoint count reflects the kernel after the
	// add/del pass, not the pre-pass snapshot.
	refreshed, err := c.client.list(ctx)
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return contextErr
		}
		c.status = mptcpStatusError
		c.message = fmt.Sprintf("list MPTCP endpoints: %v", err)
		slog.Warn("MPTCP endpoint recount failed", slog.String("error", err.Error()))
		return nil
	}
	current = refreshed

	c.endpoints = c.thManagedCountLocked(current)
	return nil
}

// desiredSetLocked derives the expected endpoint set from the registry:
// every enabled tunnel that follows the global switch (or explicitly opts
// in) and has an interface address.
func (c *mptcpControl) desiredSetLocked() map[netip.Addr]uint32 {
	desired := make(map[netip.Addr]uint32)
	for _, tunnel := range c.tunnels {
		if !tunnel.enabled {
			continue
		}
		switch {
		case tunnel.endpoint == nil:
			// Follow the global switch.
			if !c.settings.Enabled {
				continue
			}
		case !*tunnel.endpoint:
			// Explicit opt-out even when the global switch is on.
			continue
		}
		for _, addr := range tunnel.addresses {
			desired[addr.Unmap()] = mptcpDefaultEndpointFlags
		}
	}
	return desired
}

// ownedLocked reports whether an endpoint address belongs to a TH tunnel:
// the interface name matches a tunnel record and the address is part of
// that tunnel's spec.addresses. Non-TH addresses are never touched.
func (c *mptcpControl) ownedLocked(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, tunnel := range c.tunnels {
		if tunnel.interfaceName == "" {
			continue
		}
		for _, candidate := range tunnel.addresses {
			if candidate.Unmap() == addr {
				return true
			}
		}
	}
	return false
}

func (c *mptcpControl) thManagedCountLocked(current []mptcpEndpoint) int {
	count := 0
	for _, endpoint := range current {
		if c.ownedLocked(endpoint.Address) {
			count++
		}
	}
	return count
}

// refreshDetection re-runs capability detection regardless of cache age.
func (c *mptcpControl) refreshDetection(ctx context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.refreshDetectionLocked(ctx)
}

func (c *mptcpControl) refreshDetectionLocked(ctx context.Context) {
	// A non-genl client is an injected test fake whose capability state is
	// configured directly; do not overwrite it with a live detection.
	if c.client != nil {
		if _, ok := c.client.(*mptcpGenlClient); !ok {
			return
		}
	}
	supported, reason := c.detect(ctx)
	c.supported = supported
	c.unsupportedMsg = reason
	c.lastDetection = time.Now()
}

// detect checks the two capability gates: kernel version >= 5.6 and the
// mptcp_pm generic-netlink family. The family check is authoritative:
// CONFIG_MPTCP being disabled or the module unloaded makes the family
// missing, which already reports unsupported.
func (c *mptcpControl) detect(ctx context.Context) (bool, string) {
	if !kernelMPTCPVersionOK() {
		return false, fmt.Sprintf("kernel too old (need Linux >= %d.%d)", mptcpRequiredKernelMajor, mptcpRequiredKernelMinor)
	}
	client, err := c.ensureClientLocked(ctx)
	if err != nil {
		return false, err.Error()
	}
	if _, err := client.family(ctx); err != nil {
		return false, fmt.Sprintf("MPTCP path manager is not available (%s generic-netlink family missing: %v)", mptcpFamilyName, err)
	}
	return true, ""
}

// ensureClientLocked lazily dials the generic-netlink socket. Dialing only
// opens a socket; capability detection is completed by the family lookup.
func (c *mptcpControl) ensureClientLocked(ctx context.Context) (*mptcpGenlClient, error) {
	if c.client != nil {
		if real, ok := c.client.(*mptcpGenlClient); ok {
			return real, nil
		}
		return nil, errors.New("MPTCP generic-netlink client is not available")
	}
	client, err := newMptcpGenlClient(c.backend.settings.RequestTimeout())
	if err != nil {
		return nil, fmt.Errorf("open %s generic-netlink socket: %w", mptcpFamilyName, err)
	}
	c.client = client
	return client, nil
}

// health returns the current MPTCP capability and endpoint snapshot.
func (c *mptcpControl) health() core.MptcpHealth {
	c.mu.Lock()
	defer c.mu.Unlock()
	message := c.message
	if c.schedulerWarn != "" {
		if message != "" {
			message += "; "
		}
		message += "scheduler: " + c.schedulerWarn
	}
	return core.MptcpHealth{
		Supported: c.supported,
		Enabled:   c.settings.Enabled,
		Status:    c.status,
		Message:   message,
		Endpoints: c.endpoints,
	}
}

// observationDetails renders the MPTCP status for one tunnel's observation.
func (c *mptcpControl) observationDetails() map[string]string {
	c.mu.Lock()
	defer c.mu.Unlock()
	details := map[string]string{
		"mptcp":           c.status,
		"mptcp_endpoints": strconv.Itoa(c.endpoints),
	}
	if c.status == mptcpStatusUnsupported && c.unsupportedMsg != "" {
		details["mptcp"] = "unsupported (" + c.unsupportedMsg + ")"
	}
	if c.schedulerWarn != "" {
		details["mptcp_scheduler"] = c.schedulerWarn
	}
	return details
}

func (c *mptcpControl) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if client, ok := c.client.(*mptcpGenlClient); ok {
		client.close()
	}
	c.client = nil
}

func mptcpTunnelFromRecord(record model.Tunnel) mptcpTunnel {
	tunnel := mptcpTunnel{
		recordID:      record.ID,
		interfaceName: record.Interface,
		enabled:       record.Enabled,
	}
	if record.Spec.Mptcp != nil {
		tunnel.endpoint = record.Spec.Mptcp.Endpoint
	}
	tunnel.addresses = tunnelAddresses(record)
	return tunnel
}

// tunnelAddresses returns the interface addresses of a tunnel that are
// valid MPTCP endpoint sources. SRv6 tunnels have no interface address and
// are excluded by validation.
func tunnelAddresses(record model.Tunnel) []netip.Addr {
	var prefixes []netip.Prefix
	switch record.Kind {
	case model.KindGRE:
		if record.Spec.GRE != nil {
			prefixes = record.Spec.GRE.Addresses
		}
	case model.KindVXLAN:
		if record.Spec.VXLAN != nil {
			prefixes = record.Spec.VXLAN.Addresses
		}
	case model.KindWireGuard:
		if record.Spec.WireGuard != nil {
			prefixes = record.Spec.WireGuard.Addresses
		}
	case model.KindAmneziaWG:
		if record.Spec.AmneziaWG != nil {
			prefixes = record.Spec.AmneziaWG.Addresses
		}
	case model.KindXFRMStatic:
		if record.Spec.XFRMStatic != nil {
			prefixes = record.Spec.XFRMStatic.Addresses
		}
	case model.KindXFRMIKEv2:
		if record.Spec.XFRMIKEv2 != nil {
			prefixes = record.Spec.XFRMIKEv2.Addresses
		}
	}
	addresses := make([]netip.Addr, 0, len(prefixes))
	for _, prefix := range prefixes {
		if prefix.IsValid() {
			addresses = append(addresses, prefix.Addr().Unmap())
		}
	}
	return addresses
}

func findEndpoint(endpoints []mptcpEndpoint, addr netip.Addr) (mptcpEndpoint, bool) {
	addr = addr.Unmap()
	for _, endpoint := range endpoints {
		if endpoint.Address.Unmap() == addr {
			return endpoint, true
		}
	}
	return mptcpEndpoint{}, false
}

// applyMPTCPScheduler writes the configured scheduler to
// net.mptcp.scheduler. It returns an empty string on success or a
// non-fatal warning. TH never changes the node-global scheduler unless it
// was explicitly configured, and a failure only warns.
func applyMPTCPScheduler(scheduler, availablePath, schedulerPath string) string {
	if scheduler == "" {
		return ""
	}
	available, err := os.ReadFile(availablePath)
	if err != nil {
		return fmt.Sprintf("cannot read net.mptcp.available_schedulers: %v", err)
	}
	if !mptcpSchedulerAvailable(string(available), scheduler) {
		return fmt.Sprintf("scheduler %q is not in net.mptcp.available_schedulers", scheduler)
	}
	if err := os.WriteFile(schedulerPath, []byte(scheduler), 0); err != nil {
		return fmt.Sprintf("write net.mptcp.scheduler: %v", err)
	}
	return ""
}

func mptcpSchedulerAvailable(available, want string) bool {
	for _, name := range strings.Fields(available) {
		if name == want {
			return true
		}
	}
	return false
}

// kernelMPTCPVersionOK reports whether the running kernel is new enough
// for MPTCP (>= 5.6). When the release string cannot be parsed the family
// check is allowed to decide.
func kernelMPTCPVersionOK() bool {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return true
	}
	release := unix.ByteSliceToString(uts.Release[:])
	major, minor, ok := parseKernelVersion(release)
	if !ok {
		return true
	}
	return major > mptcpRequiredKernelMajor ||
		(major == mptcpRequiredKernelMajor && minor >= mptcpRequiredKernelMinor)
}

func parseKernelVersion(release string) (major, minor int, ok bool) {
	parts := strings.SplitN(release, ".", 3)
	if len(parts) < 2 {
		return 0, 0, false
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, false
	}
	minor, err = strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, false
	}
	return major, minor, true
}

// mptcpGenlClient is the real mptcp_pm generic-netlink client.
type mptcpGenlClient struct {
	conn    *genetlink.Conn
	timeout time.Duration
	mu      sync.Mutex
}

func newMptcpGenlClient(timeout time.Duration) (*mptcpGenlClient, error) {
	conn, err := genetlink.Dial(nil)
	if err != nil {
		return nil, fmt.Errorf("open generic-netlink socket: %w", err)
	}
	for _, option := range []mdnetlink.ConnOption{mdnetlink.ExtendedAcknowledge, mdnetlink.GetStrictCheck} {
		_ = conn.SetOption(option, true)
	}
	return &mptcpGenlClient{conn: conn, timeout: timeout}, nil
}

func (c *mptcpGenlClient) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		_ = c.conn.Close()
		c.conn = nil
	}
}

func (c *mptcpGenlClient) family(ctx context.Context) (genetlink.Family, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.familyLocked(ctx)
}

func (c *mptcpGenlClient) familyLocked(ctx context.Context) (genetlink.Family, error) {
	if err := ctx.Err(); err != nil {
		return genetlink.Family{}, err
	}
	family, err := c.conn.GetFamily(mptcpFamilyName)
	if err != nil {
		return genetlink.Family{}, fmt.Errorf("resolve %s generic-netlink family: %w", mptcpFamilyName, err)
	}
	return family, nil
}

func (c *mptcpGenlClient) execute(ctx context.Context, command uint8, flags mdnetlink.HeaderFlags, data []byte) ([]genetlink.Message, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	deadline := time.Now().Add(c.timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := c.conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	defer c.conn.SetDeadline(time.Time{})
	family, err := c.familyLocked(ctx)
	if err != nil {
		return nil, err
	}
	messages, err := c.conn.Execute(genetlink.Message{
		Header: genetlink.Header{Command: command, Version: family.Version},
		Data:   data,
	}, family.ID, flags)
	if err != nil {
		return nil, fmt.Errorf("%s generic-netlink command %d: %w", mptcpFamilyName, command, err)
	}
	return messages, nil
}

func (c *mptcpGenlClient) list(ctx context.Context) ([]mptcpEndpoint, error) {
	messages, err := c.execute(ctx, mptcpPMCmdGetAddr, mdnetlink.Request|mdnetlink.Dump, nil)
	if err != nil {
		return nil, err
	}
	return parseMptcpEndpoints(messages)
}

func (c *mptcpGenlClient) add(ctx context.Context, addr netip.Addr, flags uint32) error {
	data, err := encodeMptcpAddAddress(addr, flags)
	if err != nil {
		return err
	}
	_, err = c.execute(ctx, mptcpPMCmdAddAddr, mdnetlink.Request|mdnetlink.Acknowledge, data)
	return err
}

func (c *mptcpGenlClient) delByID(ctx context.Context, id uint8) error {
	encoder := mdnetlink.NewAttributeEncoder()
	encoder.Nested(mptcpPMAttrAddr, func(nested *mdnetlink.AttributeEncoder) error {
		nested.Uint8(mptcpPMAddrAttrID, id)
		return nil
	})
	data, err := encoder.Encode()
	if err != nil {
		return err
	}
	_, err = c.execute(ctx, mptcpPMCmdDelAddr, mdnetlink.Request|mdnetlink.Acknowledge, data)
	return err
}

// encodeMptcpAddAddress builds the nested MPTCP_PM_ATTR_ADDR payload for
// ADD_ADDR: family, address and flags. The kernel allocates the endpoint
// ID itself.
func encodeMptcpAddAddress(addr netip.Addr, flags uint32) ([]byte, error) {
	addr = addr.Unmap()
	encoder := mdnetlink.NewAttributeEncoder()
	encoder.Nested(mptcpPMAttrAddr, func(nested *mdnetlink.AttributeEncoder) error {
		if addr.Is4() {
			nested.Uint16(mptcpPMAddrAttrFamily, unix.AF_INET)
			four := addr.As4()
			nested.Bytes(mptcpPMAddrAttrAddr4, four[:])
		} else {
			nested.Uint16(mptcpPMAddrAttrFamily, unix.AF_INET6)
			sixteen := addr.As16()
			nested.Bytes(mptcpPMAddrAttrAddr6, sixteen[:])
		}
		nested.Uint32(mptcpPMAddrAttrFlags, flags)
		return nil
	})
	return encoder.Encode()
}

func parseMptcpEndpoints(messages []genetlink.Message) ([]mptcpEndpoint, error) {
	var endpoints []mptcpEndpoint
	for _, message := range messages {
		decoder, err := mdnetlink.NewAttributeDecoder(message.Data)
		if err != nil {
			return nil, err
		}
		for decoder.Next() {
			if decoder.Type() != mptcpPMAttrAddr {
				continue
			}
			decoder.Nested(func(nested *mdnetlink.AttributeDecoder) error {
				endpoint, err := parseMptcpAddrAttrs(nested)
				if err != nil {
					return err
				}
				endpoints = append(endpoints, endpoint)
				return nil
			})
		}
		if err := decoder.Err(); err != nil {
			return nil, err
		}
	}
	return endpoints, nil
}

func parseMptcpAddrAttrs(decoder *mdnetlink.AttributeDecoder) (mptcpEndpoint, error) {
	var endpoint mptcpEndpoint
	for decoder.Next() {
		switch decoder.Type() {
		case mptcpPMAddrAttrID:
			endpoint.ID = decoder.Uint8()
		case mptcpPMAddrAttrAddr4:
			bytes := decoder.Bytes()
			if len(bytes) != 4 {
				return endpoint, fmt.Errorf("MPTCP endpoint ADDR4 has %d bytes, want 4", len(bytes))
			}
			endpoint.Address = netip.AddrFrom4([4]byte(bytes))
		case mptcpPMAddrAttrAddr6:
			bytes := decoder.Bytes()
			if len(bytes) != 16 {
				return endpoint, fmt.Errorf("MPTCP endpoint ADDR6 has %d bytes, want 16", len(bytes))
			}
			endpoint.Address = netip.AddrFrom16([16]byte(bytes))
		case mptcpPMAddrAttrFlags:
			endpoint.Flags = decoder.Uint32()
		}
	}
	if err := decoder.Err(); err != nil {
		return endpoint, err
	}
	if !endpoint.Address.IsValid() {
		return endpoint, errors.New("MPTCP endpoint response is missing an address")
	}
	return endpoint, nil
}
