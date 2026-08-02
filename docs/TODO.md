# TH TODO

This checklist is the durable progress record for the current architecture.
Update it as each item is completed. The scope and acceptance rules are
defined in `docs/ROADMAP.md`.

Status legend: `[ ]` pending, `[-]` in progress, `[x]` complete.

## 0. Scope and Design

- [x] Record the current objective and non-negotiable invariants.
- [x] Remove OpenVPN from the supported-kind list.
- [x] Define process, filesystem, API, ownership, and reconciliation design.
- [x] Define backend choices and completion audit.

## 1. Foundation

- [x] Upgrade the Go toolchain level needed by current dependencies.
- [x] Add versioned common tunnel metadata and typed specs.
- [x] Add strict validation and secret-redacted API representations.
- [x] Implement crash-safe per-record storage and schema handling.
- [x] Implement daemon settings with standard default paths.
- [x] Implement in-memory observed status and structured conditions.
- [x] Implement versioned HTTP/JSON API over a Unix socket.
- [x] Add Unix-socket client with timeouts and typed errors.
- [x] Add `cmd/thd` daemon entry point.
- [x] Convert `cmd/th` into a non-root daemon client.

## 2. Reconciler and Kernel Foundation

- [x] Define backend interfaces and fake implementations for tests.
- [x] Implement per-tunnel serialization and reconcile scheduling.
- [x] Implement startup, mutation-triggered, and periodic reconciliation.
- [x] Implement rtnetlink handle lifecycle and route/source discovery.
- [x] Implement link ownership aliases and conflict protection.
- [x] Implement exact address, MTU, link-up, route, and rule reconciliation.
- [x] Implement safe disable/delete and orphan reporting.

## 3. Tunnel Backends

### GRE and VXLAN

- [x] Implement IPv4/IPv6 GRE reconciliation.
- [x] Implement unicast VXLAN reconciliation.
- [x] Implement GRE/VXLAN observed status.
- [x] Add GRE/VXLAN lifecycle and ownership tests.

### WireGuard

- [x] Generate and parse WireGuard keys in Go.
- [x] Create and own WireGuard links through rtnetlink.
- [x] Configure devices and peers through `wgctrl`.
- [x] Reconcile AllowedIPs routes without `wg-quick`.
- [x] Add status and lifecycle tests.

### Static XFRM

- [x] Create and own XFRM interfaces through rtnetlink.
- [x] Reconcile exact inbound/outbound XFRM states.
- [x] Reconcile exact in/fwd/out XFRM policies.
- [x] Support AES-GCM and AES-CBC/HMAC key validation.
- [x] Add status, lifecycle, and unrelated-object protection tests.

### IKEv2 XFRM / strongSwan

- [x] Implement a timeout-bound VICI session abstraction.
- [x] Build and validate `load-conn` messages.
- [x] Load/unload PSKs with stable secret IDs.
- [x] Load/unload private keys without credential files.
- [x] Send local/remote RPK public keys as binary connection values.
- [x] Implement initiate, terminate, unload, list, and event status paths.
- [x] Reconcile the owned XFRM interface with the VICI connection.
- [x] Add VICI message fixtures and lifecycle tests.

### SRv6

- [x] Move SRv6 configuration and cache into the TH store layout.
- [x] Fetch sources with timeouts, size limits, and atomic caching.
- [x] Validate every downloaded route prefix.
- [x] Reconcile exact tables, rules, SID reachability, and SEG6 routes.
- [x] Add route-diff and malformed-feed tests.

### AmneziaWG

- [x] Implement the `amneziawg` generic-netlink client.
- [x] Encode/decode standard WireGuard device and peer attributes.
- [x] Encode/decode Jc/Jmin/Jmax/S1/S2/H1-H4 by family version.
- [x] Reconcile links, addresses, peers, routes, and status.
- [x] Add UAPI fixture and conditional-kernel lifecycle tests.

### Babel

- [x] Vendor the Babel protocol implementation as `internal/babel` with no
      external module dependency.
- [x] Implement route exchange: periodic and triggered updates, route
      acquisition, feasibility, retractions, hold time, and expiry sweep.
- [x] Implement route selection with RFC 8966 Appendix A.3 hysteresis.
- [x] Implement route requests and seqno requests with forwarding.
- [x] Move participation to per-tunnel `spec.babel {enabled,
      bandwidth_mbps}` and remove the standalone `babel` tunnel kind.
- [x] Add daemon settings (`thd.json`) for the Babel engine: router id,
      route table, delay metric, multipath limits, and prefix advertisement
      with include/exclude filters over source interfaces (default `lo`).
- [x] Add a daemon-wide Babel engine that aggregates enabled tunnels,
      derives WireGuard neighbours from peer public keys (stable LLA) and
      selects multicast vs unicast mode per interface.
- [x] Implement RFC 9616 delay-based cost (RTT timestamps in Hello/IHU,
      bounded linear cost mapping, hysteresis); throughput measurement is
      intentionally out of scope for now.
- [x] Implement RFC 9229 v4-via-v6 (AE 4) encoding for IPv4 prefixes over
      IPv6 link-local links.
- [x] Derive ECMP split weights from `bandwidth_mbps`
      (256 * bw_i / bw_best) and install weighted kernel next hops.
- [x] Switch weights to the raw-signal formula `w ∝ bandwidth^α / rtt^β`
      (smoothed RTT from RFC 9616, α/β in daemon settings, default 1,1),
      gated by a 10% change threshold and a weight-update cooldown.
- [x] Add the bandwidth/latency balance knob to the TUI settings view
      (left/right slider, default centre 1,1).
- [x] Implement docs/BABEL_ECMP.md: end-to-end bottleneck bandwidth and
      path RTT propagation (PathMetrics sub-TLV, per-hop min/accumulation),
      weight formula `bottleneck^α / path_rtt^β` with local fallbacks,
      the bias knob (α=1+bias, β=1-bias), the K bottleneck penalty,
      external PTP interfaces in daemon settings, dual-stack udp4+udp6
      sockets, and weight-change fingerprint gating.
- [x] Add settings endpoints (`GET/PUT /v1/settings`) and a TUI settings
      view for the Babel globals.
- [x] Integration-test two WireGuard nodes with only IPv6 link-local
      addresses: v4/v6 prefixes converge over both tunnels.
- [x] Surface the per-tunnel Babel toggle and bandwidth in the tunnel
      editors (manage workspace + create wizard; JSON API also supports
      `spec.babel`).
- [x] Apply daemon Babel settings changes at runtime without restarting:
      data-plane settings (advertisement filters, weight exponents, ECMP
      limits, route table) update the running engine without rebuilding the
      speaker, so adjacencies stay up; protocol settings (router id, delay
      metric, external interfaces) rebuild the speaker when they change.
- [x] Migrate all ginkgo/gomega tests to the standard library and drop the
      test-only dependencies.

## 4. TUI and Client Workflows

- [x] List and manage records through the daemon API only.
- [x] Create/edit GRE and VXLAN records.
- [x] Create/edit WireGuard and AmneziaWG records.
- [x] Create/edit static and IKEv2 XFRM records.
- [x] Create/edit SRv6 records.
- [x] Show desired/observed generation and structured errors.
- [x] Make enable, disable, reconcile, and delete explicit actions.
- [x] Ensure no TUI workflow requires root or opens an external editor.
- [x] Add a scriptable non-interactive client surface.

## 5. V1 Removal

- [x] Delete all OpenVPN source, menus, models, operational docs, and dependencies.
- [x] Delete V1 command execution helpers and all callers.
- [x] Delete interfaces/swanctl/WireGuard/Amnezia config generators.
- [x] Delete package installation and service-manager runtime flows.
- [x] Stop scanning external configuration directories as desired state.
- [x] Define TH as a clean break with no V1 importer or compatibility parser.
- [x] Report pre-existing kernel-object ownership conflicts without adopting them.
- [x] Rewrite README for clean-break operation.

## 6. Packaging and Operations

- [x] Add a hardened systemd service owned by packaging, not runtime code.
- [x] Add sysusers/tmpfiles assets for group and runtime directories.
- [x] Add install/uninstall Make targets that do not run from the daemon.
- [x] Document VICI and kernel/module prerequisites by distribution family.
- [x] Document backup, restore, secret handling, and recovery.

## 7. Verification

- [x] Add AST/source guard for external command execution.
- [x] Add forbidden-path source guard.
- [x] Add store, API, redaction, generation, and reconciler unit tests.
- [x] Add supported network-namespace integration tests.
- [x] Run `gofmt` and `go mod tidy`.
- [x] Run `go test ./...` and `go test -race ./...`.
- [x] Run `go vet ./...`.
- [x] Cross-build Linux amd64, arm64, and armv7 binaries.
- [x] Audit every invariant and completion item in `docs/ROADMAP.md`.
- [x] Confirm the git diff contains no accidental generated or unrelated files.

## 8. MPTCP Infrastructure Management (`docs/MPTCP_MANAGEMENT.md`)

- [x] Add daemon settings (`thd.json`) top-level `mptcp {enabled,
      scheduler}` with defaults (off, empty), validation, and a scheduler
      allowlist (`default`, `roundrobin`, `blest`).
- [x] Add per-tunnel `spec.mptcp {endpoint}` tri-state switch (nil follows
      global, false opts out, true opts in) and reject SRv6 records.
- [x] Implement the `mptcp_pm` generic-netlink layer (no external
      commands): capability detection (kernel >= 5.6 + family presence),
      endpoint Add/Del/List, SUBFLOW|SIGNAL default flags, and
      legacy/modern ABI-stable attribute encoding.
- [x] Derive the desired endpoint set from tunnel records and reconcile it
      after Apply (link/address ready), before Remove (endpoint first),
      at daemon startup and on the 30s periodic pass; orphan cleanup only
      deletes endpoints whose address belongs to a TH tunnel record.
- [x] Optional node-global `net.mptcp.scheduler` write (only when enabled
      and explicitly configured), with warning-only failures.
- [x] Degrade gracefully when MPTCP is unavailable: tunnels and Babel keep
      working, `th health` reports `mptcp: unsupported (reason)` and
      endpoint counts appear in observations.
- [x] Extend the settings API to a Babel + MPTCP payload and add a unified
      TUI settings editor (one page with Babel + MPTCP sections, external
      interface sub-editor, MPTCP capability/endpoint readout and a
      diff-before-save flow) plus per-tunnel endpoint toggles in the create
      wizard and workspace editor.
- [x] Unit-test config/model validation, fake-genl Add/Del/List, reconcile
      diff and ownership rules, scheduler sysctl handling, and the backend
      hooks; integration-test the real kernel lifecycle in a network
      namespace (endpoint appear/idempotent/withdraw) and the unsupported
      degradation path.
