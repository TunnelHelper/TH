# TH V2 TODO

This checklist is the durable progress record for the V2 migration. Update it
as each item is completed. The scope and acceptance rules are defined in
`docs/ROADMAP.md`.

Status legend: `[ ]` pending, `[-]` in progress, `[x]` complete.

## 0. Scope and Design

- [x] Record the V2 objective and non-negotiable invariants.
- [x] Remove OpenVPN from the V2 supported-kind list.
- [x] Define process, filesystem, API, ownership, and reconciliation design.
- [x] Define backend choices and completion audit.

## 1. Foundation

- [x] Upgrade the Go toolchain level needed by current V2 dependencies.
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

- [x] Move SRv6 configuration and cache into the V2 store layout.
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
- [x] Define V2 as a clean break with no V1 importer or compatibility parser.
- [x] Report pre-existing kernel-object ownership conflicts without adopting them.
- [x] Rewrite README for V2 clean-break operation.

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
