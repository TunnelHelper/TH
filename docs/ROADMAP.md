# TH V2 Roadmap

## Objective

V2 turns TH into a Linux tunnel management service instead of a
configuration-file generator. The privileged daemon owns desired state and
reconciles it directly with kernel and control-plane APIs. The TUI is an
unprivileged client of that daemon.

This document is the authoritative scope for the V2 migration. `docs/TODO.md`
tracks implementation progress.

## Non-negotiable Invariants

1. Runtime production code must not execute external commands. This includes
   `ip`, `ifup`, `ifdown`, `wg`, `wg-quick`, `awg`, `awg-quick`, `swanctl`,
   `systemctl`, package managers, shells, editors, `openssl`, `git`, `make`,
   `dkms`, and `modprobe`.
2. Runtime production code must not read, generate, edit, or delete tunnel
   configuration in `/etc/network/interfaces*`, Netplan, NetworkManager,
   systemd-networkd, `/etc/wireguard`, `/etc/amnezia`, `/etc/swanctl`, or
   `/etc/openvpn`.
3. OpenVPN support is removed from V2. No OpenVPN menu, model, backend,
   migration target, dependency check, operational documentation, or runtime
   path remains.
4. Linux links, addresses, routes, rules, and static XFRM state/policy are
   managed through netlink APIs.
5. WireGuard and AmneziaWG device configuration uses generic netlink APIs.
6. strongSwan is controlled exclusively through the VICI protocol. V2 never
   invokes `swanctl` and never writes swanctl configuration or credential files.
7. The daemon-owned desired-state store is the sole source of truth. Scanning
   unrelated system configuration directories is not a management mechanism.
8. The TUI does not need root. All privileged operations happen in the daemon.
9. All apply/delete operations are idempotent and delete only objects proven to
   be owned by TH. Broad route or XFRM flushes are forbidden.
10. Missing kernel modules, VICI, or protocol families are reported as
    structured health/errors. V2 does not install dependencies itself.

## Supported V2 Tunnel Kinds

- GRE over IPv4 and IPv6
- VXLAN with unicast remote endpoint
- WireGuard
- AmneziaWG
- XFRM interface with IKEv2 managed by strongSwan VICI
- Static-key XFRM
- SRv6 route sets

## Process Architecture

```text
th (TUI and scriptable client)
        |
        | versioned JSON API over Unix domain socket
        v
thd (privileged daemon)
  +-- API and peer authorization
  +-- desired-state store
  +-- reconciler and status conditions
  +-- rtnetlink / XFRM netlink
  +-- WireGuard / AmneziaWG generic netlink
  `-- strongSwan VICI
```

Two binaries are used so the daemon does not include interactive UI code and
the client does not contain privileged backends:

- `cmd/th`: TUI and non-interactive client commands.
- `cmd/thd`: long-running privileged daemon.

## Filesystem Layout

The layout follows the distinction between operator configuration, persistent
service state, and runtime state:

- `/etc/th/thd.json`: optional daemon settings.
- `/var/lib/th/tunnels/<id>.json`: desired tunnel records and
  secrets, owned by root, directory mode `0700`, file mode `0600`.
- `/var/lib/th/cache/srv6/`: downloaded SRv6 source data.
- `/run/th/control.sock`: local API socket, mode configurable and
  normally owned by `root:th` with mode `0660`.

The daemon is the only writer. Records use a schema version, stable ID,
generation, desired enabled state, typed spec, and timestamps. Writes use a
same-directory temporary file, file sync, atomic rename, and directory sync.
Secrets are redacted from normal API responses and logs.

## API Surface

The initial local API is HTTP/1.1 with JSON over the Unix socket. It is easy to
version, test, and consume without generated code.

- `GET /v1/health`
- `GET /v1/tunnels`
- `POST /v1/tunnels`
- `GET /v1/tunnels/{id}`
- `PUT /v1/tunnels/{id}`
- `DELETE /v1/tunnels/{id}`
- `POST /v1/tunnels/{id}/enable`
- `POST /v1/tunnels/{id}/disable`
- `POST /v1/reconcile`

Mutation requests validate the complete typed spec. Updates use generation
preconditions so stale clients cannot overwrite newer changes. Desired state is
normally persisted before reconciliation; updates that would discard the only
old credential fingerprint or route-table ownership data first complete a safe
teardown and retain the old generation on failure. Apply failures remain visible
as conditions and are retried.

## Domain Model

Every tunnel has common metadata and exactly one typed spec. IPs and networks
are parsed into `net/netip` values at boundaries rather than manipulated as
unvalidated strings. Private keys and PSKs are write-only in ordinary API
representations.

Status is observed state, not configuration. It includes the desired and
observed generation, phase, last transition, last successful reconciliation,
and structured conditions. Status is rebuilt from kernel/VICI state after a
daemon restart.

## Reconciliation and Ownership

- Reconcile all enabled records on startup.
- Reconcile after every mutation and on relevant netlink/VICI events.
- Run a bounded periodic repair loop as a fallback.
- Serialize operations per tunnel and bound all I/O with contexts/timeouts.
- Mark created links with `Alias=th:<record-id>`.
- Refuse to mutate or delete a same-name link without the ownership alias.
- Allocate stable XFRM `if_id` and `reqid` values from record identity and check
  for collisions.
- Diff exact addresses, routes, rules, peers, XFRM states, and policies.
- Replace owned links only when immutable link attributes change.
- A disabled record remains stored but has no managed kernel/VICI objects.
- Delete tears down owned objects before removing the record. If teardown fails,
  the record is retained with a structured error so ownership information is
  never discarded while runtime objects may remain.

## Backend Plan

### rtnetlink and XFRM

Use `github.com/vishvananda/netlink` handles instead of command wrappers. The
backend covers link discovery and ownership, route lookup, GRE, VXLAN, XFRM
interfaces, addresses, MTU, link state, routes, policy rules, static XFRM
states/policies, and SRv6 encapsulation.

### WireGuard

Create the link through rtnetlink and configure it with
`golang.zx2c4.com/wireguard/wgctrl`. Generate Curve25519 keys in Go. The daemon
owns address and route behavior instead of reproducing shell-oriented
`wg-quick` hooks.

### AmneziaWG

Create the link through rtnetlink and implement the published `amneziawg`
generic-netlink family using `mdlayher/genetlink`. Encode standard peer data and
the Jc/Jmin/Jmax/S1/S2/H1-H4 attributes according to the detected family
version. Kernel module installation is outside the application.

### strongSwan VICI

Use `github.com/strongswan/govici/vici` against a configurable VICI socket.
Connections use `load-conn`; PSKs use `load-shared`; private keys use
`load-key`; raw public keys are sent as binary `pubkeys` values inside the
connection. Lifecycle and status use `initiate`, `terminate`, `unload-conn`,
`get-conns`, `get-keys`, and `list-sas`, with IKE/CHILD up/down event
subscriptions. The `get-*` calls intentionally list only objects loaded through
VICI, which preserves the ownership boundary.

### SRv6

Fetch route sources with a bounded HTTP client, validate every prefix, cache
atomically in the daemon state directory, and apply exact routes with netlink
`SEG6Encap`. Route tables and rules are reconciled without broad table flushes.

## Packaging and Privilege

Runtime code does not call a service manager. Packaging installs service files
and administrators enable the service using their platform tooling.

The systemd unit is hardened and starts with the minimum practical privilege.
Initial deployments may run as root; capability reduction to `CAP_NET_ADMIN`
and required socket permissions is validated during integration testing. The
repository also provides `sysusers.d` and `tmpfiles.d` assets where useful.

## Clean Break From V1

V2 has no V1 importer, parser, compatibility mode, directory scanner, or
automatic cleanup path. Operators remove or disable old configuration and
services themselves before enabling a V2 record with the same kernel object
names. Ownership conflicts are reported by the daemon and never adopted.

## Test Strategy

- Unit tests for validation, redaction, unsupported-schema rejection, atomic
  store behavior, API errors, generation conflicts, and reconciler decisions.
- Fake backend tests for lifecycle and failure/retry semantics.
- Linux network-namespace integration tests for GRE, VXLAN, WireGuard,
  AmneziaWG, XFRM, routes, rules, and ownership protection when supported by
  the test kernel; unavailable optional families are reported as skips.
- VICI message construction and framed-protocol lifecycle tests, with live
  strongSwan validation performed on hosts that provide charon and VICI.
- AmneziaWG attribute encoder/decoder fixture tests.
- Static source guard that fails when production packages import `os/exec` or
  contain legacy command wrappers and forbidden system configuration paths.
- `go test ./...`, `go vet ./...`, and cross-builds for supported Linux arches.

## Delivery Phases

1. Foundation: domain model, validation, atomic store, API, daemon and client.
2. First vertical slice: GRE and VXLAN with lifecycle/status through the TUI.
3. WireGuard and static-key XFRM.
4. IKEv2 XFRM through VICI, including PSK and RPK.
5. SRv6 and AmneziaWG.
6. Packaging assets, hardening, and documentation.
7. Remove all V1 execution/config-generation code and pass the completion
   audit below.

## V2 Completion Audit

V2 is complete only when all of the following are proven from the current
worktree and test output:

- Both binaries build and the daemon restores enabled tunnels after restart.
- Every supported kind can be created, observed, disabled, re-enabled, updated,
  and deleted through the daemon API.
- TUI management lists only records from the V2 store and works without root.
- OpenVPN and V1 external-file management code are absent.
- Production code has no external command execution path.
- No production code touches forbidden system configuration paths.
- strongSwan integration uses VICI only, including RPK binary public keys.
- Object ownership prevents deletion of unrelated links/routes/XFRM objects.
- Store writes are crash-safe and secrets are not exposed by list/status APIs.
- Unit, vet, source-guard, integration tests, and Linux cross-builds pass.
