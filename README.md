# TH

TH is a Linux tunnel management daemon with a non-root TUI and
CLI. The daemon stores desired state in its own private directory and
reconciles links, addresses, routes, rules, and XFRM objects through netlink.
It does not generate distribution-specific network configuration files or run
network management commands.

Supported tunnel kinds:

- GRE over IPv4 or IPv6
- Unicast VXLAN
- WireGuard
- AmneziaWG
- Static-key XFRM
- IKEv2 XFRM controlled through strongSwan VICI
- SRv6 route sets

The current architecture is a clean break. It has no old-format importer,
compatibility parser, or automatic cleanup workflow. Remove or disable old
tunnel definitions before enabling TH records that use the same names.

## Architecture

```text
th (TUI and CLI, non-root)
  |
  | HTTP/JSON over /run/th/control.sock
  v
thd (root)
  +-- /var/lib/th/tunnels/*.json
  +-- rtnetlink and XFRM netlink
  +-- WireGuard and AmneziaWG generic netlink
  `-- strongSwan VICI
```

The daemon is the only writer of TH state. Kernel objects created by the
daemon are tagged or placed in reserved ownership namespaces, and deletion is
refused when ownership cannot be proven.

WireGuard requires the in-kernel `wireguard` generic-netlink family. TH checks
that kernel API directly and controls it through its embedded Go libraries;
the `wireguard-tools` package, `wg`, and `wg-quick` are not runtime
dependencies.

## Install

The recommended installer detects Debian-family and RPM-family systems,
downloads the matching native package from the latest release, verifies it
against `checksums.txt`, and installs it with the host package manager:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/TunnelHelper/TH/main/run.sh) --install
```

On its first installation, the package creates the `th` operator group and
runtime directories, then enables and starts `thd.service`. Upgrades preserve
an administrator's disabled or stopped state. The one-command installer also
adds its invoking non-root user to the operator group. Start a new login session
afterward, then run the client without `sudo`:

```bash
th
```

The daemon stays available even when `/etc/th/thd.json` is absent or there are
no tunnel records. In that case it uses built-in defaults and keeps listening
for the client on `/run/th/control.sock`.

Native packages can also be downloaded from the release page and installed
directly:

```bash
sudo apt-get install ./th_VERSION_ARCH.deb
# or
sudo dnf install ./th-VERSION-1.ARCH.rpm
sudo usermod -aG th "$USER"
```

Configuration in `/etc/th` and state in `/var/lib/th` are preserved when the
package is removed.

## Build From Source

Go 1.25.12 or newer is required. The minimum patch level is intentional because
older toolchains contain known standard-library vulnerabilities reachable from
the client and daemon binaries.

```bash
make build
sudo make install
sudo systemd-sysusers /usr/lib/sysusers.d/th.conf
sudo systemd-tmpfiles --create /usr/lib/tmpfiles.d/th.conf
sudo systemctl daemon-reload
sudo systemctl enable --now thd
sudo usermod -aG th "$USER"
```

GoReleaser is also required to build local snapshot packages:

```bash
make package
```

## Client Commands

With no command, `th` opens the TUI. The same API is scriptable:

```bash
th health
th doctor
th version
th watch
th validate tunnels.json
th plan tunnels.json
th apply tunnels.json --wait
th export --redacted --output tunnels.json
sudo th backup th-backup.age
sudo th restore th-backup.age --check
sudo th restore th-backup.age --wait
th list
th get RECORD_ID
th create tunnel.json
th update tunnel.json
th enable RECORD_ID
th disable RECORD_ID
th reconcile RECORD_ID
th delete RECORD_ID
```

Mutations normally return after desired state is safely stored and reconcile in
the background. Add `--wait` to create, update, enable, or disable when a script
needs the resulting observed status before continuing.

Declarative commands accept a single tunnel, an array, a versioned bundle, or a
directory of `.json` files. `plan` and `apply` preserve records omitted from the
input unless `--prune` is explicit. Batch validation checks the complete final
ownership set before writing; an apply failure rolls desired state back and
queues runtime repair.

Resource bounds are enforced at validation time: at most 1024 tunnels, 256
interface addresses per tunnel, 1024 WireGuard/AmneziaWG peers, 4096
AllowedIPs per peer (16384 per tunnel), and 64 SRv6 sources.

Each SRv6 source binds exactly one address family (IPv4 or IPv6) to one full
HTTP(S) prefix-file URL, route SID, MTU, and numeric priority. Priorities use
Linux policy-rule ordering throughout: lower numbers win, values must be unique
within a tunnel, and the maximum is 32765 so TH's SRv6 lookup always precedes
the kernel `main` rule at 32766. The daemon assigns each SRv6 tunnel a stable
table-rule priority; sources are evaluated from lowest to highest and later
duplicates of the same normalized CIDR are skipped. Overlapping CIDRs with
different prefix lengths remain valid and use normal longest-prefix matching.

`export --redacted` is safe for review and declarative reuse. The root-only
backup command instead includes every stored private key and PSK, verifies an
internal SHA-256, and encrypts the archive with the standard age scrypt format.
The destination must not already exist. Supply a private `--passphrase-file`,
set `TH_BACKUP_PASSPHRASE`, or enter the passphrase on a TTY.

`th doctor` distinguishes unavailable optional backends from capabilities
required by enabled records. `th health` reports daemon, API, schema, backend,
and configured-tunnel readiness separately.

The TUI live-status view and `th watch` consume an NDJSON event stream over the
same Unix socket. Dashboard refreshes only reload the daemon's current status;
they never observe or reconcile network state. WireGuard and AmneziaWG status
includes per-peer endpoints, handshake times, AllowedIPs, protocol transfer
counters, and separate Linux link counters without exposing key material.
Explicit observation is a read-only kernel check and does not reapply tunnel
configuration. Every TH-owned tunnel interface receives a stable IPv6
link-local address.

The TUI management view is a persistent workspace rather than a sequence of
prompts. Tunnel, WireGuard peer, and SRv6 source editors keep changes in a local
draft, show breadcrumbs and a redacted field-level diff, and use the same
keyboard-selectable Save/Discard confirmation component. Nothing is sent to the
daemon until the tunnel-level Save action is confirmed. All interactive controls
are Bubble Tea components rendered inline with a compact height limit; the client
does not switch to an alternate full-screen buffer.

Use `-` instead of a filename for JSON on stdin. Updates require the current
`id` and `generation`, so a stale client cannot overwrite a newer record.

## Filesystem Layout

- `/etc/th/thd.json`: optional daemon settings
- `/var/lib/th/tunnels/<id>.json`: root-only desired state and keys
- `/var/lib/th/cache/srv6/`: atomically updated SRv6 source cache
- `/run/th/control.sock`: group-authorized local API

Normal list and status responses redact private keys, preshared keys, and
static XFRM key material. Generated secrets are displayed once by the TUI and
remain available only in the root-owned state record afterward.

## Prerequisites

The daemon never installs dependencies or loads modules. The host must provide
the kernel features required by the selected tunnel kind. In particular,
WireGuard and AmneziaWG need their generic-netlink families, XFRM needs XFRM
interface and ESP algorithm support, and SRv6 needs IPv6 SEG6 lightweight
tunnel support.

IKEv2 requires a running strongSwan `charon` with the VICI plugin enabled. The
daemon connects directly to `/run/charon.vici` by default and loads connection
and credential objects through VICI; it does not use credential files.

See [Operations](docs/OPERATIONS.md), [Local API](docs/API.md), and the
[roadmap](docs/ROADMAP.md) for detailed requirements and invariants.

## Development

```bash
make test
make test-integration
make vet
make build-linux
```

Integration tests use isolated Linux network namespaces and netlink only. They
require the relevant capabilities and skip kernel families that are genuinely
unavailable.

## License

MIT
