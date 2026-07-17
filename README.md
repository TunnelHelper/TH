# tunnel-helper V2

tunnel-helper V2 is a Linux tunnel management daemon with a non-root TUI and
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

V2 is a clean break. It has no old-format importer, compatibility parser, or
automatic cleanup workflow. Remove or disable old tunnel definitions before
enabling V2 records that use the same names.

## Architecture

```text
tunnel-helper (TUI and CLI, non-root)
             |
             | HTTP/JSON over /run/tunnel-helper/control.sock
             v
tunnel-helperd (root)
  +-- /var/lib/tunnel-helper/tunnels/*.json
  +-- rtnetlink and XFRM netlink
  +-- WireGuard and AmneziaWG generic netlink
  `-- strongSwan VICI
```

The daemon is the only writer of V2 state. Kernel objects created by the
daemon are tagged or placed in reserved ownership namespaces, and deletion is
refused when ownership cannot be proven.

## Install

The recommended installer detects Debian-family and RPM-family systems,
downloads the matching native package from the latest release, verifies it
against `checksums.txt`, and installs it with the host package manager:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/sudogeeker/tunnel-helper/main/run.sh) --install
```

On its first installation, the package creates the `tunnel-helper` operator
group and runtime directories, then enables and starts
`tunnel-helperd.service`. Upgrades preserve an administrator's disabled or
stopped state. The one-command installer also adds its invoking non-root user
to the operator group. Start a new login session afterward, then run the client
without `sudo`:

```bash
tunnel-helper
```

The daemon stays available even when
`/etc/tunnel-helper/tunnel-helperd.json` is absent or there are no tunnel
records. In that case it uses built-in defaults and keeps listening for the
client on `/run/tunnel-helper/control.sock`.

Native packages can also be downloaded from the release page and installed
directly:

```bash
sudo apt-get install ./tunnel-helper_VERSION_ARCH.deb
# or
sudo dnf install ./tunnel-helper-VERSION-1.ARCH.rpm
sudo usermod -aG tunnel-helper "$USER"
```

Configuration in `/etc/tunnel-helper` and state in `/var/lib/tunnel-helper`
are preserved when the package is removed.

## Build From Source

Go 1.24 or newer is required.

```bash
make build
sudo make install
sudo systemd-sysusers /usr/lib/sysusers.d/tunnel-helper.conf
sudo systemd-tmpfiles --create /usr/lib/tmpfiles.d/tunnel-helper.conf
sudo systemctl daemon-reload
sudo systemctl enable --now tunnel-helperd
sudo usermod -aG tunnel-helper "$USER"
```

GoReleaser is also required to build local snapshot packages:

```bash
make package
```

## Client Commands

With no command, `tunnel-helper` opens the TUI. The same API is scriptable:

```bash
tunnel-helper health
tunnel-helper list
tunnel-helper get RECORD_ID
tunnel-helper create tunnel.json
tunnel-helper update tunnel.json
tunnel-helper enable RECORD_ID
tunnel-helper disable RECORD_ID
tunnel-helper reconcile RECORD_ID
tunnel-helper delete RECORD_ID
```

Use `-` instead of a filename for JSON on stdin. Updates require the current
`id` and `generation`, so a stale client cannot overwrite a newer record.

## Filesystem Layout

- `/etc/tunnel-helper/tunnel-helperd.json`: optional daemon settings
- `/var/lib/tunnel-helper/tunnels/<id>.json`: root-only desired state and keys
- `/var/lib/tunnel-helper/cache/srv6/`: atomically updated SRv6 source cache
- `/run/tunnel-helper/control.sock`: group-authorized local API

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
[V2 roadmap](docs/ROADMAP.md) for detailed requirements and invariants.

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
