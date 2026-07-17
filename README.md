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

## Build And Install

Go 1.24 or newer is required.

```bash
make build
sudo make install
```

For a manual systemd installation, create the service group and directories,
then enable the unit using the platform service manager:

```bash
sudo systemd-sysusers /usr/lib/sysusers.d/tunnel-helper.conf
sudo systemd-tmpfiles --create /usr/lib/tmpfiles.d/tunnel-helper.conf
sudo systemctl daemon-reload
sudo systemctl enable --now tunnel-helperd
sudo usermod -aG tunnel-helper "$USER"
```

Start a new login session after changing group membership. The client itself
must not be run with `sudo`:

```bash
tunnel-helper
```

Release archives can also be installed with:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/sudogeeker/tunnel-helper/main/run.sh) --install
```

The installer requires `curl`, `tar`, and `sha256sum`, verifies the release
checksum, places files, and initializes sysusers/tmpfiles when available. It
does not enable or start the service.

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
