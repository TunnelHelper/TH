# TH

TH is a Linux tunnel manager.

A privileged daemon (`thd`) owns network state. The CLI/TUI (`th`) provides non-root control.

## Features

- GRE and unicast VXLAN
- WireGuard and AmneziaWG
- Static XFRM and strongSwan IKEv2
- SRv6 policies and routes
- Babel routing with weighted multipath
- Optional MPTCP endpoint management
- Declarative validation, planning, apply, and export
- Redacted exports and encrypted backups

## Architecture

```text
th / TUI  ->  Unix socket  ->  thd  ->  Linux kernel / strongSwan
                                  |
                                  +->  /var/lib/th/tunnels
```

- `thd` is the only writer for managed state and kernel objects.
- `th` normally runs without root; backup and restore require an administrator.
- WireGuard interfaces are created through netlink and configured through the WireGuard API.

TH does not import legacy tunnel definitions or remove objects created outside its ownership model.

## Install

Recommended installer:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/TunnelHelper/TH/main/run.sh) --install
```

Start a new login session after installation so the `th` group membership takes effect, then run:

```bash
th
```

Native `.deb` and `.rpm` packages are also available from releases:

```bash
sudo apt-get install ./th_VERSION_ARCH.deb
# or
sudo dnf install ./th-VERSION-1.ARCH.rpm
sudo usermod -aG th "$USER"
```

## Common Commands

```bash
th                         # Open the TUI
th health                  # Show backend health
th doctor                  # Diagnose daemon connectivity
th list                    # List tunnels
th get TUNNEL_ID           # Show one tunnel
th watch                   # Stream status events
```

Create or update one tunnel:

```bash
th create tunnel.json --wait
th update tunnel.json --wait
th enable TUNNEL_ID --wait
th disable TUNNEL_ID --wait
```

Apply desired state:

```bash
th validate desired.json
th plan desired.json
th apply desired.json --wait
```

`--prune` removes managed tunnels missing from the desired-state file. `plan` is read-only.

Export and recovery:

```bash
th export --redacted --output export.json
sudo th backup /root/th-backup.age
sudo th restore /root/th-backup.age --check
```

Run `th help` for the complete command list.

## Desired-State Formats

`validate`, `plan`, and `apply` accept:

- One tunnel object
- An array of tunnel objects
- An envelope: `{"tunnels": [...]}`
- A directory containing JSON files
- `-` for standard input

Generated credentials and keys are returned only by mutating commands. Store their output securely.

## Files

| Path | Purpose |
| --- | --- |
| `/etc/th/thd.json` | Optional daemon configuration |
| `/var/lib/th/tunnels` | Managed tunnel state and secrets |
| `/run/th/control.sock` | Local control socket |

## Requirements

- Linux with the kernel features required by the selected tunnel type
- strongSwan for IKEv2 profiles
- AmneziaWG support for AWG profiles
- Go 1.25.12 or newer when building from source

## Build and Test

```bash
make build
make test
make test-integration
make vet
```

Integration tests create isolated Linux network namespaces and may require root.

## Documentation

- [Operations](docs/OPERATIONS.md)
- [API](docs/API.md)
- [Babel and ECMP](docs/BABEL_ECMP.md)
- [MPTCP management](docs/MPTCP_MANAGEMENT.md)
- [Roadmap](docs/ROADMAP.md)

## License

MIT
