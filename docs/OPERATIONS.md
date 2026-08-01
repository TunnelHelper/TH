# TH Operations

## Daemon Settings

The daemon reads `/etc/th/thd.json`. The file is optional
and unspecified fields retain secure defaults. Unknown fields and multiple JSON
values are rejected. When present, it must be a regular file owned by the daemon
UID and must not be writable by its group or other users.

```json
{
  "state_dir": "/var/lib/th",
  "runtime_dir": "/run/th",
  "socket_path": "/run/th/control.sock",
  "socket_group": "th",
  "vici_socket_path": "/run/charon.vici",
  "reconcile_interval_seconds": 30,
  "request_timeout_seconds": 15
}
```

The socket defaults to mode `0660`. `socket_path` must be directly inside
`runtime_dir`. The daemon resolves `socket_group` at startup, changes the
runtime directory and socket to that group, and fails closed if the group does
not exist. State and runtime directories may not overlap or point at the
filesystem root.

Command-line flags can override paths, the socket GID, VICI location, and the
reconcile interval for tests or specialized deployments. Configuration and
state paths must be absolute.

## Host Prerequisites

All distributions need a Linux kernel and a service account with permission to
perform `CAP_NET_ADMIN` operations in the target network namespace. The
packaged service starts as root with a bounded capability set because it also
protects state and assigns the control socket group.

Debian-family, RPM-family, and Arch-family deployments should use their native
packages to provide kernel modules and strongSwan. Package names vary by
release, so verify capabilities rather than relying on a package name:

- GRE: IPv4 `gre` and IPv6 `ip6gre` link support.
- VXLAN: the `vxlan` link kind.
- WireGuard: the `wireguard` link kind and generic-netlink control family.
- AmneziaWG: the `amneziawg` link kind and generic-netlink control family.
- Static XFRM: XFRM interfaces plus AES-GCM or AES-CBC/HMAC ESP algorithms.
- IKEv2 XFRM: the same XFRM support plus strongSwan `charon` and VICI.
- SRv6: IPv6, SEG6, and SEG6 lightweight tunnel encapsulation.

Missing capabilities are returned as backend health or reconciliation errors.
The daemon does not invoke a package manager or module loader.

Run `th doctor` after installation or an upgrade to verify the control socket,
API and schema compatibility, binary versions, required backends, and enabled
tunnel readiness. Optional backends that are not used are warnings rather than
daemon readiness failures.

## strongSwan VICI

Enable the strongSwan VICI plugin and make its Unix socket reachable by the
daemon. The default is `/run/charon.vici`; change `vici_socket_path` when the
distribution uses another location.

Each managed connection name contains the record UUID. PSKs have a stable
unique credential ID, and RPK private keys are loaded as in-memory VICI
credentials.
Raw public keys are sent as binary DER values in the connection message.
Disabling or deleting a record terminates its SAs and unloads only its named
connection and credentials. An IKEv2 update first unloads the previous VICI
objects while the old credential fingerprint is still durable; if that cleanup
fails, the old generation is retained and the API reports a retryable operation
failure.

## State And Secrets

`/var/lib/th` and its tunnel files are forced to modes `0700` and
`0600`. Writes use a same-directory temporary file, file sync, atomic rename,
and directory sync. On startup, schema 2 and 3 records are validated and
migrated to schema 4 before the daemon begins reconciliation. The migration
assigns every SRv6 tunnel a unique policy-rule priority below the kernel `main`
rule and converts schema 3 source priorities from high-value-first to
low-value-first without changing which source wins a duplicate prefix. Legacy
tunnel names receive the same protocol prefix used by the current TUI; names
already carrying that prefix and SRv6 names are unchanged. All records are
preflighted before any are rewritten. Each migrated record is committed through
a synced same-directory temporary file, atomic rename, and directory sync; no
migration backup files are retained. A record with an unsafe mode, invalid
filename, unknown field, unsupported schema, or more than one JSON value stops
store loading without rewriting any record.

After installing a daemon version that supports the target schema, migration
can be run without starting any network reconciliation:

```bash
sudo thd --migrate
sudo systemctl restart thd
```

Do not edit state records while the daemon is running. Use the API so
validation, generation checks, secret merging, and reconciliation remain
atomic from the operator's perspective.

## Backup And Restore

The recommended online backup is encrypted and does not require stopping the
daemon:

```bash
sudo th backup /secure/path/th-backup.age
sudo th restore /secure/path/th-backup.age --check
sudo th restore /secure/path/th-backup.age --wait
```

The archive contains the complete desired-state store and all live tunnel key
material. It uses age scrypt authenticated encryption plus an internal SHA-256.
Only a UID 0 Unix-socket peer can call the backup/restore API. Backup output is
created with mode `0600` and never replaces an existing path. Passphrases are
read from a mode `0600` regular file, `TH_BACKUP_PASSPHRASE`, or a no-echo TTY
prompt. `--check` performs decryption, integrity, schema, record, and ownership
validation without changing state.

Daemon host settings in `/etc/th/thd.json` are not part of the portable state
archive because restoring runtime/socket paths while the service is running is
unsafe. Preserve that file separately when it differs from package defaults.

The offline filesystem procedure remains available for disaster recovery:

For a consistent offline backup:

1. Stop `thd` using the platform service manager.
2. Archive `/etc/th` and `/var/lib/th` while preserving
   ownership, permissions, and timestamps.
3. Restart the daemon.

Restore onto the same or a compatible TH schema version. Stop the daemon,
restore both directories with root ownership, ensure the state directory is
`0700` and record files are `0600`, then start the daemon. Enabled records are
reconciled from desired state on startup.

Backups contain live private keys and PSKs. Encrypt backup media, restrict
access to administrators, and rotate credentials after suspected disclosure.

## Recovery

- A name conflict is never adopted. Remove or rename the pre-existing kernel
  object, or change the TH record before enabling it.
- A backend error leaves desired state stored and visible with a structured
  condition. Fix the host dependency and request reconcile, or wait for the
  periodic repair loop.
- Delete first tears down owned runtime objects. If teardown cannot be proven
  safe, deletion fails and the state record is retained.
- Corrupt state is not skipped silently. Restore the affected record from a
  backup or move it aside while the daemon is stopped, then investigate before
  recreating it through the API.

TH never scans, imports, edits, or removes configuration from another network
manager. Operators are responsible for removing old definitions and avoiding
two owners for the same interface.
