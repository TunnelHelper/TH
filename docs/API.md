# Local API

The client and daemon use HTTP/1.1 with JSON over
`/run/th/control.sock`. This is a local administrative API protected
by Unix directory and socket permissions. Responses include
`X-TH-API: v1`.

## Endpoints

- `GET /v1/health`
- `GET /v1/events?after=SEQUENCE`
- `GET /v1/tunnels`
- `POST /v1/tunnels`
- `GET /v1/tunnels/{id}`
- `PUT /v1/tunnels/{id}`
- `DELETE /v1/tunnels/{id}`
- `POST /v1/tunnels/{id}/enable`
- `POST /v1/tunnels/{id}/disable`
- `POST /v1/tunnels/{id}/observe`
- `POST /v1/tunnels/{id}/reconcile`
- `POST /v1/observe`
- `POST /v1/reconcile`
- `POST /v1/plan`
- `POST /v1/apply?wait=true`
- `POST /v1/admin/backup`
- `POST /v1/admin/restore?check=true&wait=false`
- `GET /v1/settings`
- `PUT /v1/settings`

The health response includes `alive`, configured-tunnel `ready`, daemon build
information, the state schema version, backend capability status, and tunnel
counts. A backend has `required: true` only when at least one enabled record
currently uses it. Missing optional capabilities therefore do not make the
daemon itself unready.

The `babel` health object reports the effective router ID plus live
`neighbours` and selected `routes`. Neighbour entries expose RTT, jitter,
minimum RTT, sample age/count, robust-filter outlier count, confidence and
freshness. Route entries expose propagated path quality, dimensionless score,
and desired versus installed Linux nexthop weights. These arrays are omitted
when empty.

The settings endpoints expose only the operator-owned `babel` and `mptcp`
sections; filesystem and socket layout remain daemon-owned. `PUT` validates,
applies and persists the update. The server decodes over the current settings,
so fields omitted by an older client are preserved instead of being reset to
zero. Unknown JSON fields are still rejected.

The event endpoint is a long-lived `application/x-ndjson` response. It begins
with a `connected` item, replays retained events newer than `after`, then emits
live status/deletion events and heartbeats. Sequence gaps are reported on the
connected item so clients can reload a full tunnel snapshot. Status events
contain operational state and tunnel identity, never desired specs or key
material.

Create accepts a tunnel object. Server-owned metadata such as schema version,
UUID, generation, and timestamps is prepared by the daemon. For example:

```json
{
  "name": "site-a-gre",
  "kind": "gre",
  "interface": "gre-site-a",
  "enabled": true,
  "spec": {
    "gre": {
      "local": "192.0.2.10",
      "remote": "198.51.100.20",
      "addresses": ["10.10.0.1/30"],
      "mtu": 1450,
      "ttl": 255
    }
  }
}
```

Create, update, enable, and disable persist desired state and normally return a
`pending` view while reconciliation continues in the daemon. Add `?wait=true`
to wait for that generation's reconciliation. The CLI exposes the same behavior
as `--wait`. Delete remains synchronous because its state record cannot be
discarded until owned runtime objects have been removed safely.

Observe is read-only: it refreshes status from the kernel without reapplying
desired configuration. The single-tunnel and all-tunnel observe endpoints back
explicit observation clients. Observation has its own timestamp and does not
advance the observed generation or erase the previous reconciliation result.
The TUI dashboard's `r` action only reloads current daemon status. Reconcile may
repair or change runtime state and is kept as a separate operation.

Plan and apply accept this envelope:

```json
{
  "bundle": {
    "bundle_version": 1,
    "tunnels": [
      {
        "name": "site-a-gre",
        "kind": "gre",
        "interface": "gre-site-a",
        "enabled": true,
        "spec": {
          "gre": {
            "local": "192.0.2.10",
            "remote": "198.51.100.20"
          }
        }
      }
    ]
  },
  "prune": false
}
```

The CLI also accepts a bare tunnel, an array, or a directory of JSON files and
normalizes them to this bundle. Existing records match by ID first and then by
name. IDs are optional for new records but are required to express a rename.
The daemon validates the final set for duplicate names, interfaces, XFRM IDs,
route tables, policy priorities, and managed route claims before changing
state. Omitted records are deleted only with `prune: true`. Failed applies
restore already changed desired records in reverse order and queue repair.
The store and bundles are limited to 1024 tunnels. Per tunnel, interface
address lists are limited to 256 entries, WireGuard/AmneziaWG to 1024 peers
and 16384 total AllowedIPs (4096 per peer), and SRv6 to 64 sources.

Admin backup and restore require UID 0 proven with `SO_PEERCRED`; socket group
membership alone is insufficient. Backup returns an age/scrypt encrypted
archive containing raw daemon-owned records, including private keys and PSKs.
The encrypted payload carries its format, product and schema versions, creation
time, and an internal SHA-256 over the full content. Restore authenticates and
decrypts age, verifies the digest, validates every record and the complete
ownership set, then calculates a full replacement plan. `check=true` returns
that plan without mutation. An applying restore preserves archived IDs and
rolls deleted desired state back if a later create fails.

Update uses this envelope and requires the current generation:

```json
{
  "generation": 4,
  "tunnel": {
    "schema_version": 4,
    "id": "11111111-2222-4333-8444-555555555555",
    "generation": 4,
    "name": "site-a-gre",
    "kind": "gre",
    "interface": "gre-site-a",
    "enabled": true,
    "spec": {
      "gre": {
        "local": "192.0.2.10",
        "remote": "198.51.100.20",
        "addresses": ["10.10.0.1/30"],
        "mtu": 1400,
        "ttl": 255
      }
    }
  }
}
```

Enable and disable accept `{"generation": 4}`. Delete carries the generation
in `If-Match`. A stale generation returns HTTP `409` with code
`generation_conflict`.

## Response Model

Tunnel responses contain:

- `tunnel`: desired configuration with write-only secrets removed.
- `secret_fields`: JSON field paths that were redacted.
- `status`: desired and observed generation, phase, timestamps, conditions,
  interface state, backend-specific details, and per-peer WireGuard or
  AmneziaWG operational counters.

SRv6 specs include a durable `rule_priority`. The daemon allocates it for new
records when omitted; it is immutable with the route table and is always in the
range 1 through 32765. Source `priority` uses the same low-number-first ordering,
must be unique within the tunnel, and has the same range. This keeps the SRv6
table lookup ahead of Linux's `main` rule at priority 32766.

WireGuard `receive_bytes` and `transmit_bytes` are the sum of the same per-peer
generic-netlink transfer counters exposed by `wg`. Linux interface counters are
reported separately as `link_receive_bytes` and `link_transmit_bytes`. TH-owned
interfaces also receive a stable, record-derived IPv6 link-local `/64` address,
reported as `ipv6_link_local` after the observer verifies it in the kernel.

Environmental apply failures do not roll back desired state. The response and
subsequent list/get calls show `phase: error` and a `ReconcileFailed`
condition. The daemon retries on relevant events and its periodic interval.
Updates merge redacted secret fields from the stored record. When changing a
static XFRM algorithm or IKE authentication method, API clients must submit the
complete replacement key material; the daemon does not silently generate a
secret that the redacted response cannot return. The TUI provides an explicit
one-time generation and display flow for these transitions.

Errors use a stable envelope:

```json
{
  "error": {
    "code": "invalid_request",
    "message": "description"
  }
}
```

Known codes are `invalid_request`, `not_found`, `generation_conflict`,
`operation_failed`, and `internal_error`. An operation failure means an owned
runtime object could not be safely removed and is normally retryable after its
backend recovers. Bodies are limited to 4 MiB, unknown JSON fields are rejected,
and each body must contain exactly one JSON value.
