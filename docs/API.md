# Local V2 API

The client and daemon use HTTP/1.1 with JSON over
`/run/tunnel-helper/control.sock`. This is a local administrative API protected
by Unix directory and socket permissions. Responses include
`X-Tunnel-Helper-API: v1`.

## Endpoints

- `GET /v1/health`
- `GET /v1/tunnels`
- `POST /v1/tunnels`
- `GET /v1/tunnels/{id}`
- `PUT /v1/tunnels/{id}`
- `DELETE /v1/tunnels/{id}`
- `POST /v1/tunnels/{id}/enable`
- `POST /v1/tunnels/{id}/disable`
- `POST /v1/tunnels/{id}/reconcile`
- `POST /v1/reconcile`

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

Update uses this envelope and requires the current generation:

```json
{
  "generation": 4,
  "tunnel": {
    "schema_version": 2,
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
  interface state, and backend-specific details.

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
