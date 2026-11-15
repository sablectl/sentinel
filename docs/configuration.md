# Configuration

Sentinel reads JSON from `~/.config/sentinel/config.json` by default. Relative database and source paths resolve from the current working directory. Configuration is validated at startup and is not reloaded from an HTTP request.

## Example

```json
{
  "server": {
    "host": "127.0.0.1",
    "port": 7878,
    "allowRemote": false,
    "maxHeaderBytes": 16384,
    "maxBodyBytes": 65536,
    "maxStreamClients": 32,
    "maxStreamEventsPerSecond": 100,
    "sessionTtlMs": 28800000,
    "requestsPerMinute": 120
  },
  "storage": {
    "retentionDays": 30
  },
  "ingestion": {
    "maxRecordBytes": 65536,
    "maxFileBytes": 268435456,
    "queueHighWaterMark": 512,
    "sources": [
      {
        "name": "system-auth",
        "sourceType": "authlog",
        "path": "/var/log/auth.log",
        "enabled": true
      }
    ]
  },
  "detection": {
    "maxWindowEvents": 2000,
    "maxWindowBytes": 67108864
  },
  "export": {
    "redactSensitiveFields": true
  }
}
```

In JSON, `~` is not expanded; use an absolute path or a path relative to the process working directory. The default database path itself is resolved from the user's XDG state directory.

## Settings

- `server.host` and `server.port`: listener address and port. The safe default is `127.0.0.1:7878`.
- `server.allowRemote`: explicit opt-in for a non-loopback bind. A token of at least 32 characters is then required. Use a specific interface address where possible.
- `server.token`: optional bootstrap token. If unset, Sentinel creates a random token in a sibling `0600` file named `.<database-filename>.token` (for the default store: `~/.local/state/sentinel/.events.sqlite.token`).
- `server.maxHeaderBytes`, `server.maxBodyBytes`: Node HTTP header limit and JSON body limit.
- `server.maxStreamClients`, `server.maxStreamEventsPerSecond`: SSE client and per-client update caps.
- `server.sessionTtlMs`, `server.requestsPerMinute`: in-memory session lifetime and per-client API rate limit.
- `storage.path`: SQLite file. New files are `0600`; newly created containing directories are `0700`.
- `storage.retentionDays`: fallback event/parse-failure retention, from 1 to 3650 days. The authenticated System view can set a persistent SQLite override and prune expired records immediately; the service repeats pruning hourly.
- `ingestion.maxRecordBytes`, `ingestion.maxFileBytes`, `ingestion.queueHighWaterMark`: input and queue bounds. The configured record size multiplied by queue capacity is capped at 256 MiB.
- `ingestion.sources`: up to 64 sources with unique `name`, `sourceType`, `path` and optional `enabled`.
- `detection.maxWindowEvents`, `detection.maxWindowBytes`: hard bounds for each detection evaluation. A bound hit is surfaced as a source-health error and the record checkpoint is not advanced.
- `export.redactSensitiveFields`: defaults to `true`; redacts host, username, source IP, process, message and metadata in exports.

Rule-specific thresholds are managed through `sentinel rules tune` or the authenticated API and stored in SQLite.

## Environment overlay

Environment variables override JSON values, and explicit CLI options override both:

```text
SENTINEL_HOST
SENTINEL_PORT
SENTINEL_ALLOW_REMOTE
SENTINEL_TOKEN
SENTINEL_DB
SENTINEL_RETENTION_DAYS
SENTINEL_MAX_RECORD_BYTES
SENTINEL_MAX_FILE_BYTES
SENTINEL_QUEUE_HIGH_WATER_MARK
SENTINEL_MAX_WINDOW_EVENTS
SENTINEL_MAX_WINDOW_BYTES
SENTINEL_MAX_STREAM_EVENTS_PER_SECOND
SENTINEL_EXPORT_REDACT_SENSITIVE_FIELDS
SENTINEL_SOURCES
```

`SENTINEL_SOURCES` must be a JSON array with the same shape as `ingestion.sources`. Boolean values must be `true` or `false`. Invalid settings fail closed; Sentinel does not silently enable remote binding.
