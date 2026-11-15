# Security model

Sentinel handles sensitive security logs and is designed for local investigation. It does not send telemetry, analytics, events or exports to external services.

## Network boundary

The default listener is `127.0.0.1`. Host headers are parsed and allow-listed to prevent DNS-rebinding and Host-header abuse. A supplied Origin must match the configured local origin; state-changing routes and session establishment require an Origin. Remote binding requires explicit `server.allowRemote` and a token. For wildcard remote binds, Host/Origin must use a numeric IP pair. Plain HTTP is not suitable for untrusted networks; use a trusted local network or a separately secured tunnel.

## Authentication and CSRF

With no configured `server.token`, Sentinel creates a random 256-bit token in a `0600` sibling file named `.<database-filename>.token`. The CLI prints the file path, not its contents, and prints a dashboard URL without a token fragment. The login form accepts a manually pasted token and sends it in a same-origin JSON POST to `POST /api/session`.

The server compares bootstrap tokens in constant time and exchanges a valid token for an in-memory expiring session. The session cookie is `HttpOnly; SameSite=Strict; Path=/`; a separate same-site CSRF cookie supplies a double-submit token for writes. Reads, writes and SSE require a session. Logout revokes the session. Restarting the process invalidates all sessions.

## Browser and API

All API and asset responses use a restrictive Content Security Policy, `nosniff`, frame denial, same-origin resource policies, no-referrer and no-store headers. Event text is rendered through DOM text nodes. API filters, sorts, bodies, identifiers, query limits and output types are validated; request values never become SQL fragments.

Request targets and bodies are bounded. API rates, detection windows, file input, source queues, SSE client counts, event frames and export sizes are capped. SSE drops are reported as `stream.degraded`; views remain fetch-driven when the stream is unavailable.

## Files and data

New state directories use `0700`; new database and token files use `0600`. Existing shared parent directories are not chmodded. SQLite uses WAL and explicit migrations. The database stores canonical events, sanitised messages, metadata, source checkpoints, parse failures, rule settings, alerts, evidence, notes and runtime settings such as the retention override.

Security logs may contain usernames, IP addresses, hostnames, command names and other identifiers. Exports redact host, username, IP, process, message and metadata by default; set `export.redactSensitiveFields` to `false` only when the recipient and destination are trusted. CSV cells beginning `=`, `+`, `-`, `@`, tab or carriage return are prefixed to prevent spreadsheet formula execution.

## Deletion and limitations

Stop Sentinel, then delete the configured SQLite database and its sibling token file to remove local events, checkpoints, alerts, notes and runtime settings. Follow the retention policy to prune older events automatically. Backups and exported files are separate and must be removed separately.

Local binding and authentication reduce exposure but do not protect data from another process running as the same user or from a compromised host. Rule matches can be false positives and parser support is limited to the documented subsets.
