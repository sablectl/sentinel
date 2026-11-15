# Troubleshooting

## `sentinel doctor` reports an invalid configuration

Check the JSON syntax, setting names, integer bounds and `SENTINEL_*` overrides. Remote binding requires both `server.allowRemote: true` and a token. Use `sentinel help` for CLI option names.

## A source is unreadable

Run `sentinel sources` and check its path and status. The current user must have read access to the file. Sentinel does not elevate privileges. Export systemd journal data with an account that can already read it.

## Records become parser failures

Review the supported subset in [event formats](event-formats.md). Inspect the source and physical line/byte offset recorded for each failure. Binary journal export fields, malformed JSON, yearless timestamps outside expected ranges and unsupported vendor variants may be rejected.

## A source exceeds a configured limit

Increase `ingestion.maxRecordBytes` or `ingestion.maxFileBytes` only when the source is trusted and the available memory budget allows it. Queue capacity and record size share a 256 MiB product limit. Rotate or export very large sources rather than disabling bounds.

## Detection reports a window limit

The configured event or byte cap was exceeded. Sentinel leaves the triggering record uncommitted and surfaces a source-health error rather than silently dropping matches. Narrow the source/time range or tune limits within their maximums.

## Dashboard login fails

Use the token file path printed by `sentinel start`, not the database file. Paste the token into the login form; it is not part of the URL. The token file must be readable by the current user and contain a valid 256-bit token.

## Live updates are reconnecting or degraded

The dashboard retries SSE with bounded backoff and continues to fetch data. `stream.degraded` indicates updates were dropped for a slow or oversized client; refresh the current view to retrieve persisted data.

## Database integrity or permission errors

Stop concurrent Sentinel processes using the same database. Check free disk space and ownership of the configured state directory. New files are created with restrictive permissions; shared existing parent directories are deliberately left unchanged.
