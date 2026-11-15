# Architecture

Sentinel is a single-process Node.js application with explicit ingestion, parsing, detection, storage, HTTP and browser boundaries. `sentinel start` opens the local SQLite store, starts configured file readers, evaluates rules after committed event writes and serves the authenticated dashboard.

```text
configured files -> bounded reader -> parser -> SQLite events
                                           |-> parse failures
SQLite event window -> detection rules -> deduplicated alerts + evidence
SQLite -> authenticated HTTP API -> modular TypeScript dashboard
SQLite -> CLI status, rules, alerts and export commands
```

## Ingestion and normalisation

`SourceReader` implementations use a single read-only file descriptor, reject symlinks and special files, and process a bounded snapshot. Checkpoints record the path, device/inode identity, byte offset, physical line count, file size and a short SHA-256 fingerprint. A checkpoint is committed only after the record result has been stored. File identity changes, truncation or changed bytes at the checkpoint trigger a reset.

The queue has a configured high-water mark. Producers wait when it is full. Record and whole-file size caps prevent an untrusted source from creating unbounded buffers. A final unterminated line is left uncommitted and retried after more bytes arrive. Empty lines advance checkpoints without creating events.

Parsers return a canonical `SecurityEvent` or a typed `ParseFailure`. Event IDs are deterministic hashes of source, byte offset and normalised content. Re-imports are idempotent. Parser failures retain source, byte offset, physical line number and a short sanitised sample.

## Store and detection

SQLite uses ordered migrations, WAL, foreign keys, parameterised statements and indexes for time and common pivots. New database files are `0600`; newly created state directories are `0700`. Alert evidence links use `ON DELETE SET NULL`, allowing event retention without deleting investigation state.

Rules are pure functions over bounded, ordered event windows. Thresholds are validated against the built-in registry; requests cannot supply rule code. Each match records the rule version, threshold values, time range and supporting event IDs. Alert upserts deduplicate by rule and entity key and count new evidence rather than repeated re-evaluation of the same event.

Correlation is deterministic grouping by an observed shared attribute. It is explicitly labelled as non-attribution. Event-window event and byte caps fail visibly and leave the ingestion checkpoint unadvanced; high-severity matches are not silently dropped.

## HTTP and dashboard

The server uses Node's `http` module without a routing framework. Admission checks validate method, request-target length, Host and Origin before dispatch. Reads and SSE require an in-memory session cookie; writes additionally require an allowed Origin and double-submit CSRF token. Request bodies, rates, stream clients, event windows and SSE frames are bounded.

The browser is a vanilla TypeScript application compiled separately to `dist/web`. Hash routing selects seven view modules. Views use the same authenticated API as the CLI and remain fetch-driven when SSE disconnects. DOM helpers create elements and text nodes; event-derived values are never assigned with `innerHTML`.

## Reuse

Sentinel follows `sable-monitor` patterns for a dependency-light Node server, SQLite, safe request admission, SSE and a modular vanilla TypeScript client. File hashing uses Node's standard `crypto` API and preserves the deterministic hashing approach used in Sable's integrity tooling. No runtime import points to a sibling repository.
