# Supported event formats

Each source is a regular file. Sentinel reads a bounded snapshot and commits complete records only. Input is untrusted; malformed and oversized records are isolated as parser failures with source, byte offset and physical line number.

## Linux authentication log (`authlog`)

Supports common syslog-style prefixes followed by a host and program tag, including OpenSSH `Accepted`, `Failed` and `Invalid user` records, PAM authentication failures, sudo indicators and session-open/session-close messages. Program tags may include a numeric process ID.

The supported prefix is `Mmm dd HH:mm:ss host program[pid]: message`. The year is absent in this format. Sentinel infers a year relative to the source's observed timestamp range where available and marks `timestamp.year` in `inferred`. If the file contains only yearless timestamps, the current UTC time is the anchor. Timestamp fields are stored as UTC epoch milliseconds.

Other valid authentication-log lines with a recognised prefix are retained as generic `other` events. Vendor-specific records without the supported prefix are parse failures; they are not guessed.

## Systemd journal export (`journal`)

Supports text-form `journalctl --output=export` records separated by blank lines. Records require `__REALTIME_TIMESTAMP` in microseconds and a `MESSAGE` field. Common text fields such as `_HOSTNAME`, `_COMM`, `_PID`, `SYSLOG_IDENTIFIER` and `PRIORITY` are mapped when present.

Binary length-prefixed fields are not supported and produce a parse failure. The collector does not run `journalctl` itself and does not require root privileges; export the journal using an account that can already read it.

## Newline-delimited JSON (`ndjson`)

One JSON object is read per line. `timestamp` is required as epoch milliseconds or a timezone-qualified ISO 8601 timestamp; `action` is required as a non-empty string. Optional fields are `host`, `category`, `outcome`, `severity`, `username`, `sourceIp`, `process`, `message` and `metadata`.

Absent values remain `null` where the canonical schema allows it. Defaults are `category: "other"`, `outcome: "unknown"` and `severity: "info"`. `sourceIp` must be a valid IP address. `process` is an object containing a name and optional numeric PID. Metadata values must be scalar strings, numbers or booleans; nested objects and arrays are rejected.

## Syslog (`syslog`)

Supports RFC 3164 records with optional PRI, a yearless timestamp, host and program tag. Year selection and UTC assumptions follow the authentication-log rules above.

Also supports RFC 5424 version 1 records with a strict ISO 8601 timestamp, host, application, process ID, message ID, one structured-data element or `-`, and an optional message. Multiple structured-data elements and vendor-specific deviations outside this subset are not interpreted.

## Sanitisation and failures

ANSI escape sequences and control characters are removed from canonical text fields. When sanitisation changes input, the original record is retained as a JSON-escaped metadata value. Parse-failure samples are sanitised and truncated; they are not used to abort the source reader.
