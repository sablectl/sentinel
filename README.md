# Sentinel

Sentinel is a local-first Linux security event ingestion and investigation tool. It imports log files, normalises supported records, stores them in SQLite, evaluates indicator-level rules and provides an authenticated dashboard bound to loopback by default.

Sentinel does not perform scanning, exploitation, credential collection or remote access. It makes no telemetry or network requests to third-party services.

## Capabilities

- Incremental file imports with SQLite checkpoints, rotation detection, bounded queues and per-record and per-file limits.
- Authentication logs, text systemd journal export records, newline-delimited JSON and a documented RFC 3164/RFC 5424 syslog subset.
- Eight configurable detection rules, persistent deduplicated alerts, evidence links and analyst notes.
- Correlation timelines grouped by shared IP, username, host, category or rule; grouping is not attribution.
- A seven-section dashboard: Overview, Events, Detections, Alerts, Investigations, Sources and System.
- Authenticated JSON and CSV exports with metadata, configurable redaction and spreadsheet formula-injection protection.
- A `sentinel` CLI for importing sources, managing rules and alerts, checking local health and exporting findings.

Rule matches are indicators, not proof of compromise. Parser support is deliberately limited to the formats described in the documentation.

## Requirements

- Linux
- Node.js 24 LTS or later
- npm

The application has no runtime dependencies beyond the Node.js standard library, including `node:sqlite`.

## Quick start

```sh
npm ci
npm run build
node dist/bin/sentinel.js help
```

Create `~/.config/sentinel/config.json` with at least one source:

```json
{
  "ingestion": {
    "sources": [
      {
        "name": "system-auth",
        "sourceType": "authlog",
        "path": "/var/log/auth.log",
        "enabled": true
      }
    ]
  }
}
```

Then run the service in the foreground:

```sh
node dist/bin/sentinel.js start
```

The CLI prints a local dashboard URL and the path of the owner-only token file, but never prints the token. Paste the token from that protected file into the dashboard login form. The token is sent only in the local session-establishment request, is not embedded in HTML or a URL, and the form is cleared after submission.

Use a readable log file or a journal export accessible to the current user. Sentinel does not invoke privileged collectors automatically. To import a file once without configuring a service source:

```sh
node dist/bin/sentinel.js ingest --source-type authlog --path /var/log/auth.log
node dist/bin/sentinel.js status
```

The default database is `~/.local/state/sentinel/events.sqlite`. Newly created database files use mode `0600`; newly created state directories use mode `0700`. See the installation and security-model guides before using non-default paths or remote binding.

## Commands

```text
sentinel doctor
sentinel start
sentinel status
sentinel ingest --source-type <authlog|journal|ndjson|syslog> --path <file>
sentinel sources
sentinel rules [list|enable|disable|tune]
sentinel alerts [list|acknowledge|resolve|reopen|note]
sentinel export --format <json|csv>
sentinel version
sentinel help
```

Use `sentinel help` or a command’s `--help` flag for options. Rule settings and configured sources are local configuration; the dashboard does not invent data or expose arbitrary SQL.

## Documentation

- [Installation](docs/installation.md)
- [Configuration](docs/configuration.md)
- [Supported event formats](docs/event-formats.md)
- [Detection rules](docs/detection-rules.md)
- [Architecture](docs/architecture.md)
- [Security model](docs/security-model.md)
- [Performance procedure](docs/performance.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Development and testing](docs/development.md)
- [Changelog](CHANGELOG.md)
- [Security policy](SECURITY.md)
- [Contribution guide](CONTRIBUTING.md)

## Licence and author

Released under the [MIT licence](LICENSE).

Written by Sable (<https://github.com/sablectl>) — <https://sablectl.dev>.
