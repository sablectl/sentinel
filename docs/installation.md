# Installation

## Requirements

- Linux and Node.js 24 LTS or later.
- npm compatible with the Node.js installation.
- Read access to the configured source files. Root privileges are not required by default.

## Build from a checkout

```sh
git clone https://github.com/sablectl/sentinel.git
cd sentinel
npm ci
npm run build
node dist/bin/sentinel.js doctor
```

`npm run build` compiles the Node.js service and browser application. No production dependency installation is required.

## Configure a source

Create `~/.config/sentinel/config.json` with the source path and type. For example:

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

For systemd, create an export readable by the current user, for example with `journalctl --output=export --no-pager`, and configure it as a `journal` source. The reader does not execute a shell command or start a privileged collector.

## Start and sign in

Run the foreground service:

```sh
node dist/bin/sentinel.js start
```

The CLI prints a local dashboard URL and, when a local token file is used, its file path. Open the URL and paste the token from that owner-only file into the login form. The token is not included in the URL or served assets. Press `Ctrl+C` to stop the service cleanly.

The default listener is `127.0.0.1:7878`. Remote binding requires `server.allowRemote: true` and a configured token. Prefer a specific interface address; wildcard listeners accept IP Host/Origin pairs only. Do not expose plain HTTP to untrusted networks.

## One-shot import and health

```sh
node dist/bin/sentinel.js ingest --source-type ndjson --path ./events.ndjson
node dist/bin/sentinel.js sources
node dist/bin/sentinel.js status
```

## State and removal

Defaults follow XDG locations:

- Configuration: `~/.config/sentinel/config.json`.
- Database and token: `~/.local/state/sentinel/`.

To remove Sentinel's local state, stop the service and remove the configured database and its sibling token file. This permanently deletes events, checkpoints, alerts, notes and runtime settings. Do not remove a shared or non-Sentinel directory when using a custom path.
