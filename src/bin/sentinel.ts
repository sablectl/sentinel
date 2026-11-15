#!/usr/bin/env node
import { pathToFileURL } from "node:url";
import { resolve } from "node:path";
import {
  ConfigError,
  defaultConfigPath,
  loadConfig,
} from "../config/config.js";
import { parseArguments, UsageError } from "../cli/args.js";
import { runAlerts } from "../cli/alerts.js";
import { runDoctor } from "../cli/doctor.js";
import { runIngest } from "../cli/ingest.js";
import { runExport } from "../cli/export.js";
import { runRules } from "../cli/rules.js";
import { runStart } from "../cli/start.js";
import { runStatus } from "../cli/status.js";
import { listSources } from "../cli/sources.js";
import { AlertNotFoundError } from "../alerts/store.js";
import { RuleConfigurationError } from "../detect/registry.js";
import { FileTooLargeError } from "../ingest/reader-file.js";
import { sanitiseMessage } from "../parse/sanitise.js";
import { VERSION } from "../version.js";

const USAGE = `sentinel ${VERSION} — local-first Linux security event analysis

Usage:
  sentinel doctor [options]    Validate configuration and database integrity
  sentinel ingest [options]     Import a log file with checkpoints
  sentinel sources [options]    List configured ingestion sources
  sentinel rules [action]       List or configure detection rules
  sentinel alerts [action]      List and update persistent alerts
  sentinel start [options]      Run ingestion, detection and the local dashboard
  sentinel status [options]     Report local database and source health
  sentinel export [options]     Write a metadata-bearing JSON or CSV export
  sentinel version             Print the version
  sentinel help                Print this message

Ingest:
  --source-type <type>          authlog, journal, ndjson or syslog
  --path <file>                 Source file to read
  --name <name>                 Stable source name (defaults to type and filename)

Rules and alerts:
  sentinel rules enable <id> | disable <id> | tune <id> --thresholds <json>
  sentinel alerts acknowledge <id> | resolve <id> | reopen <id>
  sentinel alerts note <id> --note <text>
  Use --state and --severity to filter alerts.

Export:
  --format <json|csv>           Export format (required)
  --output <path>               Destination file (default: current directory)
  --range <15m|1h|6h|24h|7d>    Time range to export

Options:
  --config <path>              Configuration file (default: ${defaultConfigPath()})
  --host <address>             Address to bind (default: 127.0.0.1)
  --port <number>              Port to bind (default: 7878)
  --db <path>                  SQLite database path
  --retention-days <number>    Event retention period (default: 30)
  --max-record-bytes <number>  Maximum bytes in one record (default: 65536)
  --max-file-bytes <number>    Maximum source file size (default: 268435456)
  --queue-high-water-mark <n>  Maximum queued records (default: 512)
  --max-window-events <number> Maximum events in one detection window (default: 2000)
  --max-window-bytes <number>  Maximum bytes in one detection window (default: 67108864)
  --allow-remote               Explicitly permit a non-loopback bind; a token is required

Environment:
  SENTINEL_HOST, SENTINEL_PORT, SENTINEL_ALLOW_REMOTE, SENTINEL_TOKEN,
  SENTINEL_DB, SENTINEL_RETENTION_DAYS, SENTINEL_MAX_RECORD_BYTES,
  SENTINEL_MAX_FILE_BYTES, SENTINEL_QUEUE_HIGH_WATER_MARK,
  SENTINEL_MAX_WINDOW_EVENTS, SENTINEL_MAX_WINDOW_BYTES, SENTINEL_SOURCES

The dashboard defaults to 127.0.0.1. Do not expose it to an untrusted network.
`;

export async function main(
  argv: readonly string[] = process.argv.slice(2),
): Promise<void> {
  try {
    const invocation = parseArguments(argv);
    if (invocation.command === "help") {
      process.stdout.write(USAGE);
      return;
    }
    if (invocation.command === "version") {
      process.stdout.write(`sentinel ${VERSION}\n`);
      return;
    }

    const config = await loadConfig(
      invocation.configPath,
      invocation.overrides,
    );
    if (invocation.command === "rules") {
      process.stdout.write(runRules(config, invocation));
      return;
    }
    if (invocation.command === "alerts") {
      process.stdout.write(runAlerts(config, invocation));
      return;
    }
    if (invocation.command === "status") {
      process.stdout.write(runStatus(config));
      return;
    }
    if (invocation.command === "export") {
      const result = runExport(config, {
        format: invocation.exportFormat,
        outputPath: invocation.outputPath,
        filters: invocation.exportFilters,
      });
      process.stdout.write(
        `Exported ${result.eventCount} of ${result.filteredTotal} matching events to ${result.path}.\n`,
      );
      return;
    }
    if (invocation.command === "start") {
      await runStart(config);
      return;
    }
    if (invocation.command === "ingest") {
      const result = await runIngest(
        config,
        invocation.sourceType,
        invocation.sourcePath,
        invocation.sourceName,
      );
      process.stdout.write(
        `Read ${result.records} records; inserted ${result.eventsInserted} events; ` +
          `deduplicated ${result.duplicates}; parser failures ${result.parseFailures}; ` +
          `detection matches ${result.detectionMatches}; ` +
          `detection time ${result.detectionDurationMs.toFixed(1)} ms; ` +
          `ignored empty records ${result.ignored}.\n`,
      );
      return;
    }
    if (invocation.command === "sources") {
      const sources = listSources(config);
      if (sources.length === 0) {
        process.stdout.write("No sources have been ingested.\n");
        return;
      }
      for (const source of sources) {
        const lastSeen =
          source.lastSeen === null
            ? "never"
            : new Date(source.lastSeen).toISOString();
        const lastError =
          source.lastError === null
            ? ""
            : ` last-error=${JSON.stringify(source.lastError)}`;
        process.stdout.write(
          `${JSON.stringify(source.name)} ${source.sourceType} ${source.status} ` +
            `path=${JSON.stringify(source.path)} last-seen=${lastSeen} ` +
            `errors=${source.errorCount}${lastError}\n`,
        );
      }
      return;
    }
    const result = runDoctor(config);
    process.stdout.write(
      `Configuration valid. Database integrity: ${result.integrity}. ` +
        `Schema: ${result.schemaVersion}. Events: ${result.counts.events}.\n`,
    );
  } catch (error: unknown) {
    const message = safeErrorMessage(error);
    process.stderr.write(`sentinel: ${message}\n`);
    process.exitCode = 1;
  }
}

function safeErrorMessage(error: unknown): string {
  if (
    error instanceof ConfigError ||
    error instanceof UsageError ||
    error instanceof AlertNotFoundError ||
    error instanceof RuleConfigurationError ||
    error instanceof FileTooLargeError ||
    error instanceof RangeError ||
    error instanceof TypeError
  ) {
    return sanitiseMessage(error.message);
  }
  if (error instanceof Error && error.name === "AbortError") {
    return "operation interrupted";
  }
  return "operation failed; run sentinel doctor for configuration and storage diagnostics";
}

if (
  process.argv[1] !== undefined &&
  pathToFileURL(resolve(process.argv[1])).href === import.meta.url
) {
  void main();
}
