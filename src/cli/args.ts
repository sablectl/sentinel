import type { AlertState, Severity, SourceType } from "../types.js";

export type Command =
  | "doctor"
  | "ingest"
  | "sources"
  | "rules"
  | "alerts"
  | "start"
  | "status"
  | "export"
  | "version"
  | "help";

export interface Invocation {
  readonly command: Command;
  readonly configPath: string | undefined;
  readonly overrides: Record<string, unknown>;
  readonly sourceName: string | undefined;
  readonly sourcePath: string | undefined;
  readonly sourceType: SourceType | undefined;
  readonly action: string | undefined;
  readonly identifier: string | undefined;
  readonly note: string | undefined;
  readonly thresholds: unknown;
  readonly alertState: AlertState | undefined;
  readonly alertSeverity: Severity | undefined;
  readonly limit: number | undefined;
  readonly exportFormat: "json" | "csv" | undefined;
  readonly outputPath: string | undefined;
  readonly exportFilters: Readonly<Record<string, string>>;
}

export class UsageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UsageError";
  }
}

export function parseArguments(argv: readonly string[]): Invocation {
  let command: Command = "help";
  let index = 0;
  const first = argv[0];
  if (
    first === "doctor" ||
    first === "ingest" ||
    first === "sources" ||
    first === "rules" ||
    first === "alerts" ||
    first === "start" ||
    first === "status" ||
    first === "export" ||
    first === "version" ||
    first === "help"
  ) {
    command = first;
    index = 1;
  } else if (first !== undefined && !first.startsWith("-")) {
    throw new UsageError(`unknown command: ${first}`);
  }

  let configPath: string | undefined;
  let sourceName: string | undefined;
  let sourcePath: string | undefined;
  let sourceType: SourceType | undefined;
  let action: string | undefined;
  let identifier: string | undefined;
  let note: string | undefined;
  let thresholds: unknown;
  let alertState: AlertState | undefined;
  let alertSeverity: Severity | undefined;
  let limit: number | undefined;
  let exportFormat: "json" | "csv" | undefined;
  let outputPath: string | undefined;
  const exportFilters: Record<string, string> = {};
  let showHelp = false;
  const server: Record<string, unknown> = {};
  const storage: Record<string, unknown> = {};
  const ingestion: Record<string, unknown> = {};
  const detection: Record<string, unknown> = {};

  if (command === "rules" || command === "alerts") {
    const subcommand = argv[index];
    if (subcommand !== undefined && !subcommand.startsWith("-")) {
      action = subcommand;
      index += 1;
      if (subcommand !== "list") {
        const target = argv[index];
        if (target !== undefined && !target.startsWith("-")) {
          identifier = target;
          index += 1;
        }
      }
    }
  }

  const value = (flag: string): string => {
    const next = argv[index + 1];
    if (next === undefined || next.startsWith("--")) {
      throw new UsageError(`${flag} requires a value`);
    }
    index += 1;
    return next;
  };

  for (; index < argv.length; index += 1) {
    const argument = argv[index];
    switch (argument) {
      case "--help":
      case "-h":
        showHelp = true;
        break;
      case "--config":
        configPath = value("--config");
        break;
      case "--format":
        exportFormat = parseExportFormat(value("--format"));
        break;
      case "--output":
        outputPath = value("--output");
        break;
      case "--name":
        sourceName = value("--name");
        break;
      case "--note":
        note = value("--note");
        break;
      case "--thresholds":
        thresholds = parseThresholds(value("--thresholds"));
        break;
      case "--state":
        alertState = parseAlertState(value("--state"));
        exportFilters["state"] = alertState;
        break;
      case "--severity":
        alertSeverity = parseSeverity(value("--severity"));
        exportFilters["severity"] = alertSeverity;
        break;
      case "--limit":
        limit = parseNumberFlag("--limit", value("--limit"));
        exportFilters["limit"] = String(limit);
        break;
      case "--page":
        exportFilters["page"] = value("--page");
        break;
      case "--range":
      case "--from":
      case "--to":
      case "--source":
      case "--username":
      case "--search":
      case "--ip":
      case "--category":
      case "--outcome":
      case "--sort":
      case "--direction":
        exportFilters[argument.slice(2)] = value(argument);
        break;
      case "--path":
        sourcePath = value("--path");
        break;
      case "--source-type":
      case "--type":
        sourceType = parseSourceType(value(argument));
        break;
      case "--host":
        server["host"] = value("--host");
        break;
      case "--port":
        server["port"] = parseNumberFlag("--port", value("--port"));
        break;
      case "--db":
        storage["path"] = value("--db");
        break;
      case "--retention-days":
        storage["retentionDays"] = parseNumberFlag(
          "--retention-days",
          value("--retention-days"),
        );
        break;
      case "--max-record-bytes":
        ingestion["maxRecordBytes"] = parseNumberFlag(
          "--max-record-bytes",
          value("--max-record-bytes"),
        );
        break;
      case "--max-file-bytes":
        ingestion["maxFileBytes"] = parseNumberFlag(
          "--max-file-bytes",
          value("--max-file-bytes"),
        );
        break;
      case "--queue-high-water-mark":
        ingestion["queueHighWaterMark"] = parseNumberFlag(
          "--queue-high-water-mark",
          value("--queue-high-water-mark"),
        );
        break;
      case "--max-window-events":
        detection["maxWindowEvents"] = parseNumberFlag(
          "--max-window-events",
          value("--max-window-events"),
        );
        break;
      case "--max-window-bytes":
        detection["maxWindowBytes"] = parseNumberFlag(
          "--max-window-bytes",
          value("--max-window-bytes"),
        );
        break;
      case "--max-stream-events-per-second":
        server["maxStreamEventsPerSecond"] = parseNumberFlag(
          "--max-stream-events-per-second",
          value("--max-stream-events-per-second"),
        );
        break;
      case "--allow-remote":
        server["allowRemote"] = true;
        break;
      default:
        throw new UsageError(`unknown option: ${String(argument)}`);
    }
  }

  return {
    command: showHelp ? "help" : command,
    configPath,
    overrides: { server, storage, ingestion, detection },
    sourceName,
    sourcePath,
    sourceType,
    action,
    identifier,
    note,
    thresholds,
    alertState,
    alertSeverity,
    limit,
    exportFormat,
    outputPath,
    exportFilters,
  };
}

function parseSourceType(value: string): SourceType {
  if (
    value === "authlog" ||
    value === "journal" ||
    value === "ndjson" ||
    value === "syslog"
  ) {
    return value;
  }
  throw new UsageError(
    "--source-type must be authlog, journal, ndjson or syslog",
  );
}

function parseThresholds(value: string): unknown {
  try {
    const parsed: unknown = JSON.parse(value);
    if (
      typeof parsed !== "object" ||
      parsed === null ||
      Array.isArray(parsed)
    ) {
      throw new UsageError("--thresholds must be a JSON object");
    }
    return parsed;
  } catch (error: unknown) {
    if (error instanceof UsageError) throw error;
    throw new UsageError("--thresholds must contain valid JSON");
  }
}

function parseAlertState(value: string): AlertState {
  if (value === "open" || value === "acknowledged" || value === "resolved") {
    return value;
  }
  throw new UsageError("--state must be open, acknowledged or resolved");
}

function parseSeverity(value: string): Severity {
  if (
    value === "info" ||
    value === "low" ||
    value === "medium" ||
    value === "high" ||
    value === "critical"
  ) {
    return value;
  }
  throw new UsageError(
    "--severity must be info, low, medium, high or critical",
  );
}

function parseExportFormat(value: string): "json" | "csv" {
  if (value === "json" || value === "csv") return value;
  throw new UsageError("--format must be json or csv");
}

function parseNumberFlag(flag: string, value: string): number {
  if (!/^\d+$/.test(value)) {
    throw new UsageError(`${flag} must be a positive integer`);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) {
    throw new UsageError(`${flag} must be a positive integer`);
  }
  return parsed;
}
