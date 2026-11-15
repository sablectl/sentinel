import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { isIP } from "node:net";
import { isAbsolute, join, resolve } from "node:path";
import type { SourceType } from "../types.js";

export interface ServerConfig {
  readonly host: string;
  readonly port: number;
  readonly allowRemote: boolean;
  readonly token: string | null;
  readonly maxHeaderBytes: number;
  readonly maxBodyBytes: number;
  readonly maxStreamClients: number;
  readonly maxStreamEventsPerSecond: number;
  readonly sessionTtlMs: number;
  readonly requestsPerMinute: number;
}

export interface StorageConfig {
  readonly path: string;
  readonly retentionDays: number;
}

export interface IngestionConfig {
  readonly maxRecordBytes: number;
  readonly maxFileBytes: number;
  readonly queueHighWaterMark: number;
  readonly sources: readonly SourceConfig[];
}

export interface SourceConfig {
  readonly name: string;
  readonly sourceType: SourceType;
  readonly path: string;
  readonly enabled: boolean;
}

export interface DetectionConfig {
  readonly maxWindowEvents: number;
  readonly maxWindowBytes: number;
}

export interface ExportConfig {
  readonly redactSensitiveFields: boolean;
}

export interface Config {
  readonly server: ServerConfig;
  readonly storage: StorageConfig;
  readonly ingestion: IngestionConfig;
  readonly detection: DetectionConfig;
  readonly export: ExportConfig;
}

export class ConfigError extends Error {
  readonly problems: readonly string[];

  constructor(problems: readonly string[]) {
    super(`invalid configuration:\n  - ${problems.join("\n  - ")}`);
    this.name = "ConfigError";
    this.problems = problems;
  }
}

export function defaultConfigPath(): string {
  const configured = process.env["XDG_CONFIG_HOME"];
  const base =
    configured !== undefined && isAbsolute(configured)
      ? configured
      : join(homedir(), ".config");
  return join(base, "sentinel", "config.json");
}

export function defaultConfig(): Config {
  const configured = process.env["XDG_STATE_HOME"];
  const stateBase =
    configured !== undefined && isAbsolute(configured)
      ? configured
      : join(homedir(), ".local", "state");
  return {
    server: {
      host: "127.0.0.1",
      port: 7878,
      allowRemote: false,
      token: null,
      maxHeaderBytes: 16_384,
      maxBodyBytes: 65_536,
      maxStreamClients: 32,
      maxStreamEventsPerSecond: 100,
      sessionTtlMs: 28_800_000,
      requestsPerMinute: 120,
    },
    storage: {
      path: join(stateBase, "sentinel", "events.sqlite"),
      retentionDays: 30,
    },
    ingestion: {
      maxRecordBytes: 65_536,
      maxFileBytes: 268_435_456,
      queueHighWaterMark: 512,
      sources: [],
    },
    detection: {
      maxWindowEvents: 2_000,
      maxWindowBytes: 67_108_864,
    },
    export: { redactSensitiveFields: true },
  };
}

export function isLoopbackHost(host: string): boolean {
  const normalized = host.toLowerCase();
  if (
    normalized === "localhost" ||
    normalized === "::1" ||
    normalized === "::ffff:127.0.0.1"
  ) {
    return true;
  }
  return isIP(host) === 4 && host.startsWith("127.");
}

export function parseConfig(input: unknown): Config {
  const problems: string[] = [];
  if (!isRecord(input)) {
    throw new ConfigError(["configuration must be a JSON object"]);
  }

  checkUnknownKeys(
    input,
    ["server", "storage", "ingestion", "detection", "export"],
    "configuration",
    problems,
  );
  const serverInput = readSection(input, "server", problems);
  const storageInput = readSection(input, "storage", problems);
  const ingestionInput = readSection(input, "ingestion", problems);
  const detectionInput = readSection(input, "detection", problems);
  const exportInput = readSection(input, "export", problems);
  checkUnknownKeys(
    serverInput,
    [
      "host",
      "port",
      "allowRemote",
      "token",
      "maxHeaderBytes",
      "maxBodyBytes",
      "maxStreamClients",
      "maxStreamEventsPerSecond",
      "sessionTtlMs",
      "requestsPerMinute",
    ],
    "server",
    problems,
  );
  checkUnknownKeys(
    storageInput,
    ["path", "retentionDays"],
    "storage",
    problems,
  );
  checkUnknownKeys(
    ingestionInput,
    ["maxRecordBytes", "maxFileBytes", "queueHighWaterMark", "sources"],
    "ingestion",
    problems,
  );
  checkUnknownKeys(
    detectionInput,
    ["maxWindowEvents", "maxWindowBytes"],
    "detection",
    problems,
  );
  checkUnknownKeys(exportInput, ["redactSensitiveFields"], "export", problems);

  const defaults = defaultConfig();
  const host = readString(serverInput, "host", defaults.server.host, problems);
  const port = readInteger(
    serverInput,
    "port",
    defaults.server.port,
    1,
    65_535,
    "server.port",
    problems,
  );
  const allowRemote = readBoolean(
    serverInput,
    "allowRemote",
    defaults.server.allowRemote,
    problems,
  );
  const token = readToken(serverInput, problems);
  const maxHeaderBytes = readInteger(
    serverInput,
    "maxHeaderBytes",
    defaults.server.maxHeaderBytes,
    1_024,
    65_536,
    "server.maxHeaderBytes",
    problems,
  );
  const maxBodyBytes = readInteger(
    serverInput,
    "maxBodyBytes",
    defaults.server.maxBodyBytes,
    1_024,
    1_048_576,
    "server.maxBodyBytes",
    problems,
  );
  const maxStreamClients = readInteger(
    serverInput,
    "maxStreamClients",
    defaults.server.maxStreamClients,
    1,
    256,
    "server.maxStreamClients",
    problems,
  );
  const maxStreamEventsPerSecond = readInteger(
    serverInput,
    "maxStreamEventsPerSecond",
    defaults.server.maxStreamEventsPerSecond,
    1,
    1_000,
    "server.maxStreamEventsPerSecond",
    problems,
  );
  const sessionTtlMs = readInteger(
    serverInput,
    "sessionTtlMs",
    defaults.server.sessionTtlMs,
    60_000,
    604_800_000,
    "server.sessionTtlMs",
    problems,
  );
  const requestsPerMinute = readInteger(
    serverInput,
    "requestsPerMinute",
    defaults.server.requestsPerMinute,
    1,
    10_000,
    "server.requestsPerMinute",
    problems,
  );
  const databasePath = readString(
    storageInput,
    "path",
    defaults.storage.path,
    problems,
  );
  const retentionDays = readInteger(
    storageInput,
    "retentionDays",
    defaults.storage.retentionDays,
    1,
    3650,
    "storage.retentionDays",
    problems,
  );
  const maxRecordBytes = readInteger(
    ingestionInput,
    "maxRecordBytes",
    defaults.ingestion.maxRecordBytes,
    1,
    1_048_576,
    "ingestion.maxRecordBytes",
    problems,
  );
  const maxFileBytes = readInteger(
    ingestionInput,
    "maxFileBytes",
    defaults.ingestion.maxFileBytes,
    1,
    8_589_934_592,
    "ingestion.maxFileBytes",
    problems,
  );
  const queueHighWaterMark = readInteger(
    ingestionInput,
    "queueHighWaterMark",
    defaults.ingestion.queueHighWaterMark,
    1,
    65_536,
    "ingestion.queueHighWaterMark",
    problems,
  );
  const sources = readSources(ingestionInput["sources"], problems);
  const maxWindowEvents = readInteger(
    detectionInput,
    "maxWindowEvents",
    defaults.detection.maxWindowEvents,
    1,
    10_000,
    "detection.maxWindowEvents",
    problems,
  );
  const maxWindowBytes = readInteger(
    detectionInput,
    "maxWindowBytes",
    defaults.detection.maxWindowBytes,
    1,
    268_435_456,
    "detection.maxWindowBytes",
    problems,
  );
  const redactSensitiveFields = readBoolean(
    exportInput,
    "redactSensitiveFields",
    defaults.export.redactSensitiveFields,
    problems,
  );

  if (host.length === 0 || host.length > 253 || /\s/.test(host)) {
    problems.push("server.host must be a non-empty hostname or IP address");
  }
  if (databasePath.length === 0 || databasePath.length > 4096) {
    problems.push(
      "storage.path must be a non-empty path of at most 4096 characters",
    );
  }
  if (maxFileBytes < maxRecordBytes) {
    problems.push(
      "ingestion.maxFileBytes must be at least ingestion.maxRecordBytes",
    );
  }
  if (maxRecordBytes * queueHighWaterMark > 268_435_456) {
    problems.push(
      "ingestion.maxRecordBytes multiplied by ingestion.queueHighWaterMark must not exceed 256 MiB",
    );
  }
  if (!isLoopbackHost(host)) {
    if (!allowRemote) {
      problems.push(
        "binding beyond loopback requires server.allowRemote to be explicitly enabled",
      );
    }
    if (token === null) {
      problems.push("server.token is required when binding beyond loopback");
    }
  }

  if (problems.length > 0) throw new ConfigError(problems);

  return {
    server: {
      host,
      port,
      allowRemote,
      token,
      maxHeaderBytes,
      maxBodyBytes,
      maxStreamClients,
      maxStreamEventsPerSecond,
      sessionTtlMs,
      requestsPerMinute,
    },
    storage: {
      path: databasePath === ":memory:" ? databasePath : resolve(databasePath),
      retentionDays,
    },
    ingestion: { maxRecordBytes, maxFileBytes, queueHighWaterMark, sources },
    detection: { maxWindowEvents, maxWindowBytes },
    export: { redactSensitiveFields },
  };
}

export async function loadConfig(
  configPath?: string,
  overrides: unknown = {},
  environment: NodeJS.ProcessEnv = process.env,
): Promise<Config> {
  const selectedPath = configPath ?? defaultConfigPath();
  const document = await readConfigDocument(
    selectedPath,
    configPath === undefined,
  );
  return parseConfig(
    mergeDocuments(document, environmentDocument(environment), overrides),
  );
}

async function readConfigDocument(
  selectedPath: string,
  allowMissing: boolean,
): Promise<unknown> {
  try {
    const contents = await readFile(selectedPath, "utf8");
    try {
      return JSON.parse(contents) as unknown;
    } catch {
      throw new ConfigError(["configuration file is not valid JSON"]);
    }
  } catch (error: unknown) {
    if (error instanceof ConfigError) {
      throw error;
    }
    if (allowMissing && isMissingFile(error)) return {};
    throw new ConfigError(["configuration file could not be read"]);
  }
}

function environmentDocument(
  environment: NodeJS.ProcessEnv,
): Record<string, unknown> {
  const server: Record<string, unknown> = {};
  const storage: Record<string, unknown> = {};
  const ingestion: Record<string, unknown> = {};
  const detection: Record<string, unknown> = {};
  const host = environment["SENTINEL_HOST"];
  const port = environment["SENTINEL_PORT"];
  const allowRemote = environment["SENTINEL_ALLOW_REMOTE"];
  const token = environment["SENTINEL_TOKEN"];
  const databasePath = environment["SENTINEL_DB"];
  const retentionDays = environment["SENTINEL_RETENTION_DAYS"];
  const maxRecordBytes = environment["SENTINEL_MAX_RECORD_BYTES"];
  const maxFileBytes = environment["SENTINEL_MAX_FILE_BYTES"];
  const queueHighWaterMark = environment["SENTINEL_QUEUE_HIGH_WATER_MARK"];
  const sources = environment["SENTINEL_SOURCES"];
  const maxWindowEvents = environment["SENTINEL_MAX_WINDOW_EVENTS"];
  const maxWindowBytes = environment["SENTINEL_MAX_WINDOW_BYTES"];
  const maxStreamEventsPerSecond =
    environment["SENTINEL_MAX_STREAM_EVENTS_PER_SECOND"];
  const redactSensitiveFields =
    environment["SENTINEL_EXPORT_REDACT_SENSITIVE_FIELDS"];
  const exportSettings: Record<string, unknown> = {};

  if (host !== undefined) server["host"] = host;
  if (port !== undefined) server["port"] = parseEnvironmentInteger(port);
  if (allowRemote !== undefined)
    server["allowRemote"] = parseEnvironmentBoolean(allowRemote);
  if (token !== undefined) server["token"] = token;
  if (databasePath !== undefined) storage["path"] = databasePath;
  if (retentionDays !== undefined) {
    storage["retentionDays"] = parseEnvironmentInteger(retentionDays);
  }
  if (maxRecordBytes !== undefined) {
    ingestion["maxRecordBytes"] = parseEnvironmentInteger(maxRecordBytes);
  }
  if (maxFileBytes !== undefined) {
    ingestion["maxFileBytes"] = parseEnvironmentInteger(maxFileBytes);
  }
  if (queueHighWaterMark !== undefined) {
    ingestion["queueHighWaterMark"] =
      parseEnvironmentInteger(queueHighWaterMark);
  }
  if (sources !== undefined) {
    ingestion["sources"] = parseEnvironmentJson(sources);
  }
  if (maxWindowEvents !== undefined) {
    detection["maxWindowEvents"] = parseEnvironmentInteger(maxWindowEvents);
  }
  if (maxWindowBytes !== undefined) {
    detection["maxWindowBytes"] = parseEnvironmentInteger(maxWindowBytes);
  }
  if (maxStreamEventsPerSecond !== undefined) {
    server["maxStreamEventsPerSecond"] = parseEnvironmentInteger(
      maxStreamEventsPerSecond,
    );
  }
  if (redactSensitiveFields !== undefined) {
    exportSettings["redactSensitiveFields"] = parseEnvironmentBoolean(
      redactSensitiveFields,
    );
  }

  return { server, storage, ingestion, detection, export: exportSettings };
}

function mergeDocuments(...documents: readonly unknown[]): unknown {
  let merged: Record<string, unknown> = {};
  for (const document of documents) {
    if (!isRecord(document)) return document;
    const next: Record<string, unknown> = { ...merged, ...document };
    for (const section of [
      "server",
      "storage",
      "ingestion",
      "detection",
      "export",
    ]) {
      const currentValue = merged[section];
      const nextValue = document[section];
      if (isRecord(currentValue) && isRecord(nextValue)) {
        next[section] = { ...currentValue, ...nextValue };
      }
    }
    merged = next;
  }
  return merged;
}

function readSection(
  input: Record<string, unknown>,
  key: string,
  problems: string[],
): Record<string, unknown> {
  const value = input[key];
  if (value === undefined) return {};
  if (!isRecord(value)) {
    problems.push(`${key} must be an object`);
    return {};
  }
  return value;
}

function readString(
  input: Record<string, unknown>,
  key: string,
  fallback: string,
  problems: string[],
): string {
  const value = input[key];
  if (value === undefined) return fallback;
  if (typeof value !== "string") {
    problems.push(`${key} must be a string`);
    return fallback;
  }
  return value;
}

function readInteger(
  input: Record<string, unknown>,
  key: string,
  fallback: number,
  minimum: number,
  maximum: number,
  label: string,
  problems: string[],
): number {
  const value = input[key];
  if (value === undefined) return fallback;
  if (typeof value !== "number" || !Number.isInteger(value)) {
    problems.push(`${label} must be an integer`);
    return fallback;
  }
  if (value < minimum || value > maximum) {
    problems.push(`${label} must be between ${minimum} and ${maximum}`);
    return fallback;
  }
  return value;
}

function readBoolean(
  input: Record<string, unknown>,
  key: string,
  fallback: boolean,
  problems: string[],
): boolean {
  const value = input[key];
  if (value === undefined) return fallback;
  if (typeof value !== "boolean") {
    problems.push(`${key} must be a boolean`);
    return fallback;
  }
  return value;
}

function readSources(value: unknown, problems: string[]): SourceConfig[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > 64) {
    problems.push("ingestion.sources must be an array of at most 64 sources");
    return [];
  }
  const sources: SourceConfig[] = [];
  const names = new Set<string>();
  for (const [index, item] of value.entries()) {
    if (!isRecord(item)) {
      problems.push(`ingestion.sources[${index}] must be an object`);
      continue;
    }
    checkUnknownKeys(
      item,
      ["name", "sourceType", "path", "enabled"],
      `ingestion.sources[${index}]`,
      problems,
    );
    const name = item["name"];
    const sourceType = item["sourceType"];
    const sourcePath = item["path"];
    const enabled = item["enabled"];
    if (
      typeof name !== "string" ||
      name.length === 0 ||
      name.length > 128 ||
      /\p{Cc}/u.test(name)
    ) {
      problems.push(`ingestion.sources[${index}].name is invalid`);
      continue;
    }
    if (
      sourceType !== "authlog" &&
      sourceType !== "journal" &&
      sourceType !== "ndjson" &&
      sourceType !== "syslog"
    ) {
      problems.push(`ingestion.sources[${index}].sourceType is invalid`);
      continue;
    }
    if (
      typeof sourcePath !== "string" ||
      sourcePath.length === 0 ||
      sourcePath.length > 4096
    ) {
      problems.push(`ingestion.sources[${index}].path is invalid`);
      continue;
    }
    if (enabled !== undefined && typeof enabled !== "boolean") {
      problems.push(`ingestion.sources[${index}].enabled must be a boolean`);
      continue;
    }
    if (names.has(name)) {
      problems.push(`ingestion.sources contains duplicate name '${name}'`);
      continue;
    }
    names.add(name);
    sources.push({
      name,
      sourceType,
      path: resolve(sourcePath),
      enabled: enabled ?? true,
    });
  }
  return sources;
}

function readToken(
  input: Record<string, unknown>,
  problems: string[],
): string | null {
  const value = input["token"];
  if (value === undefined || value === null) return null;
  if (typeof value !== "string" || value.length < 32 || value.length > 512) {
    problems.push("server.token must contain between 32 and 512 characters");
    return null;
  }
  return value;
}

function checkUnknownKeys(
  input: Record<string, unknown>,
  allowed: readonly string[],
  section: string,
  problems: string[],
): void {
  for (const key of Object.keys(input)) {
    if (!allowed.includes(key))
      problems.push(`${section}.${key} is not a known setting`);
  }
}

function parseEnvironmentInteger(value: string): number | string {
  if (!/^\d+$/.test(value)) return value;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) ? parsed : value;
}

function parseEnvironmentBoolean(value: string): boolean | string {
  if (value === "true") return true;
  if (value === "false") return false;
  return value;
}

function parseEnvironmentJson(value: string): unknown {
  if (value.length > 16_384) return value;
  try {
    return JSON.parse(value) as unknown;
  } catch {
    return value;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isMissingFile(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    error.code === "ENOENT"
  );
}
