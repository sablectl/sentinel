import type { DatabaseSync } from "node:sqlite";
import type {
  EventCategory,
  EventOutcome,
  RuleThresholds,
  SecurityEvent,
  Severity,
} from "../types.js";

export interface StoredRuleConfig {
  readonly enabled: boolean;
  readonly thresholds: RuleThresholds;
  readonly updatedAt: number;
}

export function getLatestEventTimestamp(database: DatabaseSync): number | null {
  const row = database
    .prepare("SELECT MAX(timestamp) AS timestamp FROM events")
    .get();
  return row === undefined || row["timestamp"] === null
    ? null
    : readNumber(row["timestamp"], "latest event timestamp");
}

export function getEventsInWindow(
  database: DatabaseSync,
  start: number,
  end: number,
  limit: number,
  maxBytes: number,
): SecurityEvent[] {
  if (
    !Number.isSafeInteger(start) ||
    !Number.isSafeInteger(end) ||
    start < 0 ||
    end < start ||
    !Number.isSafeInteger(limit) ||
    limit < 1 ||
    !Number.isSafeInteger(maxBytes) ||
    maxBytes < 1
  ) {
    throw new RangeError("event window bounds and limit are invalid");
  }

  const rows = database
    .prepare(
      `SELECT id, timestamp, ingested_at, source, source_type, host,
         category, action, outcome, severity, username, source_ip,
         process_name, process_pid, message, parser_version, inferred_json
       FROM events
       WHERE timestamp >= ? AND timestamp <= ?
       ORDER BY timestamp, id
       LIMIT ?`,
    )
    .iterate(start, end, limit);
  const events: SecurityEvent[] = [];
  let usedBytes = 0;
  for (const row of rows) {
    const id = readString(row["id"], "event id");
    const processName = nullableString(row["process_name"]);
    const processPid = nullableNumber(row["process_pid"]);
    if ((processName === null) !== (processPid === null)) {
      throw new Error("stored process fields are inconsistent");
    }
    const message = readString(row["message"], "event message");
    usedBytes += Buffer.byteLength(message, "utf8");
    if (usedBytes > maxBytes) {
      throw new Error(
        "detection event window exceeds its configured byte limit",
      );
    }
    events.push({
      id,
      timestamp: readNumber(row["timestamp"], "event timestamp"),
      ingestedAt: readNumber(row["ingested_at"], "event ingestion timestamp"),
      source: readString(row["source"], "event source"),
      sourceType: readSourceType(row["source_type"]),
      host: nullableString(row["host"]),
      category: readCategory(row["category"]),
      action: readString(row["action"], "event action"),
      outcome: readOutcome(row["outcome"]),
      severity: readSeverity(row["severity"]),
      username: nullableString(row["username"]),
      sourceIp: nullableString(row["source_ip"]),
      process:
        processName === null || processPid === null
          ? null
          : { name: processName, pid: processPid },
      message,
      parserVersion: readString(row["parser_version"], "parser version"),
      inferred: readStringArray(row["inferred_json"]),
      metadata: {},
    });
  }

  return events;
}

export function getRuleConfiguration(
  database: DatabaseSync,
  ruleId: string,
): StoredRuleConfig | null {
  const row = database
    .prepare(
      `SELECT enabled, thresholds_json, updated_at
       FROM rules_config WHERE rule_id = ?`,
    )
    .get(ruleId);
  if (row === undefined) return null;
  const enabled = row["enabled"];
  if (enabled !== 0 && enabled !== 1) {
    throw new Error("stored rule enabled flag is invalid");
  }
  return {
    enabled: enabled === 1,
    thresholds: readThresholds(row["thresholds_json"]),
    updatedAt: readNumber(row["updated_at"], "rule update timestamp"),
  };
}

export function getRuleConfigurations(
  database: DatabaseSync,
): ReadonlyMap<string, StoredRuleConfig> {
  const rows = database
    .prepare(
      "SELECT rule_id, enabled, thresholds_json, updated_at FROM rules_config",
    )
    .all();
  const result = new Map<string, StoredRuleConfig>();
  for (const row of rows) {
    const ruleId = readString(row["rule_id"], "rule identifier");
    const enabled = row["enabled"];
    if (enabled !== 0 && enabled !== 1) {
      throw new Error("stored rule enabled flag is invalid");
    }
    result.set(ruleId, {
      enabled: enabled === 1,
      thresholds: readThresholds(row["thresholds_json"]),
      updatedAt: readNumber(row["updated_at"], "rule update timestamp"),
    });
  }
  return result;
}

export function saveRuleConfiguration(
  database: DatabaseSync,
  ruleId: string,
  enabled: boolean,
  thresholds: RuleThresholds,
  updatedAt = Date.now(),
): void {
  database
    .prepare(
      `INSERT INTO rules_config (rule_id, enabled, thresholds_json, updated_at)
       VALUES (?, ?, ?, ?)
       ON CONFLICT(rule_id) DO UPDATE SET
         enabled = excluded.enabled,
         thresholds_json = excluded.thresholds_json,
         updated_at = excluded.updated_at`,
    )
    .run(ruleId, enabled ? 1 : 0, JSON.stringify(thresholds), updatedAt);
}

function readThresholds(value: unknown): RuleThresholds {
  if (typeof value !== "string")
    throw new Error("stored thresholds are not JSON text");
  let parsed: unknown;
  try {
    parsed = JSON.parse(value) as unknown;
  } catch {
    throw new Error("stored thresholds are not valid JSON");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("stored thresholds must be an object");
  }
  const thresholds: Record<string, number | string | boolean> = {};
  for (const [key, item] of Object.entries(parsed)) {
    if (
      typeof item !== "number" &&
      typeof item !== "string" &&
      typeof item !== "boolean"
    ) {
      throw new Error("stored threshold has an invalid value");
    }
    thresholds[key] = item;
  }
  return thresholds;
}

function readStringArray(value: unknown): string[] {
  if (typeof value !== "string")
    throw new Error("stored inferred fields are not JSON text");
  let parsed: unknown;
  try {
    parsed = JSON.parse(value) as unknown;
  } catch {
    throw new Error("stored inferred fields are not valid JSON");
  }
  if (!isStringArray(parsed)) {
    throw new Error("stored inferred fields have an invalid shape");
  }
  return parsed;
}

function isStringArray(value: unknown): value is string[] {
  return (
    Array.isArray(value) && value.every((item) => typeof item === "string")
  );
}

function readSourceType(value: unknown): SecurityEvent["sourceType"] {
  if (
    value === "authlog" ||
    value === "journal" ||
    value === "ndjson" ||
    value === "syslog"
  ) {
    return value;
  }
  throw new Error("stored event source type is invalid");
}

function readCategory(value: unknown): EventCategory {
  if (
    value === "authentication" ||
    value === "privilege" ||
    value === "session" ||
    value === "account" ||
    value === "other"
  ) {
    return value;
  }
  throw new Error("stored event category is invalid");
}

function readOutcome(value: unknown): EventOutcome {
  if (value === "success" || value === "failure" || value === "unknown")
    return value;
  throw new Error("stored event outcome is invalid");
}

function readSeverity(value: unknown): Severity {
  if (
    value === "info" ||
    value === "low" ||
    value === "medium" ||
    value === "high" ||
    value === "critical"
  ) {
    return value;
  }
  throw new Error("stored event severity is invalid");
}

function readString(value: unknown, label: string): string {
  if (typeof value !== "string") throw new Error(`stored ${label} is invalid`);
  return value;
}

function readNumber(value: unknown, label: string): number {
  if (typeof value === "number" && Number.isSafeInteger(value)) return value;
  if (typeof value === "bigint" && value <= BigInt(Number.MAX_SAFE_INTEGER)) {
    return Number(value);
  }
  throw new Error(`stored ${label} is invalid`);
}

function nullableString(value: unknown): string | null {
  return value === null ? null : readString(value, "nullable text field");
}

function nullableNumber(value: unknown): number | null {
  return value === null ? null : readNumber(value, "nullable numeric field");
}
