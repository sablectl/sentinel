import type { DatabaseSync } from "node:sqlite";
import type {
  EventCategory,
  EventOutcome,
  SecurityEvent,
  Severity,
} from "../types.js";

const MAX_EVENT_RESPONSE_BYTES = 16_777_216;

export interface EventQuery {
  readonly from: number;
  readonly to: number;
  readonly page: number;
  readonly limit: number;
  readonly source?: string;
  readonly category?: EventCategory;
  readonly outcome?: EventOutcome;
  readonly severity?: Severity;
  readonly username?: string;
  readonly sourceIp?: string;
  readonly search?: string;
  readonly eventId?: string;
  readonly sort: "timestamp" | "severity" | "source" | "category" | "outcome";
  readonly direction: "asc" | "desc";
}

export interface EventPage {
  readonly events: readonly SecurityEvent[];
  readonly page: number;
  readonly limit: number;
  readonly total: number;
}

export function queryEvents(
  database: DatabaseSync,
  query: EventQuery,
): EventPage {
  if (
    !Number.isSafeInteger(query.page) ||
    query.page < 1 ||
    !Number.isSafeInteger(query.limit) ||
    query.limit < 1 ||
    query.limit > 100
  ) {
    throw new RangeError("event page and limit are invalid");
  }
  const { where, values } = buildWhere(query);
  const count = database
    .prepare(`SELECT COUNT(*) AS count FROM events e WHERE ${where}`)
    .get(...values);
  const total = readNumber(count?.["count"], "event count");
  const sortColumn = sortColumnFor(query.sort);
  const direction = query.direction === "asc" ? "ASC" : "DESC";
  const offset = (query.page - 1) * query.limit;
  if (!Number.isSafeInteger(offset))
    throw new RangeError("event page offset is invalid");

  const rows = database
    .prepare(
      `WITH page AS (
         SELECT e.id FROM events e WHERE ${where}
         ORDER BY ${sortColumn} ${direction}, e.id ${direction}
         LIMIT ? OFFSET ?
       )
       SELECT e.id, e.timestamp, e.ingested_at, e.source, e.source_type,
         e.host, e.category, e.action, e.outcome, e.severity, e.username,
         e.source_ip, e.process_name, e.process_pid, e.message,
         e.parser_version, e.inferred_json,
         m.key AS metadata_key, m.value_json AS metadata_value
       FROM page p
       JOIN events e ON e.id = p.id
       LEFT JOIN event_metadata m ON m.event_id = e.id
       ORDER BY ${sortColumn} ${direction}, e.id ${direction}, m.key`,
    )
    .iterate(...values, query.limit, offset);

  const events = new Map<string, SecurityEvent>();
  let responseBytes = 0;
  for (const row of rows) {
    const id = readString(row["id"], "event id");
    let event = events.get(id);
    if (event === undefined) {
      const processName = nullableString(row["process_name"]);
      const processPid = nullableNumber(row["process_pid"]);
      if ((processName === null) !== (processPid === null)) {
        throw new Error("stored process fields are inconsistent");
      }
      const metadata: Record<string, string | number | boolean> = {};
      event = {
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
        message: readString(row["message"], "event message"),
        parserVersion: readString(row["parser_version"], "parser version"),
        inferred: readStringArray(row["inferred_json"]),
        metadata,
      };
      responseBytes += Buffer.byteLength(event.message, "utf8") + 512;
      if (responseBytes > MAX_EVENT_RESPONSE_BYTES) {
        throw new RangeError(
          "event response exceeds its byte limit; reduce the page size",
        );
      }
      events.set(id, event);
    }

    const key = row["metadata_key"];
    const json = row["metadata_value"];
    if (key !== null && json !== null) {
      if (typeof key !== "string" || typeof json !== "string") {
        throw new Error("stored event metadata has an invalid shape");
      }
      const value = parseScalar(json);
      if (value === null)
        throw new Error("stored event metadata is not scalar JSON");
      responseBytes +=
        Buffer.byteLength(key, "utf8") + Buffer.byteLength(json, "utf8");
      if (responseBytes > MAX_EVENT_RESPONSE_BYTES) {
        throw new RangeError(
          "event response exceeds its byte limit; reduce the page size",
        );
      }
      event = {
        ...event,
        metadata: { ...event.metadata, [key]: value },
      };
      events.set(id, event);
    }
  }

  return {
    events: [...events.values()],
    page: query.page,
    limit: query.limit,
    total,
  };
}

export function getEventById(
  database: DatabaseSync,
  eventId: string,
): SecurityEvent | null {
  const result = queryEvents(database, {
    from: 0,
    to: Number.MAX_SAFE_INTEGER,
    page: 1,
    limit: 1,
    sort: "timestamp",
    direction: "asc",
    eventId,
  });
  return result.events[0] ?? null;
}

function buildWhere(query: EventQuery): {
  readonly where: string;
  readonly values: (string | number)[];
} {
  const conditions = ["e.timestamp >= ?", "e.timestamp <= ?"];
  const values: (string | number)[] = [query.from, query.to];
  for (const [field, value] of [
    ["source", query.source],
    ["category", query.category],
    ["outcome", query.outcome],
    ["severity", query.severity],
    ["username", query.username],
    ["source_ip", query.sourceIp],
  ] as const) {
    if (value === undefined) continue;
    conditions.push(`e.${field} = ?`);
    values.push(value);
  }
  if (query.search !== undefined && query.search.length > 0) {
    conditions.push(
      `(instr(lower(e.message), lower(?)) > 0 OR instr(lower(COALESCE(e.username, '')), lower(?)) > 0 OR instr(lower(COALESCE(e.source_ip, '')), lower(?)) > 0 OR instr(lower(COALESCE(e.host, '')), lower(?)) > 0)`,
    );
    values.push(query.search, query.search, query.search, query.search);
  }
  if (query.eventId !== undefined) {
    conditions.push("e.id = ?");
    values.push(query.eventId);
  }
  return { where: conditions.join(" AND "), values };
}

function sortColumnFor(sort: EventQuery["sort"]): string {
  switch (sort) {
    case "timestamp":
      return "e.timestamp";
    case "severity":
      return "e.severity";
    case "source":
      return "e.source";
    case "category":
      return "e.category";
    case "outcome":
      return "e.outcome";
  }
}

function parseScalar(value: string): string | number | boolean | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value) as unknown;
  } catch {
    return null;
  }
  return typeof parsed === "string" ||
    typeof parsed === "number" ||
    typeof parsed === "boolean"
    ? parsed
    : null;
}

function readStringArray(value: unknown): string[] {
  if (typeof value !== "string")
    throw new Error("stored inferred fields are invalid");
  let parsed: unknown;
  try {
    parsed = JSON.parse(value) as unknown;
  } catch {
    throw new Error("stored inferred fields are invalid JSON");
  }
  if (
    !Array.isArray(parsed) ||
    !parsed.every((item) => typeof item === "string")
  ) {
    throw new Error("stored inferred fields have an invalid shape");
  }
  return parsed;
}

function readSourceType(value: unknown): SecurityEvent["sourceType"] {
  if (
    value === "authlog" ||
    value === "journal" ||
    value === "ndjson" ||
    value === "syslog"
  )
    return value;
  throw new Error("stored source type is invalid");
}

function readCategory(value: unknown): EventCategory {
  if (
    value === "authentication" ||
    value === "privilege" ||
    value === "session" ||
    value === "account" ||
    value === "other"
  )
    return value;
  throw new Error("stored category is invalid");
}

function readOutcome(value: unknown): EventOutcome {
  if (value === "success" || value === "failure" || value === "unknown")
    return value;
  throw new Error("stored outcome is invalid");
}

function readSeverity(value: unknown): Severity {
  if (
    value === "info" ||
    value === "low" ||
    value === "medium" ||
    value === "high" ||
    value === "critical"
  )
    return value;
  throw new Error("stored severity is invalid");
}

function readString(value: unknown, label: string): string {
  if (typeof value !== "string") throw new Error(`stored ${label} is invalid`);
  return value;
}

function readNumber(value: unknown, label: string): number {
  if (typeof value === "number" && Number.isSafeInteger(value)) return value;
  if (typeof value === "bigint" && value <= BigInt(Number.MAX_SAFE_INTEGER))
    return Number(value);
  throw new Error(`stored ${label} is invalid`);
}

function nullableString(value: unknown): string | null {
  return value === null ? null : readString(value, "nullable text");
}

function nullableNumber(value: unknown): number | null {
  return value === null ? null : readNumber(value, "nullable number");
}
