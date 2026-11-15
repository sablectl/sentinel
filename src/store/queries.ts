import { createHash } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import type {
  ParseFailure,
  RawRecord,
  SecurityEvent,
  SourceType,
} from "../types.js";

export interface StoreCounts {
  readonly events: number;
  readonly parseFailures: number;
  readonly sources: number;
  readonly alerts: number;
}

export interface EventWriteResult {
  readonly inserted: number;
  readonly duplicates: number;
}

export interface SourceStatus {
  readonly name: string;
  readonly sourceType: SourceType;
  readonly path: string;
  readonly status: string;
  readonly lastSeen: number | null;
  readonly errorCount: number;
  readonly lastError: string | null;
}

export interface TimestampRange {
  readonly start: number;
  readonly end: number;
}

export function getStoreCounts(database: DatabaseSync): StoreCounts {
  return {
    events: countRows(database, "events"),
    parseFailures: countRows(database, "parse_failures"),
    sources: countRows(database, "sources"),
    alerts: countRows(database, "alerts"),
  };
}

export function insertEvents(
  database: DatabaseSync,
  events: readonly SecurityEvent[],
): EventWriteResult {
  let inserted = 0;
  database.exec("BEGIN IMMEDIATE");
  try {
    const insertEvent = database.prepare(
      `INSERT INTO events (
         id, timestamp, ingested_at, source, source_type, host, category,
         action, outcome, severity, username, source_ip, process_name,
         process_pid, message, parser_version, inferred_json
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(id) DO NOTHING`,
    );
    const insertMetadata = database.prepare(
      "INSERT INTO event_metadata (event_id, key, value_json) VALUES (?, ?, ?)",
    );
    const updateLastSeen = database.prepare(
      `UPDATE sources SET
         last_seen = CASE
           WHEN last_seen IS NULL OR last_seen < ? THEN ?
           ELSE last_seen
         END,
         status = 'ready', updated_at = ?
       WHERE name = ?`,
    );

    for (const event of events) {
      const result = insertEvent.run(
        event.id,
        event.timestamp,
        event.ingestedAt,
        event.source,
        event.sourceType,
        event.host,
        event.category,
        event.action,
        event.outcome,
        event.severity,
        event.username,
        event.sourceIp,
        event.process?.name ?? null,
        event.process?.pid ?? null,
        event.message,
        event.parserVersion,
        JSON.stringify(event.inferred),
      );
      if (countChanges(result.changes) === 0) continue;

      inserted += 1;
      for (const [key, value] of Object.entries(event.metadata).sort(
        ([left], [right]) => (left < right ? -1 : left > right ? 1 : 0),
      )) {
        insertMetadata.run(event.id, key, JSON.stringify(value));
      }
      updateLastSeen.run(
        event.timestamp,
        event.timestamp,
        Date.now(),
        event.source,
      );
    }
    database.exec("COMMIT");
  } catch (error: unknown) {
    database.exec("ROLLBACK");
    throw error;
  }
  return { inserted, duplicates: events.length - inserted };
}

export function recordParseFailure(
  database: DatabaseSync,
  failure: ParseFailure,
  record: RawRecord,
  failedAt = Date.now(),
): boolean {
  const recordKey = createHash("sha256")
    .update(failure.source, "utf8")
    .update("\0", "utf8")
    .update(record.fileId, "utf8")
    .update("\0", "utf8")
    .update(String(failure.offset), "utf8")
    .update("\0", "utf8")
    .update(record.checkpointHash, "utf8")
    .digest("hex");
  database.exec("BEGIN IMMEDIATE");
  try {
    const inserted = database
      .prepare(
        `INSERT INTO parse_failures
           (source, record_key, offset, line_number, reason, sample, failed_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(source, record_key) DO NOTHING`,
      )
      .run(
        failure.source,
        recordKey,
        failure.offset,
        failure.lineNumber,
        failure.reason,
        failure.sample,
        failedAt,
      );
    const didInsert = countChanges(inserted.changes) > 0;
    if (didInsert) {
      database
        .prepare(
          `UPDATE sources SET error_count = error_count + 1,
             status = 'ready', last_error = ?, updated_at = ?
           WHERE name = ?`,
        )
        .run(failure.reason, failedAt, failure.source);
    }
    database.exec("COMMIT");
    return didInsert;
  } catch (error: unknown) {
    database.exec("ROLLBACK");
    throw error;
  }
}

export function setSourceStatus(
  database: DatabaseSync,
  sourceName: string,
  status: string,
  error?: string,
): void {
  const safeError =
    error === undefined ? null : error.replace(/\p{Cc}/gu, " ").slice(0, 512);
  database
    .prepare(
      `UPDATE sources SET status = ?, last_error = COALESCE(?, last_error),
         error_count = error_count + ?, updated_at = ?
       WHERE name = ?`,
    )
    .run(
      status,
      safeError,
      error === undefined ? 0 : 1,
      Date.now(),
      sourceName,
    );
}

export function getSourceStatuses(database: DatabaseSync): SourceStatus[] {
  return database
    .prepare(
      `SELECT name, source_type, path, status, last_seen, error_count, last_error
       FROM sources ORDER BY name`,
    )
    .all()
    .map((row) => {
      const sourceType = row["source_type"];
      if (
        sourceType !== "authlog" &&
        sourceType !== "journal" &&
        sourceType !== "ndjson" &&
        sourceType !== "syslog"
      ) {
        throw new Error("stored source has an invalid source type");
      }
      return {
        name: stringValue(row["name"]),
        sourceType,
        path: stringValue(row["path"]),
        status: stringValue(row["status"]),
        lastSeen: nullableNumber(row["last_seen"]),
        errorCount: numberValue(row["error_count"]),
        lastError: nullableString(row["last_error"]),
      };
    });
}

export function getEventTimestampRange(
  database: DatabaseSync,
  sourceName: string,
): TimestampRange | null {
  const row = database
    .prepare(
      "SELECT MIN(timestamp) AS start, MAX(timestamp) AS end FROM events WHERE source = ?",
    )
    .get(sourceName);
  if (row === undefined || row["start"] === null || row["end"] === null) {
    return null;
  }
  const start = numberValue(row["start"]);
  const end = numberValue(row["end"]);
  return { start, end };
}

type CountTable = "events" | "parse_failures" | "sources" | "alerts";

function countRows(database: DatabaseSync, table: CountTable): number {
  const row = database.prepare(`SELECT COUNT(*) AS count FROM ${table}`).get();
  const value = row?.["count"];
  if (typeof value === "number" && Number.isSafeInteger(value)) return value;
  if (typeof value === "bigint" && value <= BigInt(Number.MAX_SAFE_INTEGER)) {
    return Number(value);
  }
  throw new Error(`could not read row count for ${table}`);
}

function countChanges(value: number | bigint): number {
  if (typeof value === "number" && Number.isSafeInteger(value)) return value;
  if (typeof value === "bigint" && value <= BigInt(Number.MAX_SAFE_INTEGER)) {
    return Number(value);
  }
  throw new Error("database reported an unsafe change count");
}

function stringValue(value: unknown): string {
  if (typeof value !== "string")
    throw new Error("stored source has an invalid text field");
  return value;
}

function numberValue(value: unknown): number {
  if (typeof value === "number" && Number.isSafeInteger(value)) return value;
  if (typeof value === "bigint" && value <= BigInt(Number.MAX_SAFE_INTEGER)) {
    return Number(value);
  }
  throw new Error("stored source has an invalid numeric field");
}

function nullableNumber(value: unknown): number | null {
  return value === null ? null : numberValue(value);
}

function nullableString(value: unknown): string | null {
  return value === null ? null : stringValue(value);
}
