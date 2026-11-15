import type { DatabaseSync } from "node:sqlite";
import type {
  Alert,
  AlertNote,
  AlertState,
  RuleMatch,
  RuleThresholds,
  Severity,
} from "../types.js";
import { sanitiseMessage } from "../parse/sanitise.js";
import type { EventDatabase } from "../store/database.js";

export interface AlertFilters {
  readonly state?: AlertState;
  readonly severity?: Severity;
  readonly limit?: number;
  readonly offset?: number;
}

export interface AlertUpsertResult {
  readonly alert: Alert;
  readonly created: boolean;
  readonly evidenceAdded: number;
}

export class AlertNotFoundError extends Error {
  constructor(alertId: number) {
    super(`alert ${alertId} was not found`);
    this.name = "AlertNotFoundError";
  }
}

export class AlertStore {
  constructor(private readonly store: EventDatabase) {}

  upsert(match: RuleMatch): Alert {
    return this.upsertWithResult(match).alert;
  }

  upsertWithResult(match: RuleMatch): AlertUpsertResult {
    validateMatch(match);
    let alertId = 0;
    let created = false;
    let evidenceAdded = 0;
    this.store.withDatabase((database) => {
      database.exec("BEGIN IMMEDIATE");
      try {
        const existing = database
          .prepare("SELECT id FROM alerts WHERE rule_id = ? AND dedup_key = ?")
          .get(match.ruleId, match.dedupKey);

        if (existing === undefined) {
          created = true;
          const insertedAlert = database
            .prepare(
              `INSERT INTO alerts (
                 rule_id, dedup_key, rule_version, severity, state,
                 first_seen, last_seen, occurrences, rationale,
                 thresholds_json, window_start, window_end
               ) VALUES (?, ?, ?, ?, 'open', ?, ?, 1, ?, ?, ?, ?)`,
            )
            .run(
              match.ruleId,
              match.dedupKey,
              match.ruleVersion,
              match.severity,
              match.windowStart,
              match.windowEnd,
              match.rationale,
              JSON.stringify(match.thresholds),
              match.windowStart,
              match.windowEnd,
            );
          alertId = safeInteger(
            insertedAlert.lastInsertRowid,
            "new alert identifier",
          );
          evidenceAdded = insertEvidence(database, alertId, match.eventIds);
        } else {
          alertId = safeInteger(existing["id"], "stored alert identifier");
          evidenceAdded = insertEvidence(database, alertId, match.eventIds);
          database
            .prepare(
              `UPDATE alerts SET
                 rule_version = ?, severity = ?,
                 state = CASE WHEN state = 'resolved' AND ? > 0 THEN 'open' ELSE state END,
                 first_seen = MIN(first_seen, ?), last_seen = MAX(last_seen, ?),
                 occurrences = occurrences + ?, rationale = ?, thresholds_json = ?,
                 window_start = MIN(window_start, ?), window_end = MAX(window_end, ?)
               WHERE id = ?`,
            )
            .run(
              match.ruleVersion,
              match.severity,
              evidenceAdded,
              match.windowStart,
              match.windowEnd,
              evidenceAdded > 0 ? 1 : 0,
              match.rationale,
              JSON.stringify(match.thresholds),
              match.windowStart,
              match.windowEnd,
              alertId,
            );
        }
        database.exec("COMMIT");
      } catch (error: unknown) {
        database.exec("ROLLBACK");
        throw error;
      }
    });
    return { alert: this.get(alertId), created, evidenceAdded };
  }

  get(alertId: number): Alert {
    if (!Number.isSafeInteger(alertId) || alertId < 1) {
      throw new RangeError("alert identifier must be a positive integer");
    }
    return this.store.withDatabase((database) => {
      const row = database
        .prepare("SELECT * FROM alerts WHERE id = ?")
        .get(alertId);
      if (row === undefined) throw new AlertNotFoundError(alertId);
      return mapAlert(database, row);
    });
  }

  list(filters: AlertFilters = {}): Alert[] {
    const limit = filters.limit ?? 100;
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 500) {
      throw new RangeError("alert limit must be between 1 and 500");
    }
    const offset = filters.offset ?? 0;
    if (!Number.isSafeInteger(offset) || offset < 0 || offset > 10_000_000) {
      throw new RangeError("alert offset is invalid");
    }
    return this.store.withDatabase((database) =>
      database
        .prepare(
          `SELECT * FROM alerts
           WHERE (? IS NULL OR state = ?)
             AND (? IS NULL OR severity = ?)
           ORDER BY last_seen DESC, id DESC
           LIMIT ? OFFSET ?`,
        )
        .all(
          filters.state ?? null,
          filters.state ?? null,
          filters.severity ?? null,
          filters.severity ?? null,
          limit,
          offset,
        )
        .map((row) => mapAlert(database, row)),
    );
  }

  count(filters: Pick<AlertFilters, "state" | "severity"> = {}): number {
    return this.store.withDatabase((database) => {
      const row = database
        .prepare(
          `SELECT COUNT(*) AS count FROM alerts
           WHERE (? IS NULL OR state = ?)
             AND (? IS NULL OR severity = ?)`,
        )
        .get(
          filters.state ?? null,
          filters.state ?? null,
          filters.severity ?? null,
          filters.severity ?? null,
        );
      const count = row?.["count"];
      if (typeof count !== "number" && typeof count !== "bigint") {
        throw new Error("database returned an invalid alert count");
      }
      return toCount(count);
    });
  }

  setState(alertId: number, state: AlertState): Alert {
    this.store.withDatabase((database) => {
      const result = database
        .prepare("UPDATE alerts SET state = ? WHERE id = ?")
        .run(state, alertId);
      if (toCount(result.changes) === 0) throw new AlertNotFoundError(alertId);
    });
    return this.get(alertId);
  }

  addNote(alertId: number, note: string): AlertNote {
    const sanitised = sanitiseMessage(note);
    if (sanitised.length === 0 || sanitised.length > 4000) {
      throw new RangeError(
        "alert note must contain between 1 and 4000 characters",
      );
    }
    return this.store.withDatabase((database) => {
      const result = database
        .prepare(
          "INSERT INTO alert_notes (alert_id, created_at, note) VALUES (?, ?, ?)",
        )
        .run(alertId, Date.now(), sanitised);
      const id = safeInteger(result.lastInsertRowid, "new note identifier");
      return mapNote(
        database.prepare("SELECT * FROM alert_notes WHERE id = ?").get(id),
      );
    });
  }

  notes(alertId: number, limit = 100): AlertNote[] {
    if (!Number.isSafeInteger(alertId) || alertId < 1) {
      throw new RangeError("alert identifier must be a positive integer");
    }
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) {
      throw new RangeError("alert note limit must be between 1 and 100");
    }
    return this.store.withDatabase((database) =>
      database
        .prepare(
          `SELECT id, alert_id, created_at, note FROM (
             SELECT id, alert_id, created_at, note FROM alert_notes
             WHERE alert_id = ? ORDER BY created_at DESC, id DESC LIMIT ?
           ) ORDER BY created_at, id`,
        )
        .all(alertId, limit)
        .map(mapNote),
    );
  }
}

function validateMatch(match: RuleMatch): void {
  if (
    match.ruleId.length === 0 ||
    match.ruleId.length > 128 ||
    match.dedupKey.length === 0 ||
    match.dedupKey.length > 512 ||
    !Number.isSafeInteger(match.ruleVersion) ||
    match.ruleVersion < 1 ||
    !Number.isSafeInteger(match.windowStart) ||
    !Number.isSafeInteger(match.windowEnd) ||
    match.windowStart < 0 ||
    match.windowEnd < match.windowStart ||
    match.eventIds.length === 0 ||
    match.eventIds.length > 5000
  ) {
    throw new RangeError("detection match has an invalid shape");
  }
  const rationale = sanitiseMessage(match.rationale);
  if (rationale.length === 0 || rationale.length > 1000) {
    throw new RangeError("detection rationale has an invalid length");
  }
}

function insertEvidence(
  database: DatabaseSync,
  alertId: number,
  eventIds: readonly string[],
): number {
  const statement = database.prepare(
    `INSERT INTO alert_events (alert_id, event_id) VALUES (?, ?)
     ON CONFLICT(alert_id, event_id) DO NOTHING`,
  );
  let inserted = 0;
  for (const eventId of new Set(eventIds)) {
    const result = statement.run(alertId, eventId);
    inserted += toCount(result.changes);
  }
  return inserted;
}

function mapAlert(database: DatabaseSync, row: Record<string, unknown>): Alert {
  const id = safeInteger(row["id"], "alert identifier");
  const state = readState(row["state"]);
  return {
    id,
    ruleId: readString(row["rule_id"], "alert rule identifier"),
    dedupKey: readString(row["dedup_key"], "alert deduplication key"),
    severity: readSeverity(row["severity"]),
    state,
    firstSeen: safeInteger(row["first_seen"], "alert first-seen timestamp"),
    lastSeen: safeInteger(row["last_seen"], "alert last-seen timestamp"),
    occurrences: safeInteger(row["occurrences"], "alert occurrence count"),
    rationale: readString(row["rationale"], "alert rationale"),
    thresholds: readThresholds(row["thresholds_json"]),
    eventIds: database
      .prepare(
        "SELECT event_id FROM alert_events WHERE alert_id = ? AND event_id IS NOT NULL ORDER BY event_id",
      )
      .all(id)
      .map((evidence) =>
        readString(evidence["event_id"], "alert evidence identifier"),
      ),
  };
}

function mapNote(row: Record<string, unknown> | undefined): AlertNote {
  if (row === undefined) throw new Error("stored alert note was not found");
  return {
    id: safeInteger(row["id"], "alert note identifier"),
    alertId: safeInteger(row["alert_id"], "alert note alert identifier"),
    createdAt: safeInteger(row["created_at"], "alert note timestamp"),
    note: readString(row["note"], "alert note text"),
  };
}

function readThresholds(value: unknown): RuleThresholds {
  if (typeof value !== "string")
    throw new Error("stored alert thresholds are invalid");
  let parsed: unknown;
  try {
    parsed = JSON.parse(value) as unknown;
  } catch {
    throw new Error("stored alert thresholds are invalid JSON");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("stored alert thresholds have an invalid shape");
  }
  const thresholds: Record<string, number | string | boolean> = {};
  for (const [key, item] of Object.entries(parsed)) {
    if (
      typeof item !== "number" &&
      typeof item !== "string" &&
      typeof item !== "boolean"
    ) {
      throw new Error("stored alert threshold is invalid");
    }
    thresholds[key] = item;
  }
  return thresholds;
}

function readState(value: unknown): AlertState {
  if (value === "open" || value === "acknowledged" || value === "resolved") {
    return value;
  }
  throw new Error("stored alert state is invalid");
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
  throw new Error("stored alert severity is invalid");
}

function readString(value: unknown, label: string): string {
  if (typeof value !== "string") throw new Error(`stored ${label} is invalid`);
  return value;
}

function safeInteger(value: unknown, label: string): number {
  if (typeof value === "number" && Number.isSafeInteger(value)) return value;
  if (typeof value === "bigint" && value <= BigInt(Number.MAX_SAFE_INTEGER)) {
    return Number(value);
  }
  throw new Error(`stored ${label} is invalid`);
}

function toCount(value: number | bigint): number {
  if (typeof value === "number" && Number.isSafeInteger(value)) return value;
  if (typeof value === "bigint" && value <= BigInt(Number.MAX_SAFE_INTEGER)) {
    return Number(value);
  }
  throw new Error("database reported an unsafe evidence count");
}
