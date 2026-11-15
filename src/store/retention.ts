import type { DatabaseSync } from "node:sqlite";

const DAY_MS = 86_400_000;

export interface PruneResult {
  readonly events: number;
  readonly parseFailures: number;
}

export function pruneExpiredData(
  database: DatabaseSync,
  retentionDays: number,
  now: number,
): number {
  if (!Number.isSafeInteger(retentionDays) || retentionDays < 1) {
    throw new RangeError("retentionDays must be a positive integer");
  }
  if (!Number.isSafeInteger(now) || now < 0) {
    throw new RangeError("now must be a non-negative integer timestamp");
  }

  const result = pruneExpiredRecords(database, now - retentionDays * DAY_MS);
  return result.events + result.parseFailures;
}

export function pruneExpiredRecords(
  database: DatabaseSync,
  cutoff: number,
): PruneResult {
  if (!Number.isSafeInteger(cutoff) || cutoff < 0) {
    throw new RangeError("cutoff must be a non-negative integer timestamp");
  }

  database.exec("BEGIN IMMEDIATE");
  try {
    const events = database
      .prepare("DELETE FROM events WHERE timestamp < ?")
      .run(cutoff).changes;
    const parseFailures = database
      .prepare("DELETE FROM parse_failures WHERE failed_at < ?")
      .run(cutoff).changes;
    database.exec("COMMIT");
    return {
      events: safeCount(events),
      parseFailures: safeCount(parseFailures),
    };
  } catch (error: unknown) {
    database.exec("ROLLBACK");
    throw error;
  }
}

function safeCount(value: number | bigint): number {
  if (typeof value === "number" && Number.isSafeInteger(value)) return value;
  if (typeof value === "bigint" && value <= BigInt(Number.MAX_SAFE_INTEGER)) {
    return Number(value);
  }
  throw new Error("database reported an unsafe deletion count");
}
