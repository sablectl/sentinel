import type { DatabaseSync } from "node:sqlite";

const RETENTION_KEY = "retentionDays";

export function getRetentionDays(
  database: DatabaseSync,
  fallback: number,
): number {
  const defaultValue = validateRetentionDays(fallback);
  const row = database
    .prepare("SELECT value_json FROM app_settings WHERE key = ?")
    .get(RETENTION_KEY);
  if (row === undefined) return defaultValue;
  const stored = row["value_json"];
  if (typeof stored !== "string") {
    throw new Error("stored retention setting is invalid");
  }
  let value: unknown;
  try {
    value = JSON.parse(stored) as unknown;
  } catch {
    throw new Error("stored retention setting is invalid JSON");
  }
  if (typeof value !== "number") {
    throw new Error("stored retention setting is not a number");
  }
  return validateRetentionDays(value);
}

export function setRetentionDays(
  database: DatabaseSync,
  retentionDays: number,
  updatedAt = Date.now(),
): number {
  const validated = validateRetentionDays(retentionDays);
  if (!Number.isSafeInteger(updatedAt) || updatedAt < 0) {
    throw new RangeError("retention update timestamp is invalid");
  }
  database
    .prepare(
      `INSERT INTO app_settings (key, value_json, updated_at)
       VALUES (?, ?, ?)
       ON CONFLICT(key) DO UPDATE SET
         value_json = excluded.value_json,
         updated_at = excluded.updated_at`,
    )
    .run(RETENTION_KEY, JSON.stringify(validated), updatedAt);
  return validated;
}

function validateRetentionDays(value: number): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > 3650) {
    throw new RangeError("retention days must be between 1 and 3650");
  }
  return value;
}
