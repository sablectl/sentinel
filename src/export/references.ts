import type { DatabaseSync } from "node:sqlite";

const QUERY_CHUNK_SIZE = 500;

export function getRelevantRuleReferences(
  database: DatabaseSync,
  eventIds: readonly string[],
): string[] {
  const rules = new Set<string>();
  for (let offset = 0; offset < eventIds.length; offset += QUERY_CHUNK_SIZE) {
    const chunk = eventIds.slice(offset, offset + QUERY_CHUNK_SIZE);
    if (chunk.length === 0) continue;
    const placeholders = chunk.map(() => "?").join(", ");
    const rows = database
      .prepare(
        `SELECT DISTINCT a.rule_id FROM alerts a
         JOIN alert_events ae ON ae.alert_id = a.id
         WHERE ae.event_id IN (${placeholders}) ORDER BY a.rule_id`,
      )
      .all(...chunk);
    for (const row of rows) {
      const ruleId = row["rule_id"];
      if (typeof ruleId === "string") rules.add(ruleId);
    }
  }
  return [...rules].sort();
}
