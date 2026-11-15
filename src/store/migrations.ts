import type { DatabaseSync } from "node:sqlite";

export interface Migration {
  readonly version: number;
  readonly statements: readonly string[];
}

export const MIGRATIONS: readonly Migration[] = [
  {
    version: 1,
    statements: [
      `CREATE TABLE events (
         id            TEXT PRIMARY KEY,
         timestamp     INTEGER NOT NULL,
         ingested_at   INTEGER NOT NULL,
         source        TEXT NOT NULL,
         source_type   TEXT NOT NULL,
         host          TEXT,
         category      TEXT NOT NULL,
         action        TEXT NOT NULL,
         outcome       TEXT NOT NULL CHECK (outcome IN ('success', 'failure', 'unknown')),
         severity      TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
         username      TEXT,
         source_ip     TEXT,
         process_name  TEXT,
         process_pid   INTEGER,
         message       TEXT NOT NULL,
         parser_version TEXT NOT NULL,
         inferred_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(inferred_json))
       ) STRICT`,
      `CREATE INDEX events_timestamp ON events (timestamp DESC, id)`,
      `CREATE INDEX events_source_ip_timestamp ON events (source_ip, timestamp DESC)`,
      `CREATE INDEX events_username_timestamp ON events (username, timestamp DESC)`,
      `CREATE INDEX events_category_outcome_timestamp ON events (category, outcome, timestamp DESC)`,
      `CREATE TABLE event_metadata (
         event_id   TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
         key        TEXT NOT NULL,
         value_json TEXT NOT NULL CHECK (json_valid(value_json)),
         PRIMARY KEY (event_id, key)
       ) STRICT`,
      `CREATE TABLE parse_failures (
         id         INTEGER PRIMARY KEY,
         source     TEXT NOT NULL,
         record_key TEXT NOT NULL,
         offset     INTEGER NOT NULL CHECK (offset >= 0),
         line_number INTEGER NOT NULL CHECK (line_number > 0),
         reason     TEXT NOT NULL,
         sample     TEXT NOT NULL,
         failed_at  INTEGER NOT NULL,
         UNIQUE (source, record_key)
       ) STRICT`,
      `CREATE INDEX parse_failures_source_time ON parse_failures (source, failed_at DESC)`,
      `CREATE TABLE sources (
         name         TEXT PRIMARY KEY,
         source_type  TEXT NOT NULL,
         path         TEXT NOT NULL,
         enabled      INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
         status       TEXT NOT NULL DEFAULT 'idle',
         last_seen    INTEGER,
         error_count  INTEGER NOT NULL DEFAULT 0 CHECK (error_count >= 0),
         last_error   TEXT,
         updated_at   INTEGER NOT NULL
       ) STRICT`,
      `CREATE TABLE checkpoints (
         source_name TEXT PRIMARY KEY REFERENCES sources(name) ON DELETE CASCADE,
         path        TEXT NOT NULL,
         inode       TEXT,
         size        INTEGER NOT NULL DEFAULT 0 CHECK (size >= 0),
         offset      INTEGER NOT NULL DEFAULT 0 CHECK (offset >= 0),
         line_number INTEGER NOT NULL DEFAULT 0 CHECK (line_number >= 0),
         last_hash   TEXT,
         updated_at  INTEGER NOT NULL
       ) STRICT`,
      `CREATE TABLE rules_config (
         rule_id        TEXT PRIMARY KEY,
         enabled        INTEGER NOT NULL CHECK (enabled IN (0, 1)),
         thresholds_json TEXT NOT NULL CHECK (json_valid(thresholds_json)),
         updated_at     INTEGER NOT NULL
       ) STRICT`,
      `CREATE TABLE alerts (
         id               INTEGER PRIMARY KEY,
         rule_id          TEXT NOT NULL,
         dedup_key        TEXT NOT NULL,
         rule_version     INTEGER NOT NULL CHECK (rule_version > 0),
         severity         TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
         state            TEXT NOT NULL CHECK (state IN ('open', 'acknowledged', 'resolved')),
         first_seen       INTEGER NOT NULL,
         last_seen        INTEGER NOT NULL,
         occurrences      INTEGER NOT NULL CHECK (occurrences > 0),
         rationale        TEXT NOT NULL,
         thresholds_json  TEXT NOT NULL CHECK (json_valid(thresholds_json)),
         window_start     INTEGER NOT NULL,
         window_end       INTEGER NOT NULL,
         UNIQUE (rule_id, dedup_key)
       ) STRICT`,
      `CREATE INDEX alerts_state_severity_last_seen ON alerts (state, severity, last_seen DESC)`,
      `CREATE TABLE alert_events (
         id       INTEGER PRIMARY KEY,
         alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
         event_id TEXT REFERENCES events(id) ON DELETE SET NULL,
         UNIQUE (alert_id, event_id)
       ) STRICT`,
      `CREATE INDEX alert_events_event ON alert_events (event_id)`,
      `CREATE TABLE alert_notes (
         id         INTEGER PRIMARY KEY,
         alert_id   INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
         created_at INTEGER NOT NULL,
         note       TEXT NOT NULL CHECK (length(note) BETWEEN 1 AND 4000)
       ) STRICT`,
      `CREATE INDEX alert_notes_alert_time ON alert_notes (alert_id, created_at DESC)`,
      `CREATE TABLE app_settings (
         key        TEXT PRIMARY KEY,
         value_json TEXT NOT NULL CHECK (json_valid(value_json)),
         updated_at INTEGER NOT NULL
       ) STRICT`,
    ],
  },
];

export const SCHEMA_VERSION = MIGRATIONS.at(-1)?.version ?? 0;

export function migrateDatabase(database: DatabaseSync): void {
  database.exec(
    `CREATE TABLE IF NOT EXISTS schema_migrations (
       version    INTEGER PRIMARY KEY,
       applied_at INTEGER NOT NULL
     ) STRICT`,
  );

  const versionRow = database.prepare("PRAGMA user_version").get();
  const currentVersion =
    typeof versionRow?.["user_version"] === "number"
      ? versionRow["user_version"]
      : 0;

  if (currentVersion > SCHEMA_VERSION) {
    throw new Error(
      `database schema version ${currentVersion} is newer than this build supports (${SCHEMA_VERSION})`,
    );
  }

  const recordedVersions = database
    .prepare("SELECT version FROM schema_migrations ORDER BY version")
    .all()
    .map((row) => row["version"]);
  const historyIsConsistent =
    recordedVersions.length === currentVersion &&
    recordedVersions.every(
      (version, index) => version === MIGRATIONS[index]?.version,
    );
  if (!historyIsConsistent) {
    throw new Error(
      `database migration history is inconsistent with user_version ${currentVersion}`,
    );
  }

  for (const migration of MIGRATIONS) {
    if (migration.version <= currentVersion) continue;

    database.exec("BEGIN IMMEDIATE");
    try {
      for (const statement of migration.statements) database.exec(statement);
      database
        .prepare(
          "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
        )
        .run(migration.version, Date.now());
      database.exec(`PRAGMA user_version = ${migration.version}`);
      database.exec("COMMIT");
    } catch (error: unknown) {
      database.exec("ROLLBACK");
      throw error;
    }
  }
}
