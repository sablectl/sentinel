import { chmodSync, closeSync, lstatSync, mkdirSync, openSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { migrateDatabase, SCHEMA_VERSION } from "./migrations.js";
import { getStoreCounts, type StoreCounts } from "./queries.js";
import { pruneExpiredData } from "./retention.js";

export interface EventDatabaseOptions {
  readonly path: string;
}

export class EventDatabase {
  private readonly database: DatabaseSync;
  private readonly path: string;
  private closed = false;

  constructor(options: EventDatabaseOptions) {
    if (options.path.length === 0) {
      throw new Error("database path must not be empty");
    }
    this.path = options.path;

    if (options.path !== ":memory:") this.prepareDatabaseFile(options.path);

    this.database = new DatabaseSync(options.path);
    try {
      this.database.exec("PRAGMA foreign_keys = ON");
      this.database.exec("PRAGMA journal_mode = WAL");
      this.database.exec("PRAGMA synchronous = FULL");
      this.database.exec("PRAGMA trusted_schema = OFF");
      migrateDatabase(this.database);
      if (options.path !== ":memory:") this.setFilePermissions();
    } catch (error: unknown) {
      this.database.close();
      throw error;
    }
  }

  get schemaVersion(): number {
    return SCHEMA_VERSION;
  }

  withDatabase<T>(operation: (database: DatabaseSync) => T): T {
    this.assertOpen();
    return operation(this.database);
  }

  counts(): StoreCounts {
    return this.withDatabase(getStoreCounts);
  }

  integrityCheck(): string {
    return this.withDatabase((database) => {
      const row = database.prepare("PRAGMA integrity_check").get();
      return typeof row?.["integrity_check"] === "string"
        ? row["integrity_check"]
        : "integrity check returned no result";
    });
  }

  prune(retentionDays: number, now = Date.now()): number {
    this.assertOpen();
    return pruneExpiredData(this.database, retentionDays, now);
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    try {
      this.database.exec("PRAGMA wal_checkpoint(TRUNCATE)");
    } finally {
      this.database.close();
    }
  }

  private assertOpen(): void {
    if (this.closed) throw new Error("database is closed");
  }

  private prepareDatabaseFile(path: string): void {
    const directory = dirname(path);
    this.ensureDatabaseDirectory(directory);

    try {
      const info = lstatSync(path);
      if (info.isSymbolicLink() || !info.isFile()) {
        throw new Error("database path must be a regular file, not a symlink");
      }
      if (info.nlink !== 1) {
        throw new Error("database file must not have additional hard links");
      }
      chmodSync(path, 0o600);
    } catch (error: unknown) {
      if (!isMissingFile(error)) throw error;

      let descriptor: number | undefined;
      try {
        descriptor = openSync(path, "wx", 0o600);
      } catch (createError: unknown) {
        if (!isAlreadyExists(createError)) throw createError;
        const info = lstatSync(path);
        if (info.isSymbolicLink() || !info.isFile()) {
          throw new Error(
            "database path must be a regular file, not a symlink",
            { cause: createError },
          );
        }
        if (info.nlink !== 1) {
          throw new Error("database file must not have additional hard links", {
            cause: createError,
          });
        }
      } finally {
        if (descriptor !== undefined) closeSync(descriptor);
      }
    }
  }

  private ensureDatabaseDirectory(directory: string): void {
    let info;
    try {
      info = lstatSync(directory);
    } catch (error: unknown) {
      if (!isMissingFile(error)) throw error;
      mkdirSync(directory, { recursive: true, mode: 0o700 });
      info = lstatSync(directory);
    }
    if (info.isSymbolicLink() || !info.isDirectory()) {
      throw new Error(
        "database parent path must be a directory, not a symlink",
      );
    }
    const sharedWritable = (info.mode & 0o022) !== 0;
    const sticky = (info.mode & 0o1000) !== 0;
    if (sharedWritable && !sticky) {
      throw new Error(
        "database parent directory is writable by other users without the sticky bit",
      );
    }
  }

  private setFilePermissions(): void {
    for (const suffix of ["", "-wal", "-shm"]) {
      try {
        chmodSync(`${this.path}${suffix}`, 0o600);
      } catch (error: unknown) {
        if (!isMissingFile(error)) throw error;
      }
    }
  }
}

function isMissingFile(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    error.code === "ENOENT"
  );
}

function isAlreadyExists(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    error.code === "EEXIST"
  );
}
