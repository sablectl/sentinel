import type { DatabaseSync } from "node:sqlite";
import type {
  Checkpoint,
  CheckpointRepository,
  SourceRegistration,
} from "../types.js";
import type { EventDatabase } from "../store/database.js";

export class SqliteCheckpointStore implements CheckpointRepository {
  constructor(private readonly store: EventDatabase) {}

  registerSource(source: SourceRegistration): void {
    if (
      source.name.length === 0 ||
      source.name.length > 128 ||
      /\p{Cc}/u.test(source.name)
    ) {
      throw new RangeError(
        "source name must contain between 1 and 128 characters",
      );
    }
    this.store.withDatabase((database) => {
      database
        .prepare(
          `INSERT INTO sources (name, source_type, path, status, updated_at)
           VALUES (?, ?, ?, 'idle', ?)
           ON CONFLICT(name) DO UPDATE SET
             source_type = excluded.source_type,
             path = excluded.path,
             updated_at = excluded.updated_at`,
        )
        .run(source.name, source.sourceType, source.path, Date.now());
    });
  }

  load(sourceName: string): Checkpoint | null {
    return this.store.withDatabase((database) =>
      loadCheckpoint(database, sourceName),
    );
  }

  save(sourceName: string, checkpoint: Checkpoint): void {
    if (
      checkpoint.offset < 0 ||
      checkpoint.size < 0 ||
      checkpoint.lineNumber < 0 ||
      !Number.isSafeInteger(checkpoint.offset) ||
      !Number.isSafeInteger(checkpoint.size) ||
      !Number.isSafeInteger(checkpoint.lineNumber) ||
      checkpoint.offset > checkpoint.size
    ) {
      throw new RangeError("checkpoint offsets must be valid file positions");
    }
    this.store.withDatabase((database) => {
      database
        .prepare(
          `INSERT INTO checkpoints
             (source_name, path, inode, size, offset, line_number, last_hash, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(source_name) DO UPDATE SET
             path = excluded.path,
             inode = excluded.inode,
             size = excluded.size,
             offset = excluded.offset,
             line_number = excluded.line_number,
             last_hash = excluded.last_hash,
             updated_at = excluded.updated_at`,
        )
        .run(
          sourceName,
          checkpoint.path,
          checkpoint.inode,
          checkpoint.size,
          checkpoint.offset,
          checkpoint.lineNumber,
          checkpoint.lastHash,
          Date.now(),
        );
    });
  }
}

function loadCheckpoint(
  database: DatabaseSync,
  sourceName: string,
): Checkpoint | null {
  const row = database
    .prepare(
      `SELECT path, inode, size, offset, line_number, last_hash
       FROM checkpoints WHERE source_name = ?`,
    )
    .get(sourceName);
  if (row === undefined) return null;

  const path = row["path"];
  const inode = row["inode"];
  const size = row["size"];
  const offset = row["offset"];
  const lineNumber = row["line_number"];
  const lastHash = row["last_hash"];
  if (
    typeof path !== "string" ||
    typeof inode !== "string" ||
    typeof size !== "number" ||
    typeof offset !== "number" ||
    typeof lineNumber !== "number" ||
    !Number.isSafeInteger(lineNumber) ||
    lineNumber < 0 ||
    (lastHash !== null && typeof lastHash !== "string")
  ) {
    throw new Error("stored checkpoint has an invalid shape");
  }
  return { path, inode, size, offset, lineNumber, lastHash };
}
