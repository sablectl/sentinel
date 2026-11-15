import { basename, resolve } from "node:path";
import type { Config } from "../config/config.js";
import { DetectionEngine } from "../detect/engine.js";
import { ingestSource } from "../ingest/pipeline.js";
import { SqliteCheckpointStore } from "../ingest/checkpoint.js";
import { createSourceReader, parserForSource } from "../ingest/factory.js";
import { EventDatabase } from "../store/database.js";
import { getRetentionDays } from "../store/system-settings.js";
import type { IngestResult } from "../ingest/pipeline.js";
import type { SourceType } from "../types.js";
import { UsageError } from "./args.js";

export async function runIngest(
  config: Config,
  sourceType: SourceType | undefined,
  sourcePath: string | undefined,
  requestedName: string | undefined,
): Promise<IngestResult> {
  if (sourceType === undefined || sourcePath === undefined) {
    throw new UsageError(
      "ingest requires --source-type and --path; use sentinel ingest --help for usage",
    );
  }
  const path = resolve(sourcePath);
  const name = requestedName ?? `${sourceType}-${basename(path)}`;
  if (name.length === 0 || name.length > 128) {
    throw new UsageError(
      "source name must contain between 1 and 128 characters",
    );
  }

  const database = new EventDatabase({ path: config.storage.path });
  try {
    const checkpoints = new SqliteCheckpointStore(database);
    const source = createSourceReader(
      { name, path, sourceType, enabled: true },
      checkpoints,
      {
        maxRecordBytes: config.ingestion.maxRecordBytes,
        maxFileBytes: config.ingestion.maxFileBytes,
      },
    );
    const detection = new DetectionEngine(database, config.detection);
    const controller = new AbortController();
    const abort = (): void => {
      controller.abort();
    };
    process.once("SIGINT", abort);
    try {
      const result = await ingestSource({
        source,
        parser: parserForSource(sourceType),
        database,
        queueHighWaterMark: config.ingestion.queueHighWaterMark,
        signal: controller.signal,
        detection,
      });
      const retentionDays = database.withDatabase((connection) =>
        getRetentionDays(connection, config.storage.retentionDays),
      );
      database.prune(retentionDays);
      return result;
    } finally {
      process.off("SIGINT", abort);
    }
  } finally {
    database.close();
  }
}
