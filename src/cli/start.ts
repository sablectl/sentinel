import type { Config } from "../config/config.js";
import { DetectionEngine } from "../detect/engine.js";
import { createSourceReader, parserForSource } from "../ingest/factory.js";
import { SqliteCheckpointStore } from "../ingest/checkpoint.js";
import { ingestSource } from "../ingest/pipeline.js";
import { EventDatabase } from "../store/database.js";
import { getRetentionDays } from "../store/system-settings.js";
import { HttpApiServer } from "../server/http.js";
import type { EventStream } from "../server/stream.js";
import { VERSION } from "../version.js";

export interface StartOptions {
  readonly listenPort?: number;
  readonly signal?: AbortSignal;
  readonly output?: (line: string) => void;
  readonly onListening?: (port: number) => void;
}

export async function runStart(
  config: Config,
  options: StartOptions = {},
): Promise<void> {
  const database = new EventDatabase({ path: config.storage.path });
  const detection = new DetectionEngine(database, config.detection);
  const server = new HttpApiServer({ config, database, detection });
  const controller = new AbortController();
  let pruneTimer: NodeJS.Timeout | undefined;
  const write =
    options.output ??
    ((line: string): void => {
      process.stdout.write(line);
    });
  let resolveStop: (() => void) | undefined;
  const stopped = new Promise<void>((resolve) => {
    resolveStop = resolve;
  });
  const shutdown = (): void => {
    controller.abort();
    resolveStop?.();
  };
  const externalSignal = options.signal;
  if (externalSignal === undefined) {
    process.once("SIGINT", shutdown);
    process.once("SIGTERM", shutdown);
  } else {
    externalSignal.addEventListener("abort", shutdown, { once: true });
    if (externalSignal.aborted) shutdown();
  }
  try {
    const port = await server.listen(options.listenPort ?? config.server.port);
    const host = formatHost(config.server.host);
    write(`Sentinel ${VERSION} listening at http://${host}:${port}/\n`);
    write(`Login URL: ${server.loginUrl()}\n`);
    const tokenPath = server.tokenFilePath();
    if (tokenPath !== null) {
      write(`Access token file: ${tokenPath} (owner-only permissions)\n`);
    } else {
      write("Access token: supplied by the configured server.token setting.\n");
    }
    options.onListening?.(port);
    const prune = (): void => {
      try {
        const retentionDays = database.withDatabase((connection) =>
          getRetentionDays(connection, config.storage.retentionDays),
        );
        const removed = database.prune(retentionDays);
        if (removed > 0) {
          server.stream.publish("system.retention_pruned", {
            records: removed,
            retentionDays,
          });
        }
      } catch {
        process.stderr.write("sentinel: retention pruning failed.\n");
      }
    };
    prune();
    pruneTimer = setInterval(prune, 3_600_000);
    pruneTimer.unref();
    const enabledSources = config.ingestion.sources.filter(
      ({ enabled }) => enabled,
    );
    if (enabledSources.length === 0) {
      write("No ingestion sources are enabled.\n");
    }
    const ingestion = runSources(
      config,
      database,
      detection,
      server.stream,
      controller.signal,
    ).catch(() => {
      process.stderr.write(
        "sentinel: ingestion workers stopped unexpectedly.\n",
      );
      shutdown();
    });
    await stopped;
    controller.abort();
    await server.close();
    await ingestion;
  } finally {
    if (pruneTimer !== undefined) clearInterval(pruneTimer);
    if (externalSignal === undefined) {
      process.off("SIGINT", shutdown);
      process.off("SIGTERM", shutdown);
    } else {
      externalSignal.removeEventListener("abort", shutdown);
    }
    controller.abort();
    await server.close();
    database.close();
  }
}

async function runSources(
  config: Config,
  database: EventDatabase,
  detection: DetectionEngine,
  stream: EventStream,
  signal: AbortSignal,
): Promise<void> {
  const checkpoints = new SqliteCheckpointStore(database);
  const workers = config.ingestion.sources
    .filter(({ enabled }) => enabled)
    .map((sourceConfig) => ({
      sourceConfig,
      source: createSourceReader(sourceConfig, checkpoints, {
        maxRecordBytes: config.ingestion.maxRecordBytes,
        maxFileBytes: config.ingestion.maxFileBytes,
      }),
      parser: parserForSource(sourceConfig.sourceType),
      retryAfter: 0,
    }));

  while (!signal.aborted) {
    for (const worker of workers) {
      if (signal.aborted) return;
      if (Date.now() < worker.retryAfter) continue;
      try {
        await ingestSource({
          source: worker.source,
          parser: worker.parser,
          database,
          detection,
          publish: (event, payload) => {
            stream.publish(event, payload);
          },
          queueHighWaterMark: config.ingestion.queueHighWaterMark,
          signal,
        });
      } catch (error: unknown) {
        if (
          signal.aborted ||
          (error instanceof Error && error.name === "AbortError")
        ) {
          return;
        }
        worker.retryAfter = Date.now() + 5_000;
        process.stderr.write(
          `sentinel: source ${JSON.stringify(worker.sourceConfig.name)} ingestion failed; retrying.\n`,
        );
      }
    }
    if (!(await delay(1_000, signal))) return;
  }
}

function delay(milliseconds: number, signal: AbortSignal): Promise<boolean> {
  if (signal.aborted) return Promise.resolve(false);
  return new Promise((resolve) => {
    const finish = (completed: boolean): void => {
      clearTimeout(timer);
      signal.removeEventListener("abort", aborted);
      resolve(completed);
    };
    const timer = setTimeout(() => {
      finish(true);
    }, milliseconds);
    const aborted = (): void => {
      finish(false);
    };
    signal.addEventListener("abort", aborted, { once: true });
    if (signal.aborted) aborted();
  });
}

function formatHost(host: string): string {
  return host.includes(":") ? `[${host}]` : host;
}
