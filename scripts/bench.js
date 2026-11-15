import { mkdtemp, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { performance } from "node:perf_hooks";
import { EventDatabase } from "../dist/store/database.js";
import { DetectionEngine } from "../dist/detect/engine.js";
import { SqliteCheckpointStore } from "../dist/ingest/checkpoint.js";
import { ingestSource } from "../dist/ingest/pipeline.js";
import { createNdjsonSource } from "../dist/ingest/source-ndjson.js";
import { parseNdjson } from "../dist/parse/ndjson.js";

const eventCount = parseCount(process.argv[2] ?? "1000");
const directory = await mkdtemp(join(tmpdir(), "sentinel-bench-"));
let database;
let sampler;
const memoryStartRssBytes = process.memoryUsage().rss;
let peakRss = memoryStartRssBytes;

try {
  const baseTime = Date.now() - 3_600_000;
  const lines = Array.from({ length: eventCount }, (_, index) => {
    const outcome = index % 20 === 0 ? "success" : "failure";
    const action =
      outcome === "success"
        ? "ssh.authentication.success"
        : "ssh.authentication.failure";
    return JSON.stringify({
      timestamp: new Date(baseTime + index * 500).toISOString(),
      source: "synthetic-bench",
      host: `node-${index % 4}`,
      category: "authentication",
      action,
      outcome,
      severity: outcome === "failure" ? "medium" : "info",
      username: `operator-${index % 8}`,
      sourceIp: `203.0.113.${(index % 24) + 1}`,
      message: `synthetic benchmark authentication record ${index}`,
      metadata: { synthetic: true, sequence: index },
    });
  });
  const corpus = `${lines.join("\n")}\n`;
  const sourcePath = join(directory, "synthetic.ndjson");
  const databasePath = join(directory, "events.sqlite");
  await writeFile(sourcePath, corpus, { encoding: "utf8", mode: 0o600 });
  const sourceBytes = (await stat(sourcePath)).size;
  database = new EventDatabase({ path: databasePath });
  const detection = new DetectionEngine(database, {
    maxWindowEvents: Math.max(2_000, eventCount),
    maxWindowBytes: 268_435_456,
  });
  const source = createNdjsonSource({
    name: "synthetic-bench",
    path: sourcePath,
    checkpoints: new SqliteCheckpointStore(database),
    maxRecordBytes: 65_536,
    maxFileBytes: Math.max(268_435_456, sourceBytes + 1),
  });
  sampler = setInterval(() => {
    peakRss = Math.max(peakRss, process.memoryUsage().rss);
  }, 10);

  const started = performance.now();
  const result = await ingestSource({
    source,
    parser: parseNdjson,
    database,
    detection,
    queueHighWaterMark: 512,
    signal: new AbortController().signal,
    publish: () => {
      peakRss = Math.max(peakRss, process.memoryUsage().rss);
    },
  });
  const elapsedMs = performance.now() - started;
  clearInterval(sampler);
  sampler = undefined;
  peakRss = Math.max(peakRss, process.memoryUsage().rss);
  const counts = database.counts();
  database.close();
  database = undefined;
  const databaseBytes = await totalDatabaseBytes(databasePath);

  process.stdout.write(
    `${JSON.stringify(
      {
        syntheticEventsRequested: eventCount,
        recordsRead: result.records,
        eventsInserted: result.eventsInserted,
        parserFailures: result.parseFailures,
        eventParseRate:
          result.records === 0 ? 0 : result.eventsInserted / result.records,
        inputBytes: sourceBytes,
        elapsedMs: Number(elapsedMs.toFixed(2)),
        eventsPerSecond:
          elapsedMs === 0
            ? 0
            : Number(((result.eventsInserted / elapsedMs) * 1000).toFixed(2)),
        detectionEvaluations: result.detectionEvaluations,
        detectionDurationMs: Number(result.detectionDurationMs.toFixed(2)),
        meanDetectionLatencyMs:
          result.detectionEvaluations === 0
            ? 0
            : Number(
                (
                  result.detectionDurationMs / result.detectionEvaluations
                ).toFixed(4),
              ),
        memoryStartRssBytes,
        memoryPeakRssBytes: peakRss,
        databaseBytes,
        databaseBytesPerEvent:
          counts.events === 0
            ? 0
            : Number((databaseBytes / counts.events).toFixed(2)),
      },
      null,
      2,
    )}\n`,
  );
} finally {
  if (sampler !== undefined) clearInterval(sampler);
  database?.close();
  await rm(directory, { recursive: true, force: true });
}

function parseCount(value) {
  if (!/^\d+$/.test(value)) {
    throw new Error("event count must be an integer between 1 and 10000");
  }
  const count = Number(value);
  if (!Number.isSafeInteger(count) || count < 1 || count > 10_000) {
    throw new Error("event count must be an integer between 1 and 10000");
  }
  return count;
}

async function totalDatabaseBytes(path) {
  let total = 0;
  for (const suffix of ["", "-wal", "-shm"]) {
    try {
      total += (await stat(`${path}${suffix}`)).size;
    } catch {
      // SQLite removes sidecars when it closes cleanly.
    }
  }
  return total;
}
