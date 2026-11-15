import { performance } from "node:perf_hooks";
import type {
  ParseResult,
  Parser,
  ParserContext,
  RawRecord,
  SourceReader,
} from "../types.js";
import type { DetectionEngine } from "../detect/engine.js";
import { DetectionWindowLimitError } from "../detect/engine.js";
import { parseFailure } from "../parse/common.js";
import { BoundedQueue } from "./queue.js";
import { FileTooLargeError } from "./reader-file.js";
import type { EventDatabase } from "../store/database.js";
import {
  insertEvents,
  recordParseFailure,
  getEventTimestampRange,
  setSourceStatus,
  type TimestampRange,
} from "../store/queries.js";

export interface IngestOptions {
  readonly source: SourceReader;
  readonly parser: Parser;
  readonly database: EventDatabase;
  readonly queueHighWaterMark: number;
  readonly signal: AbortSignal;
  readonly parserContext?: ParserContext;
  readonly detection?: DetectionEngine;
  readonly publish?: (event: string, payload: unknown) => void;
}

export interface IngestResult {
  readonly records: number;
  readonly ignored: number;
  readonly eventsInserted: number;
  readonly duplicates: number;
  readonly parseFailures: number;
  readonly detectionMatches: number;
  readonly detectionEvaluations: number;
  readonly detectionDurationMs: number;
  readonly lastEventTimestamp: number | null;
}

export async function ingestSource(
  options: IngestOptions,
): Promise<IngestResult> {
  const { source, database, signal } = options;
  const queue = new BoundedQueue<RawRecord>(options.queueHighWaterMark);
  const result = {
    records: 0,
    ignored: 0,
    eventsInserted: 0,
    duplicates: 0,
    parseFailures: 0,
    detectionMatches: 0,
    detectionEvaluations: 0,
    detectionDurationMs: 0,
    lastEventTimestamp: null as number | null,
  };

  database.withDatabase((connection) => {
    setSourceStatus(connection, source.name, "reading");
  });

  let producer: Promise<void> | undefined;
  try {
    const parserContext =
      options.parserContext ??
      (await observeTimestampRange(source, options.parser, database, signal));
    producer = (async (): Promise<void> => {
      try {
        for await (const record of source.read(signal)) {
          await queue.push(record, signal);
        }
        queue.close();
      } catch (error: unknown) {
        queue.close(toError(error));
      }
    })();

    for await (const record of queue) {
      result.records += 1;
      if (record.empty) {
        source.commit(record);
        result.ignored += 1;
        continue;
      }

      const parsed = parseSafely(options.parser, record, parserContext);
      if (!parsed.ok) {
        database.withDatabase((connection) =>
          recordParseFailure(connection, parsed.failure, record),
        );
        source.commit(record);
        result.parseFailures += 1;
        options.publish?.("source.health", {
          source: source.name,
          offset: record.offset,
          lineNumber: record.lineNumber,
          parserFailure: parsed.failure.reason,
        });
        continue;
      }

      const written = database.withDatabase((connection) =>
        insertEvents(connection, [parsed.event]),
      );
      const detection =
        options.detection === undefined
          ? null
          : measureDetection(
              options.detection,
              parsed.event.timestamp,
              parsed.event.id,
            );
      source.commit(record);
      result.eventsInserted += written.inserted;
      result.duplicates += written.duplicates;
      if (written.inserted > 0) {
        options.publish?.("event.created", parsed.event);
      }
      if (detection !== null) {
        result.detectionMatches += detection.recordedMatches;
        result.detectionEvaluations += 1;
        result.detectionDurationMs += detection.durationMs;
        for (const alert of detection.alerts) {
          options.publish?.("alert.updated", alert);
        }
      }
      result.lastEventTimestamp =
        result.lastEventTimestamp === null
          ? parsed.event.timestamp
          : Math.max(result.lastEventTimestamp, parsed.event.timestamp);
    }
    await producer;
    database.withDatabase((connection) => {
      setSourceStatus(connection, source.name, "ready");
    });
    return result;
  } catch (error: unknown) {
    queue.close(toError(error));
    await producer;
    const message = sourceFailureMessage(error);
    const aborted = error instanceof Error && error.name === "AbortError";
    database.withDatabase((connection) => {
      setSourceStatus(
        connection,
        source.name,
        aborted ? "idle" : "error",
        aborted ? undefined : message,
      );
    });
    throw error;
  }
}

function measureDetection(
  engine: DetectionEngine,
  timestamp: number,
  eventId: string,
): ReturnType<DetectionEngine["evaluateAt"]> & { readonly durationMs: number } {
  const start = performance.now();
  const result = engine.evaluateAt(timestamp, eventId);
  return { ...result, durationMs: performance.now() - start };
}

function parseSafely(
  parser: Parser,
  record: RawRecord,
  context: ParserContext = {},
): ParseResult {
  try {
    return parser(record, context);
  } catch {
    return parseFailure(record, "parser could not process the record");
  }
}

async function observeTimestampRange(
  source: SourceReader,
  parser: Parser,
  database: EventDatabase,
  signal: AbortSignal,
): Promise<ParserContext> {
  if (source.sourceType !== "authlog" && source.sourceType !== "syslog") {
    return {};
  }

  const storedRange = database.withDatabase((connection) =>
    getEventTimestampRange(connection, source.name),
  );
  const referenceTime =
    storedRange === null
      ? Date.now()
      : storedRange.start +
        Math.floor((storedRange.end - storedRange.start) / 2);
  let start = storedRange?.start ?? null;
  let end = storedRange?.end ?? null;

  for await (const record of source.read(signal)) {
    if (record.empty || record.oversized) continue;
    const parsed = parseSafely(parser, record, { referenceTime });
    if (!parsed.ok) continue;
    start =
      start === null
        ? parsed.event.timestamp
        : Math.min(start, parsed.event.timestamp);
    end =
      end === null
        ? parsed.event.timestamp
        : Math.max(end, parsed.event.timestamp);
  }

  if (start === null || end === null) return {};
  const observedRange: TimestampRange = { start, end };
  return { observedRange };
}

function toError(error: unknown): Error {
  return error instanceof Error ? error : new Error("source ingestion failed");
}

function sourceFailureMessage(error: unknown): string {
  if (error instanceof FileTooLargeError) return error.message;
  if (error instanceof DetectionWindowLimitError) return error.message;
  if (error instanceof Error && error.name === "AbortError") {
    return "source ingestion interrupted";
  }
  return "source read, parser or store operation failed";
}
