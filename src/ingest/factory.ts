import type { SourceConfig } from "../config/config.js";
import type { CheckpointRepository, Parser } from "../types.js";
import { parseAuthlog } from "../parse/authlog.js";
import { parseJournal } from "../parse/journal.js";
import { parseNdjson } from "../parse/ndjson.js";
import { parseSyslog } from "../parse/syslog.js";
import { createAuthlogSource } from "./source-authlog.js";
import { createJournalSource } from "./source-journal.js";
import { createNdjsonSource } from "./source-ndjson.js";
import { createSyslogSource } from "./source-syslog.js";
import type { FileTailReader } from "./reader-file.js";

export interface SourceLimits {
  readonly maxRecordBytes: number;
  readonly maxFileBytes: number;
}

export function createSourceReader(
  source: SourceConfig,
  checkpoints: CheckpointRepository,
  limits: SourceLimits,
): FileTailReader {
  const options = {
    name: source.name,
    path: source.path,
    checkpoints,
    ...limits,
  };
  switch (source.sourceType) {
    case "authlog":
      return createAuthlogSource(options);
    case "journal":
      return createJournalSource(options);
    case "ndjson":
      return createNdjsonSource(options);
    case "syslog":
      return createSyslogSource(options);
  }
}

export function parserForSource(
  sourceType: SourceConfig["sourceType"],
): Parser {
  switch (sourceType) {
    case "authlog":
      return parseAuthlog;
    case "journal":
      return parseJournal;
    case "ndjson":
      return parseNdjson;
    case "syslog":
      return parseSyslog;
  }
}
