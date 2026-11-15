import type { ParseResult, ParserContext, RawRecord } from "../types.js";
import {
  classifyAuthMessage,
  normaliseEvent,
  oversizedFailure,
  parseFailure,
  parserReferenceTime,
  parseYearlessTimestamp,
} from "./common.js";

const PARSER_VERSION = "authlog/1";
const PREFIX =
  /^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+.+$/;

export function parseAuthlog(
  record: RawRecord,
  context: ParserContext = {},
): ParseResult {
  const sizeFailure = oversizedFailure(record);
  if (sizeFailure !== null) return sizeFailure;
  if (record.sourceType !== "authlog") {
    return parseFailure(
      record,
      "record does not belong to an authentication log source",
    );
  }

  const prefix = PREFIX.exec(record.content);
  if (prefix === null)
    return parseFailure(record, "unsupported authentication log record");
  const match = /^(\S+\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.+)$/.exec(
    record.content,
  );
  if (match === null)
    return parseFailure(record, "authentication log header is malformed");

  const timestamp = parseYearlessTimestamp(
    match[1] ?? "",
    parserReferenceTime(context),
  );
  if (timestamp === null) {
    return parseFailure(record, "authentication log timestamp is invalid");
  }

  const host = match[2] ?? "";
  const body = match[3] ?? "";
  const application = /^([^\s:[\]]+)(?:\[(\d+)\])?:\s*(.*)$/.exec(body);
  const program = application?.[1] ?? "authlog";
  const pidValue = application?.[2];
  const pid = pidValue === undefined ? null : Number(pidValue);
  const message = application?.[3] ?? body;
  const indicators = classifyAuthMessage(program, message);

  return normaliseEvent(
    record,
    {
      timestamp: timestamp.timestamp,
      host,
      category: indicators.category,
      action: indicators.action,
      outcome: indicators.outcome,
      severity: indicators.severity,
      username: indicators.username,
      sourceIp: indicators.sourceIp,
      process: { name: program, pid: Number.isSafeInteger(pid) ? pid : null },
      message,
      metadata: { program },
      parserVersion: PARSER_VERSION,
      inferred: ["timestamp.year"],
    },
    context,
  );
}
