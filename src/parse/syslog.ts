import type { ParseResult, ParserContext, RawRecord } from "../types.js";
import {
  classifyAuthMessage,
  normaliseEvent,
  oversizedFailure,
  parseExplicitTimestamp,
  parseFailure,
  parserReferenceTime,
  parseYearlessTimestamp,
  severityForPriority,
} from "./common.js";

const PARSER_VERSION = "syslog/1";

export function parseSyslog(
  record: RawRecord,
  context: ParserContext = {},
): ParseResult {
  const sizeFailure = oversizedFailure(record);
  if (sizeFailure !== null) return sizeFailure;
  if (record.sourceType !== "syslog") {
    return parseFailure(record, "record does not belong to a syslog source");
  }

  const rfc5424 = parseRfc5424(record.content);
  if (rfc5424 !== null) {
    const timestamp = parseExplicitTimestamp(rfc5424.timestamp);
    if (timestamp === null)
      return parseFailure(record, "RFC 5424 timestamp is invalid");
    return makeEvent(record, rfc5424, timestamp, [], context);
  }

  const rfc3164 = parseRfc3164(record.content);
  if (rfc3164 === null)
    return parseFailure(record, "unsupported syslog record");
  const timestamp = parseYearlessTimestamp(
    rfc3164.timestamp,
    parserReferenceTime(context),
  );
  if (timestamp === null)
    return parseFailure(record, "RFC 3164 timestamp is invalid");
  return makeEvent(
    record,
    rfc3164,
    timestamp.timestamp,
    ["timestamp.year"],
    context,
  );
}

interface SyslogFields {
  readonly timestamp: string;
  readonly host: string | null;
  readonly application: string;
  readonly processId: number | null;
  readonly priority: number | null;
  readonly structuredData?: string;
  readonly message: string;
}

function parseRfc5424(value: string): SyslogFields | null {
  const match =
    /^<(\d{1,3})>(\d{1,3}) (\S+) (\S+) (\S+) (\S+) (\S+) (\[(?:[^\\\]]|\\.)*\]|-)(?: (.*))?$/.exec(
      value,
    );
  if (match === null) return null;
  const priorityValue = parsePriority(match[1]);
  if (
    priorityValue === null ||
    match[2] === undefined ||
    !/^\d{1,3}$/.test(match[2]) ||
    Number(match[2]) < 1
  ) {
    return null;
  }
  const processValue = match[6];
  return {
    timestamp: match[3] ?? "",
    host: nullableHeaderValue(match[4]),
    application: nullableHeaderValue(match[5]) ?? "syslog",
    processId: parseProcessId(processValue),
    priority: priorityValue,
    ...(match[8] !== undefined && match[8] !== "-"
      ? { structuredData: match[8] }
      : {}),
    message: match[9] ?? "",
  };
}

function parseRfc3164(value: string): SyslogFields | null {
  const match =
    /^(?:<(\d{1,3})>)?((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^\s:[\]]+)(?:\[(\d+)\])?:\s*(.*)$/.exec(
      value,
    );
  if (match === null) return null;
  const priority = match[1] === undefined ? null : parsePriority(match[1]);
  if (match[1] !== undefined && priority === null) return null;
  return {
    timestamp: match[2] ?? "",
    host: match[3] === "-" ? null : (match[3] ?? null),
    application: match[4] ?? "syslog",
    processId: parseProcessId(match[5]),
    priority,
    message: match[6] ?? "",
  };
}

function makeEvent(
  record: RawRecord,
  fields: SyslogFields,
  timestamp: number,
  inferred: readonly string[],
  context: ParserContext,
): ParseResult {
  const indicators = classifyAuthMessage(fields.application, fields.message);
  const process =
    fields.application === "syslog"
      ? null
      : { name: fields.application, pid: fields.processId };
  const metadata: Record<string, string | number | boolean> = {};
  if (fields.priority !== null) metadata["priority"] = fields.priority;
  if (fields.structuredData !== undefined) {
    metadata["structuredData"] = fields.structuredData;
  }
  return normaliseEvent(
    record,
    {
      timestamp,
      host: fields.host,
      category: indicators.category,
      action: indicators.action,
      outcome: indicators.outcome,
      severity:
        indicators.outcome === "failure" || indicators.outcome === "success"
          ? indicators.severity
          : severityForPriority(
              fields.priority === null ? null : fields.priority % 8,
            ),
      username: indicators.username,
      sourceIp: indicators.sourceIp,
      process,
      message: fields.message,
      metadata,
      parserVersion: PARSER_VERSION,
      inferred,
    },
    context,
  );
}

function parsePriority(value: string | undefined): number | null {
  if (value === undefined || !/^\d{1,3}$/.test(value)) return null;
  const parsed = Number(value);
  return parsed <= 191 ? parsed : null;
}

function parseProcessId(value: string | undefined): number | null {
  if (value === undefined || value === "-" || !/^\d+$/.test(value)) return null;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) ? parsed : null;
}

function nullableHeaderValue(value: string | undefined): string | null {
  return value === undefined || value === "-" ? null : value;
}
