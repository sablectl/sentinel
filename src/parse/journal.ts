import type { ParseResult, ParserContext, RawRecord } from "../types.js";
import {
  classifyAuthMessage,
  normaliseEvent,
  oversizedFailure,
  parseFailure,
  severityForPriority,
} from "./common.js";

const PARSER_VERSION = "journal-export/1";

export function parseJournal(
  record: RawRecord,
  context: ParserContext = {},
): ParseResult {
  const sizeFailure = oversizedFailure(record);
  if (sizeFailure !== null) return sizeFailure;
  if (record.sourceType !== "journal") {
    return parseFailure(record, "record does not belong to a journal source");
  }

  const fields: Record<string, string> = {};
  for (const line of record.content.split("\n")) {
    const separator = line.indexOf("=");
    if (separator <= 0) {
      return parseFailure(
        record,
        "journal record contains an unsupported binary field",
      );
    }
    const key = line.slice(0, separator);
    if (!/^[A-Z0-9_]{1,128}$/.test(key)) {
      return parseFailure(
        record,
        "journal record contains an invalid field name",
      );
    }
    fields[key] = line.slice(separator + 1).replace(/\r$/, "");
  }

  const realtime = fields["__REALTIME_TIMESTAMP"];
  if (realtime === undefined || !/^\d+$/.test(realtime)) {
    return parseFailure(
      record,
      "journal record has no valid realtime timestamp",
    );
  }
  const microseconds = Number(realtime);
  const timestamp = Math.floor(microseconds / 1000);
  if (!Number.isSafeInteger(microseconds) || !Number.isSafeInteger(timestamp)) {
    return parseFailure(
      record,
      "journal realtime timestamp is outside the supported range",
    );
  }

  const message = fields["MESSAGE"];
  if (message === undefined)
    return parseFailure(record, "journal record has no MESSAGE field");
  const program =
    fields["SYSLOG_IDENTIFIER"] ?? fields["_COMM"] ?? "systemd-journal";
  const indicators = classifyAuthMessage(program, message);
  const priority = parsePriority(fields["PRIORITY"]);
  const processName = fields["_COMM"] ?? fields["SYSLOG_IDENTIFIER"];
  const pid = parseProcessId(fields["_PID"]);
  const metadata: Record<string, string | number | boolean> = {};
  for (const key of [
    "_UID",
    "_SYSTEMD_UNIT",
    "_TRANSPORT",
    "SYSLOG_FACILITY",
  ]) {
    const value = fields[key];
    if (value !== undefined) metadata[key] = value;
  }
  if (priority !== null) metadata["priority"] = priority;

  return normaliseEvent(
    record,
    {
      timestamp,
      host: fields["_HOSTNAME"] ?? null,
      category: indicators.category,
      action: indicators.action,
      outcome: indicators.outcome,
      severity:
        indicators.outcome === "failure" || indicators.outcome === "success"
          ? indicators.severity
          : severityForPriority(priority),
      username: indicators.username,
      sourceIp: indicators.sourceIp,
      process: processName === undefined ? null : { name: processName, pid },
      message,
      metadata,
      parserVersion: PARSER_VERSION,
    },
    context,
  );
}

function parsePriority(value: string | undefined): number | null {
  if (value === undefined || !/^\d$/.test(value)) return null;
  const priority = Number(value);
  return priority <= 7 ? priority : null;
}

function parseProcessId(value: string | undefined): number | null {
  if (value === undefined || !/^\d+$/.test(value)) return null;
  const pid = Number(value);
  return Number.isSafeInteger(pid) ? pid : null;
}
