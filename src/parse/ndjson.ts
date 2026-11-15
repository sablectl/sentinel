import type { ParseResult, ParserContext, RawRecord } from "../types.js";
import {
  normaliseEvent,
  oversizedFailure,
  parseExplicitTimestamp,
  parseFailure,
  validCategory,
  validOutcome,
  validSeverity,
  validIpAddress,
} from "./common.js";

const PARSER_VERSION = "ndjson/1";

export function parseNdjson(
  record: RawRecord,
  context: ParserContext = {},
): ParseResult {
  const sizeFailure = oversizedFailure(record);
  if (sizeFailure !== null) return sizeFailure;
  if (record.sourceType !== "ndjson") {
    return parseFailure(record, "record does not belong to an NDJSON source");
  }

  let value: unknown;
  try {
    value = JSON.parse(record.content) as unknown;
  } catch {
    return parseFailure(record, "NDJSON record is not valid JSON");
  }
  if (!isRecord(value))
    return parseFailure(record, "NDJSON record must be a JSON object");

  const timestamp = parseTimestamp(value["timestamp"]);
  if (timestamp === null) {
    return parseFailure(
      record,
      "NDJSON timestamp must be epoch milliseconds or ISO 8601",
    );
  }
  const action = value["action"];
  if (
    typeof action !== "string" ||
    action.trim().length === 0 ||
    action.length > 256
  ) {
    return parseFailure(
      record,
      "NDJSON action must be a non-empty string of at most 256 characters",
    );
  }

  const category = parseEnum(value["category"], validCategory, "other");
  const outcome = parseEnum(value["outcome"], validOutcome, "unknown");
  const severity = parseEnum(value["severity"], validSeverity, "info");
  if (category === null || outcome === null || severity === null) {
    return parseFailure(
      record,
      "NDJSON category, outcome or severity is invalid",
    );
  }

  const host = optionalString(value, "host");
  const username = optionalString(value, "username");
  const sourceIp = optionalString(value, "sourceIp");
  if (host === false || username === false || sourceIp === false) {
    return parseFailure(
      record,
      "NDJSON host, username or sourceIp must be a string or null",
    );
  }
  const validatedIp = sourceIp === null ? null : validIpAddress(sourceIp);
  if (sourceIp !== null && validatedIp === null) {
    return parseFailure(record, "NDJSON sourceIp is not a valid IP address");
  }

  const process = parseProcess(value["process"]);
  if (process === false)
    return parseFailure(record, "NDJSON process has an invalid shape");
  const metadata = parseMetadata(value["metadata"]);
  if (metadata === null)
    return parseFailure(record, "NDJSON metadata must contain scalar values");

  const message = value["message"];
  if (
    message !== undefined &&
    message !== null &&
    typeof message !== "string"
  ) {
    return parseFailure(
      record,
      "NDJSON message must be a string when supplied",
    );
  }

  return normaliseEvent(
    record,
    {
      timestamp,
      host,
      category,
      action: action.trim(),
      outcome,
      severity,
      username,
      sourceIp: validatedIp,
      process,
      message: typeof message === "string" ? message : record.content,
      metadata,
      parserVersion: PARSER_VERSION,
    },
    context,
  );
}

function parseTimestamp(value: unknown): number | null {
  if (typeof value === "number") {
    return Number.isSafeInteger(value) && value >= 0 ? value : null;
  }
  return typeof value === "string" ? parseExplicitTimestamp(value) : null;
}

function parseEnum<T extends string>(
  value: unknown,
  validate: (candidate: unknown) => candidate is T,
  fallback: T,
): T | null {
  if (value === undefined || value === null) return fallback;
  return validate(value) ? value : null;
}

function optionalString(
  input: Record<string, unknown>,
  key: string,
): string | null | false {
  const value = input[key];
  if (value === undefined || value === null) return null;
  if (typeof value !== "string" || value.length > 1024) return false;
  return value.length === 0 ? null : value;
}

function parseProcess(
  value: unknown,
): { readonly name: string; readonly pid: number | null } | null | false {
  if (value === undefined || value === null) return null;
  if (
    !isRecord(value) ||
    typeof value["name"] !== "string" ||
    value["name"].length > 256
  ) {
    return false;
  }
  const pid = value["pid"];
  if (pid === undefined || pid === null)
    return { name: value["name"], pid: null };
  if (typeof pid !== "number" || !Number.isSafeInteger(pid) || pid < 0)
    return false;
  return { name: value["name"], pid };
}

function parseMetadata(
  value: unknown,
): Readonly<Record<string, string | number | boolean>> | null {
  if (value === undefined || value === null) return {};
  if (!isRecord(value) || Object.keys(value).length > 100) return null;
  const result: Record<string, string | number | boolean> = {};
  for (const key of Object.keys(value).sort()) {
    if (
      key.length === 0 ||
      key.length > 128 ||
      key === "__proto__" ||
      key === "constructor" ||
      key === "prototype"
    ) {
      return null;
    }
    const item = value[key];
    if (
      typeof item !== "string" &&
      typeof item !== "number" &&
      typeof item !== "boolean"
    ) {
      return null;
    }
    if (typeof item === "string" && item.length > 2048) return null;
    if (typeof item === "number" && !Number.isFinite(item)) return null;
    result[key] = item;
  }
  return result;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
