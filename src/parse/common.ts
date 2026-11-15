import { isIP } from "node:net";
import type {
  EventCategory,
  EventOutcome,
  ParseResult,
  ParserContext,
  RawRecord,
  SecurityEvent,
  Severity,
} from "../types.js";
import { createEventId } from "./ids.js";
import { escapeOriginal, sanitiseMessage } from "./sanitise.js";

const MONTHS: Readonly<Record<string, number>> = {
  Jan: 0,
  Feb: 1,
  Mar: 2,
  Apr: 3,
  May: 4,
  Jun: 5,
  Jul: 6,
  Aug: 7,
  Sep: 8,
  Oct: 9,
  Nov: 10,
  Dec: 11,
};

export interface EventDraft {
  readonly timestamp: number;
  readonly host: string | null;
  readonly category: EventCategory;
  readonly action: string;
  readonly outcome: EventOutcome;
  readonly severity: Severity;
  readonly username: string | null;
  readonly sourceIp: string | null;
  readonly process: {
    readonly name: string;
    readonly pid: number | null;
  } | null;
  readonly message: string;
  readonly metadata?: Readonly<Record<string, string | number | boolean>>;
  readonly parserVersion: string;
  readonly inferred?: readonly string[];
}

export interface AuthIndicators {
  readonly category: EventCategory;
  readonly action: string;
  readonly outcome: EventOutcome;
  readonly severity: Severity;
  readonly username: string | null;
  readonly sourceIp: string | null;
}

export function parserReferenceTime(context: ParserContext): number {
  const range = context.observedRange;
  if (
    range !== undefined &&
    Number.isSafeInteger(range.start) &&
    Number.isSafeInteger(range.end) &&
    range.start >= 0 &&
    range.end >= range.start
  ) {
    return range.start + Math.floor((range.end - range.start) / 2);
  }
  return context.referenceTime ?? context.ingestedAt ?? Date.now();
}

export function parseFailure(record: RawRecord, reason: string): ParseResult {
  return {
    ok: false,
    failure: {
      source: record.source,
      offset: record.offset,
      lineNumber: record.lineNumber,
      reason,
      sample: sanitiseMessage(record.content).slice(0, 256),
    },
  };
}

export function oversizedFailure(record: RawRecord): ParseResult | null {
  return record.oversized
    ? parseFailure(record, "record exceeds the configured size limit")
    : null;
}

export function normaliseEvent(
  record: RawRecord,
  draft: EventDraft,
  context: ParserContext = {},
): ParseResult {
  if (!Number.isSafeInteger(draft.timestamp) || draft.timestamp < 0) {
    return parseFailure(
      record,
      "timestamp is outside the supported epoch range",
    );
  }
  if (!Number.isFinite(new Date(draft.timestamp).getTime())) {
    return parseFailure(
      record,
      "timestamp is outside the supported calendar range",
    );
  }
  const ingestedAt = context.ingestedAt ?? Date.now();
  if (!Number.isSafeInteger(ingestedAt) || ingestedAt < 0) {
    return parseFailure(record, "ingestion timestamp is invalid");
  }

  const message = sanitiseMessage(draft.message);
  const action = sanitiseMessage(draft.action).slice(0, 256);
  if (action.length === 0)
    return parseFailure(record, "event action is empty after sanitisation");
  const host = sanitiseNullable(draft.host, 255);
  const username = sanitiseNullable(draft.username, 256);
  const processName =
    draft.process === null ? null : sanitiseNullable(draft.process.name, 256);
  const process =
    draft.process === null || processName === null
      ? null
      : { name: processName, pid: draft.process.pid };
  if (draft.sourceIp !== null && validIpAddress(draft.sourceIp) === null) {
    return parseFailure(record, "event source IP is invalid");
  }

  const metadata: Record<string, string | number | boolean> = {};
  let transformed =
    message !== draft.message ||
    action !== draft.action ||
    host !== draft.host ||
    username !== draft.username ||
    processName !== (draft.process?.name ?? null) ||
    record.content !== sanitiseMessage(record.content);
  for (const [rawKey, rawValue] of Object.entries(draft.metadata ?? {})) {
    const key = sanitiseMessage(rawKey).slice(0, 128);
    if (
      key.length === 0 ||
      key === "__proto__" ||
      key === "constructor" ||
      key === "prototype" ||
      key === "originalEscaped"
    ) {
      transformed = true;
      continue;
    }
    if (typeof rawValue === "string") {
      const value = sanitiseMessage(rawValue).slice(0, 2048);
      if (key !== rawKey || value !== rawValue) transformed = true;
      metadata[key] = value;
    } else {
      if (key !== rawKey) transformed = true;
      metadata[key] = rawValue;
    }
  }
  if (transformed) {
    metadata["originalEscaped"] = escapeOriginal(record.content);
  }

  const event: Omit<SecurityEvent, "id" | "ingestedAt"> = {
    timestamp: draft.timestamp,
    source: record.source,
    sourceType: record.sourceType,
    host,
    category: draft.category,
    action,
    outcome: draft.outcome,
    severity: draft.severity,
    username,
    sourceIp: draft.sourceIp,
    process,
    message,
    metadata,
    parserVersion: draft.parserVersion,
    inferred: draft.inferred ?? [],
  };

  return {
    ok: true,
    event: {
      id: createEventId(record, event),
      ...event,
      ingestedAt,
    },
  };
}

export function parseYearlessTimestamp(
  value: string,
  referenceTime = Date.now(),
): { readonly timestamp: number; readonly inferred: true } | null {
  const match =
    /^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})$/.exec(
      value.trim(),
    );
  if (match === null) return null;

  const monthName = match[1];
  const month = monthName === undefined ? undefined : MONTHS[monthName];
  const day = Number(match[2]);
  const hour = Number(match[3]);
  const minute = Number(match[4]);
  const second = Number(match[5]);
  if (
    month === undefined ||
    day < 1 ||
    day > 31 ||
    hour > 23 ||
    minute > 59 ||
    second > 59 ||
    !Number.isSafeInteger(referenceTime)
  ) {
    return null;
  }

  const referenceYear = new Date(referenceTime).getUTCFullYear();
  const candidates = [referenceYear - 1, referenceYear, referenceYear + 1]
    .map((year) => {
      const timestamp = Date.UTC(year, month, day, hour, minute, second);
      const date = new Date(timestamp);
      if (
        date.getUTCFullYear() !== year ||
        date.getUTCMonth() !== month ||
        date.getUTCDate() !== day
      ) {
        return null;
      }
      return timestamp;
    })
    .filter((timestamp): timestamp is number => timestamp !== null);
  const timestamp = candidates.sort(
    (left, right) =>
      Math.abs(left - referenceTime) - Math.abs(right - referenceTime) ||
      left - right,
  )[0];
  return timestamp === undefined ? null : { timestamp, inferred: true };
}

export function parseExplicitTimestamp(value: string): number | null {
  const match =
    /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(Z|[+-](\d{2}):(\d{2}))$/.exec(
      value,
    );
  if (match === null) return null;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  const offsetHour = match[8] === undefined ? 0 : Number(match[8]);
  const offsetMinute = match[9] === undefined ? 0 : Number(match[9]);
  if (
    month < 1 ||
    month > 12 ||
    day < 1 ||
    hour > 23 ||
    minute > 59 ||
    second > 59 ||
    offsetHour > 23 ||
    offsetMinute > 59
  ) {
    return null;
  }
  const calendar = new Date(0);
  calendar.setUTCFullYear(year, month - 1, day);
  calendar.setUTCHours(hour, minute, second, 0);
  if (
    calendar.getUTCFullYear() !== year ||
    calendar.getUTCMonth() !== month - 1 ||
    calendar.getUTCDate() !== day
  ) {
    return null;
  }
  const timestamp = Date.parse(value);
  return Number.isSafeInteger(timestamp) && timestamp >= 0 ? timestamp : null;
}

export function classifyAuthMessage(
  application: string,
  message: string,
): AuthIndicators {
  const normalizedApplication = application.toLowerCase();
  const sshSuccess =
    /Accepted\s+\S+\s+for\s+(?:invalid user\s+)?([^\s]+)\s+from\s+([^\s]+)/i.exec(
      message,
    );
  if (sshSuccess !== null) {
    return authIndicators(
      "ssh.authentication.success",
      "success",
      sshSuccess[1],
      sshSuccess[2],
    );
  }

  const sshFailure =
    /Failed\s+\S+\s+for\s+(?:invalid user\s+)?([^\s]+)\s+from\s+([^\s]+)/i.exec(
      message,
    );
  if (sshFailure !== null) {
    return authIndicators(
      "ssh.authentication.failure",
      "failure",
      sshFailure[1],
      sshFailure[2],
    );
  }

  const invalidUser = /Invalid user\s+([^\s]+)\s+from\s+([^\s]+)/i.exec(
    message,
  );
  if (invalidUser !== null) {
    return authIndicators(
      "ssh.invalid_user",
      "failure",
      invalidUser[1],
      invalidUser[2],
    );
  }

  const username = /\buser(?:name)?[= :]+['"]?([^\s;'"),]+)/i.exec(
    message,
  )?.[1];
  const sourceIp = extractSourceIp(message);
  if (
    /authentication failure|authentication failed|failed password/i.test(
      message,
    )
  ) {
    const sudo =
      normalizedApplication.includes("sudo") || /\bsudo\b/i.test(message);
    return {
      category: "authentication",
      action: sudo
        ? "sudo.authentication.failure"
        : "pam.authentication.failure",
      outcome: "failure",
      severity: "medium",
      username: username ?? null,
      sourceIp,
    };
  }
  if (/session opened for user/i.test(message)) {
    return {
      category: "session",
      action: "session.opened",
      outcome: "success",
      severity: "info",
      username: username ?? null,
      sourceIp,
    };
  }
  if (/session closed for user/i.test(message)) {
    return {
      category: "session",
      action: "session.closed",
      outcome: "unknown",
      severity: "info",
      username: username ?? null,
      sourceIp,
    };
  }
  if (normalizedApplication.startsWith("sudo") || /\bsudo:/i.test(message)) {
    return {
      category: "privilege",
      action: "sudo.command",
      outcome: "unknown",
      severity: "low",
      username: username ?? null,
      sourceIp,
    };
  }
  return {
    category: "other",
    action: `${normalizedApplication || "syslog"}.message`,
    outcome: "unknown",
    severity: "info",
    username: username ?? null,
    sourceIp,
  };
}

export function severityForPriority(priority: number | null): Severity {
  if (priority === null) return "info";
  if (priority <= 2) return "critical";
  if (priority === 3) return "high";
  if (priority === 4) return "medium";
  if (priority === 5) return "low";
  return "info";
}

export function validOutcome(value: unknown): value is EventOutcome {
  return value === "success" || value === "failure" || value === "unknown";
}

export function validCategory(value: unknown): value is EventCategory {
  return (
    value === "authentication" ||
    value === "privilege" ||
    value === "session" ||
    value === "account" ||
    value === "other"
  );
}

export function validSeverity(value: unknown): value is Severity {
  return (
    value === "info" ||
    value === "low" ||
    value === "medium" ||
    value === "high" ||
    value === "critical"
  );
}

export function validIpAddress(value: string): string | null {
  return isIP(value) === 0 ? null : value;
}

function sanitiseNullable(
  value: string | null,
  maxLength: number,
): string | null {
  if (value === null) return null;
  const sanitised = sanitiseMessage(value).slice(0, maxLength);
  return sanitised.length === 0 ? null : sanitised;
}

function authIndicators(
  action: string,
  outcome: EventOutcome,
  rawUsername: string | undefined,
  rawIp: string | undefined,
): AuthIndicators {
  return {
    category: "authentication",
    action,
    outcome,
    severity: outcome === "failure" ? "medium" : "info",
    username: rawUsername ?? null,
    sourceIp: rawIp === undefined ? null : validIpAddress(rawIp),
  };
}

function extractSourceIp(message: string): string | null {
  const candidate = /\bfrom\s+([^\s]+)/i.exec(message)?.[1];
  return candidate === undefined ? null : validIpAddress(candidate);
}
