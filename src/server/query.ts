import { isIP } from "node:net";
import type {
  AlertState,
  CorrelationField,
  EventCategory,
  EventOutcome,
  Severity,
} from "../types.js";
import type { AlertFilters } from "../alerts/store.js";
import type { EventQuery } from "../store/event-queries.js";

export type Parsed<T> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly error: string };

const RANGES: Readonly<Record<string, number>> = {
  "15m": 900_000,
  "1h": 3_600_000,
  "6h": 21_600_000,
  "24h": 86_400_000,
  "7d": 604_800_000,
};
const DEFAULT_RANGE_MS = 86_400_000;
const EVENT_SORTS: readonly EventQuery["sort"][] = [
  "timestamp",
  "severity",
  "source",
  "category",
  "outcome",
];
const EVENT_DIRECTIONS: readonly EventQuery["direction"][] = ["asc", "desc"];
const EVENT_CATEGORIES: readonly EventCategory[] = [
  "authentication",
  "privilege",
  "session",
  "account",
  "other",
];
const EVENT_OUTCOMES: readonly EventOutcome[] = [
  "success",
  "failure",
  "unknown",
];
const SEVERITIES: readonly Severity[] = [
  "info",
  "low",
  "medium",
  "high",
  "critical",
];
const ALERT_STATES: readonly AlertState[] = [
  "open",
  "acknowledged",
  "resolved",
];
const CORRELATION_FIELDS: readonly CorrelationField[] = [
  "ip",
  "username",
  "host",
  "category",
  "rule",
];

export type ParsedEventQuery = EventQuery;

export interface ParsedCorrelationQuery {
  readonly by: CorrelationField;
  readonly windowMs: number;
  readonly limit: number;
  readonly endTime: number;
  readonly value: string | undefined;
}

export function parseEventQuery(
  params: URLSearchParams,
  now: number,
): Parsed<ParsedEventQuery> {
  const unknown = rejectUnknown(params, [
    "range",
    "from",
    "to",
    "page",
    "limit",
    "source",
    "username",
    "search",
    "ip",
    "category",
    "outcome",
    "severity",
    "sort",
    "direction",
  ]);
  if (unknown !== null) return fail(unknown);
  const range = single(params, "range");
  if (!range.ok) return range;
  const from = integerParameter(params, "from", 0, Number.MAX_SAFE_INTEGER);
  if (!from.ok) return from;
  const to = integerParameter(params, "to", 0, Number.MAX_SAFE_INTEGER);
  if (!to.ok) return to;
  if (
    range.value !== null &&
    (from.value !== undefined || to.value !== undefined)
  ) {
    return fail("range cannot be combined with from or to");
  }

  let start = from.value;
  const end = to.value ?? now;
  if (start === undefined && range.value !== null) {
    const duration = RANGES[range.value];
    if (duration === undefined) {
      return fail(`range must be one of ${Object.keys(RANGES).join(", ")}`);
    }
    start = Math.max(0, now - duration);
  }
  start ??= Math.max(0, now - DEFAULT_RANGE_MS);
  if (start > end) return fail("from must not be later than to");

  const page = integerParameter(params, "page", 1, 100_000);
  if (!page.ok) return page;
  const limit = integerParameter(params, "limit", 1, 100);
  if (!limit.ok) return limit;
  const source = boundedText(params, "source", 128);
  if (!source.ok) return source;
  const username = boundedText(params, "username", 256);
  if (!username.ok) return username;
  const search = boundedText(params, "search", 256);
  if (!search.ok) return search;
  const sourceIp = boundedText(params, "ip", 64);
  if (!sourceIp.ok) return sourceIp;
  if (sourceIp.value !== undefined && isIP(sourceIp.value) === 0) {
    return fail("ip must be a valid IPv4 or IPv6 address");
  }
  const category = enumParameter(params, "category", EVENT_CATEGORIES);
  if (!category.ok) return category;
  const outcome = enumParameter(params, "outcome", EVENT_OUTCOMES);
  if (!outcome.ok) return outcome;
  const severity = enumParameter(params, "severity", SEVERITIES);
  if (!severity.ok) return severity;
  const sort = enumParameter(params, "sort", EVENT_SORTS);
  if (!sort.ok) return sort;
  const direction = enumParameter(params, "direction", EVENT_DIRECTIONS);
  if (!direction.ok) return direction;

  return ok({
    from: start,
    to: end,
    page: page.value ?? 1,
    limit: limit.value ?? 100,
    ...(source.value === undefined ? {} : { source: source.value }),
    ...(category.value === undefined ? {} : { category: category.value }),
    ...(outcome.value === undefined ? {} : { outcome: outcome.value }),
    ...(severity.value === undefined ? {} : { severity: severity.value }),
    ...(username.value === undefined ? {} : { username: username.value }),
    ...(sourceIp.value === undefined ? {} : { sourceIp: sourceIp.value }),
    ...(search.value === undefined ? {} : { search: search.value }),
    sort: sort.value ?? "timestamp",
    direction: direction.value ?? "desc",
  });
}

export function parseAlertQuery(params: URLSearchParams): Parsed<AlertFilters> {
  const unknown = rejectUnknown(params, ["state", "severity", "limit", "page"]);
  if (unknown !== null) return fail(unknown);
  const state = enumParameter(params, "state", ALERT_STATES);
  if (!state.ok) return state;
  const severity = enumParameter(params, "severity", SEVERITIES);
  if (!severity.ok) return severity;
  const limit = integerParameter(params, "limit", 1, 100);
  if (!limit.ok) return limit;
  const page = integerParameter(params, "page", 1, 100_000);
  if (!page.ok) return page;
  return ok({
    ...(state.value === undefined ? {} : { state: state.value }),
    ...(severity.value === undefined ? {} : { severity: severity.value }),
    limit: limit.value ?? 100,
    offset: ((page.value ?? 1) - 1) * (limit.value ?? 100),
  });
}

export function parseCorrelationQuery(
  params: URLSearchParams,
  now: number,
): Parsed<ParsedCorrelationQuery> {
  const unknown = rejectUnknown(params, [
    "by",
    "windowMs",
    "limit",
    "to",
    "value",
  ]);
  if (unknown !== null) return fail(unknown);
  const by = enumParameter(params, "by", CORRELATION_FIELDS);
  if (!by.ok) return by;
  const windowMs = integerParameter(params, "windowMs", 1_000, 604_800_000);
  if (!windowMs.ok) return windowMs;
  const limit = integerParameter(params, "limit", 1, 1_000);
  if (!limit.ok) return limit;
  const endTime = integerParameter(params, "to", 0, Number.MAX_SAFE_INTEGER);
  if (!endTime.ok) return endTime;
  const value = boundedText(params, "value", 256);
  if (!value.ok) return value;
  return ok({
    by: by.value ?? "ip",
    windowMs: windowMs.value ?? 3_600_000,
    limit: limit.value ?? 100,
    endTime: endTime.value ?? now,
    value: value.value,
  });
}

function integerParameter(
  params: URLSearchParams,
  name: string,
  minimum: number,
  maximum: number,
): Parsed<number | undefined> {
  const raw = single(params, name);
  if (!raw.ok) return raw;
  if (raw.value === null) return ok(undefined);
  if (!/^\d{1,16}$/.test(raw.value))
    return fail(`${name} must be a non-negative integer`);
  const value = Number(raw.value);
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    return fail(`${name} must be between ${minimum} and ${maximum}`);
  }
  return ok(value);
}

function boundedText(
  params: URLSearchParams,
  name: string,
  maximum: number,
): Parsed<string | undefined> {
  const value = single(params, name);
  if (!value.ok) return value;
  if (value.value === null) return ok(undefined);
  if (
    value.value.length > maximum ||
    value.value.length === 0 ||
    /\p{Cc}/u.test(value.value)
  ) {
    return fail(`${name} has an invalid value or length`);
  }
  return ok(value.value);
}

function enumParameter<T extends string>(
  params: URLSearchParams,
  name: string,
  values: readonly T[],
): Parsed<T | undefined> {
  const value = single(params, name);
  if (!value.ok) return value;
  if (value.value === null) return ok(undefined);
  const selected = values.find((candidate) => candidate === value.value);
  return selected === undefined
    ? fail(`${name} must be one of ${values.join(", ")}`)
    : ok(selected);
}

function rejectUnknown(
  params: URLSearchParams,
  allowed: readonly string[],
): string | null {
  for (const key of params.keys()) {
    if (!allowed.includes(key)) return `unknown query parameter '${key}'`;
  }
  return null;
}

function single(params: URLSearchParams, name: string): Parsed<string | null> {
  const values = params.getAll(name);
  if (values.length > 1) return fail(`${name} must not be repeated`);
  return ok(values[0] ?? null);
}

function fail<T>(error: string): Parsed<T> {
  return { ok: false, error };
}

function ok<T>(value: T): Parsed<T> {
  return { ok: true, value };
}
