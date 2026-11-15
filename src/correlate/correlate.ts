import type { CorrelationField, SecurityEvent } from "../types.js";
import { orderedEvents } from "../detect/rules/shared.js";

export const CORRELATION_LABEL = "Shared-attribute grouping; not attribution.";

export interface CorrelationOptions {
  readonly by: CorrelationField;
  readonly windowMs: number;
  readonly limit: number;
  readonly endTime?: number;
  readonly ruleIdsByEvent?: ReadonlyMap<string, readonly string[]>;
}

export interface CorrelationGroup {
  readonly by: CorrelationField;
  readonly key: string;
  readonly label: typeof CORRELATION_LABEL;
  readonly events: readonly SecurityEvent[];
}

export function correlate(
  events: readonly SecurityEvent[],
  options: CorrelationOptions,
): readonly CorrelationGroup[] {
  if (
    !Number.isSafeInteger(options.windowMs) ||
    options.windowMs < 1_000 ||
    options.windowMs > 604_800_000 ||
    !Number.isSafeInteger(options.limit) ||
    options.limit < 1 ||
    options.limit > 1_000 ||
    events.length > 10_000
  ) {
    throw new RangeError(
      "correlation window, result limit or input size is invalid",
    );
  }

  const ordered = orderedEvents(events);
  if (ordered.length === 0) return [];
  const endTime = options.endTime ?? ordered.at(-1)?.timestamp;
  if (endTime === undefined || !Number.isSafeInteger(endTime) || endTime < 0) {
    throw new RangeError("correlation endTime is invalid");
  }
  const startTime = Math.max(0, endTime - options.windowMs);
  const groups = new Map<string, SecurityEvent[]>();

  for (const event of ordered) {
    if (event.timestamp < startTime || event.timestamp > endTime) continue;
    for (const key of correlationKeys(event, options)) {
      const current = groups.get(key);
      if (current === undefined) groups.set(key, [event]);
      else current.push(event);
    }
  }

  return [...groups.entries()]
    .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
    .slice(0, options.limit)
    .map(([key, group]) => ({
      by: options.by,
      key,
      label: CORRELATION_LABEL,
      events: orderedEvents(group),
    }));
}

function correlationKeys(
  event: SecurityEvent,
  options: CorrelationOptions,
): string[] {
  switch (options.by) {
    case "ip":
      return event.sourceIp === null ? [] : [event.sourceIp];
    case "username":
      return event.username === null ? [] : [event.username];
    case "host":
      return event.host === null ? [] : [event.host];
    case "category":
      return [event.category];
    case "rule":
      return [...new Set(options.ruleIdsByEvent?.get(event.id) ?? [])].sort();
  }
}
