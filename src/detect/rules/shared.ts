import type {
  DetectionRule,
  RuleMatch,
  RuleThresholds,
  SecurityEvent,
} from "../../types.js";

export function numberThreshold(
  thresholds: RuleThresholds,
  key: string,
  fallback: number,
): number {
  const value = thresholds[key];
  return typeof value === "number" ? value : fallback;
}

export function stringThreshold(
  thresholds: RuleThresholds,
  key: string,
  fallback: string,
): string {
  const value = thresholds[key];
  return typeof value === "string" ? value : fallback;
}

export function orderedEvents(
  events: readonly SecurityEvent[],
): SecurityEvent[] {
  return [...events].sort(
    (left, right) =>
      left.timestamp - right.timestamp ||
      (left.id < right.id ? -1 : left.id > right.id ? 1 : 0),
  );
}

export function groupEvents(
  events: readonly SecurityEvent[],
  keyFor: (event: SecurityEvent) => string | null,
): Map<string, SecurityEvent[]> {
  const groups = new Map<string, SecurityEvent[]>();
  for (const event of events) {
    const key = keyFor(event);
    if (key === null) continue;
    const group = groups.get(key);
    if (group === undefined) groups.set(key, [event]);
    else group.push(event);
  }
  return new Map(
    [...groups.entries()]
      .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
      .map(([key, values]) => [key, orderedEvents(values)]),
  );
}

export function latestCountWindow(
  events: readonly SecurityEvent[],
  count: number,
  windowMs: number,
): SecurityEvent[] | null {
  const ordered = orderedEvents(events);
  let start = 0;
  let latestStart = -1;
  let latestEnd = -1;
  for (let end = 0; end < ordered.length; end += 1) {
    const current = ordered[end];
    if (current === undefined) continue;
    while (
      start < end &&
      current.timestamp - (ordered[start]?.timestamp ?? current.timestamp) >
        windowMs
    ) {
      start += 1;
    }
    if (end - start + 1 >= count) {
      latestStart = end - count + 1;
      latestEnd = end;
    }
  }
  return latestStart < 0 ? null : ordered.slice(latestStart, latestEnd + 1);
}

export function match(
  rule: DetectionRule,
  dedupKey: string,
  events: readonly SecurityEvent[],
  thresholds: RuleThresholds,
  rationale: string,
): RuleMatch {
  const evidence = orderedEvents(events);
  const timestamps = evidence.map(({ timestamp }) => timestamp);
  return {
    ruleId: rule.id,
    ruleVersion: rule.version,
    dedupKey,
    severity: rule.severity,
    rationale,
    thresholds,
    windowStart: Math.min(...timestamps),
    windowEnd: Math.max(...timestamps),
    eventIds: evidence.map(({ id }) => id),
  };
}

export function entityKey(value: string): string {
  return encodeURIComponent(value);
}

export function isAuthenticationFailure(event: SecurityEvent): boolean {
  return (
    event.category === "authentication" &&
    event.outcome === "failure" &&
    (event.action.startsWith("ssh.") || event.action.startsWith("pam."))
  );
}
