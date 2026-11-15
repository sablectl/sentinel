import type { DetectionRule, RuleMatch, SecurityEvent } from "../../types.js";
import { entityKey, groupEvents, match, numberThreshold } from "./shared.js";

const rule: DetectionRule = {
  id: "ssh.failure_then_success",
  version: 1,
  name: "SSH failure followed by success",
  description:
    "A successful SSH authentication follows one or more failures for the same observed IP and username.",
  severity: "high",
  categories: ["authentication"],
  defaults: { windowMs: 900_000 },
  evaluate(events, thresholds) {
    const windowMs = numberThreshold(thresholds, "windowMs", 900_000);
    const candidates = events.filter(
      (event) =>
        event.category === "authentication" &&
        event.sourceIp !== null &&
        event.username !== null &&
        event.action.startsWith("ssh.") &&
        (event.outcome === "failure" || event.outcome === "success"),
    );
    const groups = groupEvents(candidates, (event) =>
      event.sourceIp === null || event.username === null
        ? null
        : `${event.sourceIp}\0${event.username}`,
    );
    const matches: RuleMatch[] = [];

    for (const group of groups.values()) {
      let latest: {
        readonly key: string;
        readonly evidence: SecurityEvent[];
      } | null = null;
      const failures = group.filter((event) => event.outcome === "failure");
      const successes = group
        .filter((event) => event.outcome === "success")
        .reverse();
      for (const success of successes) {
        if (success.sourceIp === null || success.username === null) continue;
        const start = lowerBound(failures, success.timestamp - windowMs);
        const end = lowerBound(failures, success.timestamp);
        const lastFailure = failures[end - 1];
        if (
          start >= end ||
          lastFailure === undefined ||
          success.timestamp - lastFailure.timestamp > windowMs
        ) {
          continue;
        }
        latest = {
          key: `${rule.id}:ip:${entityKey(success.sourceIp)}:user:${entityKey(success.username)}`,
          evidence: [...failures.slice(start, end), success],
        };
        break;
      }
      if (latest === null) continue;
      matches.push(
        match(
          rule,
          latest.key,
          latest.evidence,
          thresholds,
          `An SSH success followed authentication failure indicators for the same observed IP and username within ${windowMs} ms.`,
        ),
      );
    }
    return matches;
  },
};

export default rule;

function lowerBound(
  events: readonly SecurityEvent[],
  timestamp: number,
): number {
  let low = 0;
  let high = events.length;
  while (low < high) {
    const middle = Math.floor((low + high) / 2);
    const event = events[middle];
    if (event !== undefined && event.timestamp < timestamp) low = middle + 1;
    else high = middle;
  }
  return low;
}
