import type { DetectionRule, RuleMatch } from "../../types.js";
import {
  entityKey,
  groupEvents,
  latestCountWindow,
  match,
  numberThreshold,
} from "./shared.js";

const rule: DetectionRule = {
  id: "auth.burst",
  version: 1,
  name: "Authentication event burst",
  description: "A high rate of authentication events shares one source IP.",
  severity: "medium",
  categories: ["authentication"],
  defaults: { count: 20, windowMs: 300_000 },
  evaluate(events, thresholds) {
    const count = numberThreshold(thresholds, "count", 20);
    const windowMs = numberThreshold(thresholds, "windowMs", 300_000);
    const groups = groupEvents(
      events.filter(
        (event) =>
          event.category === "authentication" && event.sourceIp !== null,
      ),
      (event) => event.sourceIp,
    );
    const matches: RuleMatch[] = [];
    for (const [ip, group] of groups) {
      const evidence = latestCountWindow(group, count, windowMs);
      if (evidence === null) continue;
      matches.push(
        match(
          rule,
          `${rule.id}:ip:${entityKey(ip)}`,
          evidence,
          thresholds,
          `${evidence.length} authentication events from one source IP occurred within ${windowMs} ms.`,
        ),
      );
    }
    return matches;
  },
};

export default rule;
