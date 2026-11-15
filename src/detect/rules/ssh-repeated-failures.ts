import type { DetectionRule, RuleMatch } from "../../types.js";
import {
  entityKey,
  groupEvents,
  isAuthenticationFailure,
  latestCountWindow,
  match,
  numberThreshold,
} from "./shared.js";

const rule: DetectionRule = {
  id: "ssh.repeated_failures",
  version: 1,
  name: "Repeated SSH authentication failures",
  description:
    "Repeated SSH authentication failure indicators from one source IP.",
  severity: "high",
  categories: ["authentication"],
  defaults: { count: 5, windowMs: 300_000 },
  evaluate(events, thresholds) {
    const count = numberThreshold(thresholds, "count", 5);
    const windowMs = numberThreshold(thresholds, "windowMs", 300_000);
    const groups = groupEvents(
      events.filter(
        (event) =>
          isAuthenticationFailure(event) &&
          event.action.startsWith("ssh.") &&
          event.sourceIp !== null,
      ),
      (event) => event.sourceIp,
    );
    const matches: RuleMatch[] = [];

    for (const [ip, group] of groups) {
      const evidence = latestCountWindow(group, count, windowMs);
      if (evidence !== null) {
        matches.push(
          match(
            rule,
            `${rule.id}:ip:${entityKey(ip)}`,
            evidence,
            thresholds,
            `${evidence.length} SSH authentication failures from one source IP occurred within ${windowMs} ms.`,
          ),
        );
      }
    }
    return matches;
  },
};

export default rule;
