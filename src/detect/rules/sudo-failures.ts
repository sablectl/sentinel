import type { DetectionRule, RuleMatch } from "../../types.js";
import {
  entityKey,
  groupEvents,
  latestCountWindow,
  match,
  numberThreshold,
} from "./shared.js";

const rule: DetectionRule = {
  id: "sudo.repeated_failures",
  version: 1,
  name: "Repeated sudo authentication failures",
  description:
    "Repeated sudo authentication failure indicators for one user or host.",
  severity: "medium",
  categories: ["authentication"],
  defaults: { count: 3, windowMs: 600_000 },
  evaluate(events, thresholds) {
    const count = numberThreshold(thresholds, "count", 3);
    const windowMs = numberThreshold(thresholds, "windowMs", 600_000);
    const groups = groupEvents(
      events.filter((event) => event.action === "sudo.authentication.failure"),
      (event) => {
        const entity = event.username ?? event.host;
        return entity === null ? null : `${event.host ?? ""}\0${entity}`;
      },
    );
    const matches: RuleMatch[] = [];

    for (const [entity, group] of groups) {
      const evidence = latestCountWindow(group, count, windowMs);
      if (evidence === null) continue;
      matches.push(
        match(
          rule,
          `${rule.id}:entity:${entityKey(entity)}`,
          evidence,
          thresholds,
          `${evidence.length} sudo authentication failures for one observed user or host occurred within ${windowMs} ms.`,
        ),
      );
    }
    return matches;
  },
};

export default rule;
