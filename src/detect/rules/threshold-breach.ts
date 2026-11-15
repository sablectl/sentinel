import type { DetectionRule, EventCategory, RuleMatch } from "../../types.js";
import {
  entityKey,
  groupEvents,
  latestCountWindow,
  match,
  numberThreshold,
  stringThreshold,
} from "./shared.js";

const CATEGORIES: readonly EventCategory[] = [
  "authentication",
  "privilege",
  "session",
  "account",
  "other",
];

const rule: DetectionRule = {
  id: "event.threshold_breach",
  version: 1,
  name: "Configured event threshold breach",
  description:
    "A configured category exceeds its event-count threshold for one shared entity.",
  severity: "medium",
  categories: CATEGORIES,
  defaults: { count: 25, windowMs: 300_000, category: "authentication" },
  evaluate(events, thresholds) {
    const count = numberThreshold(thresholds, "count", 25);
    const windowMs = numberThreshold(thresholds, "windowMs", 300_000);
    const category = stringThreshold(thresholds, "category", "authentication");
    const groups = groupEvents(
      events.filter((event) => event.category === category),
      (event) => event.sourceIp ?? event.username ?? event.host ?? event.source,
    );
    const matches: RuleMatch[] = [];

    for (const [entity, group] of groups) {
      const evidence = latestCountWindow(group, count, windowMs);
      if (evidence === null) continue;
      matches.push(
        match(
          rule,
          `${rule.id}:category:${category}:entity:${entityKey(entity)}`,
          evidence,
          thresholds,
          `${evidence.length} ${category} events for one shared entity occurred within ${windowMs} ms.`,
        ),
      );
    }
    return matches;
  },
};

export default rule;
