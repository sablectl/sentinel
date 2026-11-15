import type { DetectionRule, RuleMatch } from "../../types.js";
import { entityKey, match, numberThreshold } from "./shared.js";

const rule: DetectionRule = {
  id: "auth.out_of_hours",
  version: 1,
  name: "Out-of-hours authentication success",
  description:
    "A successful authentication indicator occurs outside the configured UTC hours.",
  severity: "low",
  categories: ["authentication"],
  defaults: { startHour: 22, endHour: 6 },
  evaluate(events, thresholds) {
    const startHour = numberThreshold(thresholds, "startHour", 22);
    const endHour = numberThreshold(thresholds, "endHour", 6);
    const matches: RuleMatch[] = [];
    for (const event of events) {
      if (event.category !== "authentication" || event.outcome !== "success") {
        continue;
      }
      const hour = new Date(event.timestamp).getUTCHours();
      const outsideHours =
        startHour > endHour
          ? hour >= startHour || hour < endHour
          : hour < startHour || hour >= endHour;
      if (!outsideHours) continue;
      const principal =
        event.username ?? event.sourceIp ?? event.host ?? event.source;
      matches.push(
        match(
          rule,
          `${rule.id}:entity:${entityKey(`${principal}:${event.host ?? ""}`)}`,
          [event],
          thresholds,
          `A successful authentication indicator occurred at ${String(hour).padStart(2, "0")}:00 UTC, outside ${startHour}:00–${endHour}:00 UTC.`,
        ),
      );
    }
    return matches;
  },
};

export default rule;
