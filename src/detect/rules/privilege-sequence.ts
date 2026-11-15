import type { DetectionRule, RuleMatch } from "../../types.js";
import { entityKey, groupEvents, match, numberThreshold } from "./shared.js";

const rule: DetectionRule = {
  id: "privilege.sudo_session_sequence",
  version: 1,
  name: "Sudo and privileged-session sequence",
  description:
    "A sudo command indicator is followed by a session-open indicator on the same host.",
  severity: "medium",
  categories: ["privilege", "session"],
  defaults: { windowMs: 600_000 },
  evaluate(events, thresholds) {
    const windowMs = numberThreshold(thresholds, "windowMs", 600_000);
    const candidates = events.filter(
      (event) =>
        event.host !== null &&
        (event.action === "sudo.command" || event.action === "session.opened"),
    );
    const groups = groupEvents(candidates, (event) => event.host);
    const matches: RuleMatch[] = [];

    for (const [host, group] of groups) {
      let latestSudo: (typeof group)[number] | undefined;
      let latestPair: [(typeof group)[number], (typeof group)[number]] | null =
        null;
      for (const event of group) {
        if (event.action === "sudo.command") {
          latestSudo = event;
          continue;
        }
        if (
          event.action === "session.opened" &&
          latestSudo !== undefined &&
          event.timestamp > latestSudo.timestamp &&
          event.timestamp - latestSudo.timestamp <= windowMs
        ) {
          latestPair = [latestSudo, event];
        }
      }
      if (latestPair === null) continue;
      matches.push(
        match(
          rule,
          `${rule.id}:host:${entityKey(host)}`,
          latestPair,
          thresholds,
          `Sudo-command and session-open indicators occurred on one host within ${windowMs} ms; the shared host is not attribution.`,
        ),
      );
    }
    return matches;
  },
};

export default rule;
