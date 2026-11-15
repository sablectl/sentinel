import type { DetectionRule, RuleMatch } from "../../types.js";
import {
  entityKey,
  groupEvents,
  isAuthenticationFailure,
  match,
  numberThreshold,
} from "./shared.js";

const rule: DetectionRule = {
  id: "ssh.username_spray",
  version: 1,
  name: "SSH username spray indicator",
  description: "One source IP attempts authentication with many usernames.",
  severity: "high",
  categories: ["authentication"],
  defaults: { count: 8, windowMs: 600_000 },
  evaluate(events, thresholds) {
    const count = numberThreshold(thresholds, "count", 8);
    const windowMs = numberThreshold(thresholds, "windowMs", 600_000);
    const groups = groupEvents(
      events.filter(
        (event) =>
          isAuthenticationFailure(event) &&
          event.action.startsWith("ssh.") &&
          event.sourceIp !== null &&
          event.username !== null,
      ),
      (event) => event.sourceIp,
    );
    const matches: RuleMatch[] = [];

    for (const [ip, group] of groups) {
      let start = 0;
      let latestStart = -1;
      let latestEnd = -1;
      let latestUserCount = 0;
      const userCounts = new Map<string, number>();
      for (let end = 0; end < group.length; end += 1) {
        const current = group[end];
        if (current === undefined) continue;
        if (current.username !== null) {
          userCounts.set(
            current.username,
            (userCounts.get(current.username) ?? 0) + 1,
          );
        }
        while (
          start < end &&
          current.timestamp - (group[start]?.timestamp ?? current.timestamp) >
            windowMs
        ) {
          const expiredUsername = group[start]?.username;
          if (expiredUsername !== undefined && expiredUsername !== null) {
            const remaining = (userCounts.get(expiredUsername) ?? 1) - 1;
            if (remaining === 0) userCounts.delete(expiredUsername);
            else userCounts.set(expiredUsername, remaining);
          }
          start += 1;
        }
        if (userCounts.size >= count) {
          latestStart = start;
          latestEnd = end;
          latestUserCount = userCounts.size;
        }
      }
      if (latestStart < 0) continue;
      matches.push(
        match(
          rule,
          `${rule.id}:ip:${entityKey(ip)}`,
          group.slice(latestStart, latestEnd + 1),
          thresholds,
          `${latestUserCount} distinct usernames had SSH authentication failures from one source IP within ${windowMs} ms.`,
        ),
      );
    }
    return matches;
  },
};

export default rule;
