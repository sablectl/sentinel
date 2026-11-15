import type { SecurityEvent } from "../api-types.js";
import { el } from "../dom.js";
import { formatTimestamp } from "../format.js";
import { severityBadge } from "./severity.js";

export function timeline(events: readonly SecurityEvent[]): HTMLElement {
  if (events.length === 0)
    return el("p", { className: "empty-state" }, "No related events.");
  const ordered = [...events].sort(
    (left, right) =>
      left.timestamp - right.timestamp || (left.id < right.id ? -1 : 1),
  );
  return el(
    "ol",
    { className: "timeline", "aria-label": "Correlated event timeline" },
    ...ordered.map((event) =>
      el(
        "li",
        {},
        el(
          "time",
          { dateTime: new Date(event.timestamp).toISOString() },
          formatTimestamp(event.timestamp),
        ),
        severityBadge(event.severity),
        el("strong", {}, event.action),
        el("span", {}, event.message),
        el(
          "small",
          {},
          `${event.source} · ${event.host ?? "Host not recorded"}`,
        ),
      ),
    ),
  );
}
