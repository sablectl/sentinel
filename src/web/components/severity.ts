import type { Severity } from "../api-types.js";
import { el } from "../dom.js";

export function severityBadge(severity: Severity): HTMLElement {
  return el(
    "span",
    {
      className: `severity severity-${severity}`,
      "aria-label": `Severity: ${severity}`,
    },
    severity.toUpperCase(),
  );
}
