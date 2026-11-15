import { api } from "../api.js";
import type { Alert, RuleView } from "../api-types.js";
import { severityBadge } from "../components/severity.js";
import { table, type Column } from "../components/table.js";
import { errorState, loading, panel, section } from "../components/layout.js";
import { el, replaceChildren } from "../dom.js";
import { formatRelative } from "../format.js";
import { errorMessage, refreshOnStream, type View } from "./shared.js";

export function detectionsView(): View {
  const content = el("div", {}, loading("Loading detection rules"));
  const root = section(
    "Detections",
    el(
      "p",
      { className: "muted" },
      "Rule matches are indicators, not confirmation of compromise.",
    ),
    content,
  );
  let generation = 0;
  let disposed = false;

  const refresh = async (): Promise<void> => {
    const requestId = ++generation;
    try {
      const [rules, alertPage] = await Promise.all([
        api.rules(),
        api.alerts({ limit: 50 }),
      ]);
      if (disposed || generation !== requestId) return;
      const recent = table(
        "Recent detection-backed alerts",
        [
          { key: "rule", label: "Rule", render: (alert) => alert.ruleId },
          {
            key: "severity",
            label: "Severity",
            render: (alert) => severityBadge(alert.severity),
          },
          { key: "state", label: "State", render: (alert) => alert.state },
          {
            key: "last",
            label: "Last seen",
            render: (alert) => formatRelative(alert.lastSeen),
          },
        ] satisfies readonly Column<Alert>[],
        alertPage.alerts,
        "No detection matches have been recorded.",
      );
      replaceChildren(
        content,
        el(
          "div",
          { className: "rule-list" },
          ...rules.map((rule) => ruleCard(rule, refresh)),
        ),
        panel("Recent matches", recent),
      );
    } catch (error: unknown) {
      if (!disposed && generation === requestId) {
        replaceChildren(content, errorState(new Error(errorMessage(error))));
      }
    }
  };

  const offStream = refreshOnStream(() => {
    void refresh();
  }, ["rules.updated", "alert.updated"]);
  void refresh();
  return {
    root,
    dispose: () => {
      disposed = true;
      generation += 1;
      offStream();
    },
  };
}

function ruleCard(rule: RuleView, refresh: () => Promise<void>): HTMLElement {
  const status = el("p", { className: "form-status", role: "status" });
  const thresholds = el("form", { className: "threshold-form" });
  const fields: {
    readonly name: string;
    readonly input: HTMLInputElement;
    readonly value: number | string | boolean;
  }[] = [];

  for (const [name, value] of Object.entries(rule.thresholds)) {
    if (typeof value === "boolean") continue;
    const input = el("input", {
      name,
      type: typeof value === "number" ? "number" : "text",
      value: String(value),
      min: typeof value === "number" ? "0" : undefined,
      step: typeof value === "number" ? "1" : undefined,
      required: true,
    });
    fields.push({ name, input, value });
    thresholds.append(
      el("label", { className: "field" }, el("span", {}, name), input),
    );
  }
  const save = el(
    "button",
    { type: "submit", className: "button button-secondary" },
    "Save thresholds",
  );
  thresholds.append(save);
  thresholds.addEventListener("submit", (event) => {
    event.preventDefault();
    const updated: Record<string, number | string> = {};
    for (const field of fields) {
      const raw = field.input.value.trim();
      if (typeof field.value === "number") {
        const value = Number(raw);
        if (!Number.isSafeInteger(value)) {
          status.textContent = `${field.name} must be an integer.`;
          return;
        }
        updated[field.name] = value;
      } else {
        updated[field.name] = raw;
      }
    }
    save.disabled = true;
    status.textContent = "Saving rule configuration…";
    void api
      .configureRule(rule.id, { thresholds: updated })
      .then(() => {
        status.textContent = "Rule configuration saved.";
        return refresh();
      })
      .catch((error: unknown) => {
        status.textContent = errorMessage(error);
      })
      .finally(() => {
        save.disabled = false;
      });
  });

  const toggle = el(
    "button",
    { type: "button", className: "button button-secondary" },
    rule.enabled ? "Disable rule" : "Enable rule",
  );
  toggle.addEventListener("click", () => {
    toggle.disabled = true;
    void api
      .configureRule(rule.id, { enabled: !rule.enabled })
      .then(() => refresh())
      .catch((error: unknown) => {
        status.textContent = errorMessage(error);
      })
      .finally(() => {
        toggle.disabled = false;
      });
  });

  return el(
    "article",
    { className: "rule-card" },
    el(
      "div",
      { className: "rule-heading" },
      el(
        "div",
        {},
        el("h2", {}, rule.name),
        el("p", { className: "muted" }, rule.description),
      ),
      severityBadge(rule.severity),
    ),
    el(
      "p",
      { className: "rule-meta" },
      `${rule.id} · ${rule.categories.join(", ")} · version ${rule.version}`,
    ),
    toggle,
    thresholds,
    status,
  );
}
