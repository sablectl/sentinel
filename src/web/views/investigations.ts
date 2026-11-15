import { api } from "../api.js";
import type { CorrelationField } from "../api-types.js";
import { filterBar } from "../components/filters.js";
import { errorState, loading, panel, section } from "../components/layout.js";
import { timeline } from "../components/timeline.js";
import { el, replaceChildren } from "../dom.js";
import { errorMessage, refreshOnStream, type View } from "./shared.js";

const FIELDS: readonly CorrelationField[] = [
  "ip",
  "username",
  "host",
  "category",
  "rule",
];
const WINDOWS: readonly { readonly value: string; readonly label: string }[] = [
  { value: "3600000", label: "1 hour" },
  { value: "21600000", label: "6 hours" },
  { value: "86400000", label: "24 hours" },
  { value: "604800000", label: "7 days" },
];

export function investigationsView(): View {
  let filters: Readonly<Record<string, string>> = {
    by: "ip",
    windowMs: "3600000",
  };
  let generation = 0;
  let disposed = false;
  const content = el("div", {}, loading("Loading correlated events"));
  const controls = filterBar(
    [
      {
        name: "by",
        label: "Group by shared attribute",
        value: "ip",
        options: FIELDS.map((value) => ({ value, label: value })),
      },
      { name: "value", label: "Specific value", value: "" },
      {
        name: "windowMs",
        label: "Time window",
        value: "3600000",
        options: WINDOWS,
      },
    ],
    (values) => {
      filters = values;
      void refresh();
    },
  );
  const root = section(
    "Investigations",
    el(
      "p",
      { className: "muted" },
      "Correlation groups events by shared attributes; a shared value does not establish identity or attribution.",
    ),
    controls,
    content,
  );

  const refresh = async (): Promise<void> => {
    const requestId = ++generation;
    try {
      const by = FIELDS.find((value) => value === filters["by"]) ?? "ip";
      const windowMs = Number(filters["windowMs"] ?? "3600000");
      const value = filters["value"]?.trim();
      const groups = await api.correlate({
        by,
        windowMs,
        limit: 100,
        ...(value === undefined || value.length === 0 ? {} : { value }),
      });
      if (disposed || requestId !== generation) return;
      replaceChildren(
        content,
        groups.length === 0
          ? el(
              "p",
              { className: "empty-state" },
              "No related events in this window.",
            )
          : el(
              "div",
              { className: "correlation-groups" },
              ...groups.map((group) =>
                panel(
                  `${group.by}: ${group.key}`,
                  el(
                    "p",
                    { className: "muted correlation-label" },
                    group.label,
                  ),
                  timeline(group.events),
                ),
              ),
            ),
      );
    } catch (error: unknown) {
      if (!disposed && requestId === generation) {
        replaceChildren(content, errorState(new Error(errorMessage(error))));
      }
    }
  };

  const offStream = refreshOnStream(() => {
    void refresh();
  }, ["event.created", "alert.updated"]);
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
