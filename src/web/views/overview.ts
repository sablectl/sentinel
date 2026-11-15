import { api } from "../api.js";
import type { Alert, SecurityEvent } from "../api-types.js";
import { button, el, replaceChildren } from "../dom.js";
import { formatCount, formatRelative, formatTimestamp } from "../format.js";
import { severityBadge } from "../components/severity.js";
import { table, type Column } from "../components/table.js";
import {
  errorState,
  loading,
  metric,
  panel,
  section,
} from "../components/layout.js";
import {
  errorMessage,
  refreshOnStream,
  showEventDetail,
  type View,
} from "./shared.js";

export function overviewView(): View {
  const content = el("div", {}, loading());
  const refreshButton = button("Refresh", () => void refresh(), {
    className: "button button-secondary",
  });
  const root = section(
    "Overview",
    el(
      "div",
      { className: "toolbar-row" },
      el(
        "p",
        { className: "muted" },
        "Security activity from the local event store.",
      ),
      refreshButton,
    ),
    content,
  );
  let generation = 0;
  let disposed = false;

  const refresh = async (): Promise<void> => {
    const requestId = ++generation;
    try {
      const overview = await api.overview();
      if (disposed || requestId !== generation) return;
      const metrics = el(
        "div",
        { className: "metrics" },
        metric("Events", formatCount(overview.totals.events)),
        metric("Active alerts", formatCount(overview.activeAlerts)),
        metric("Parser failures", formatCount(overview.totals.parseFailures)),
        metric("Sources", formatCount(overview.totals.sources)),
      );
      const alertColumns: readonly Column<Alert>[] = [
        {
          key: "severity",
          label: "Severity",
          render: (alert) => severityBadge(alert.severity),
        },
        { key: "rule", label: "Rule", render: (alert) => alert.ruleId },
        { key: "state", label: "State", render: (alert) => alert.state },
        {
          key: "occurrences",
          label: "Occurrences",
          render: (alert) => formatCount(alert.occurrences),
        },
        {
          key: "last-seen",
          label: "Last seen",
          render: (alert) => formatRelative(alert.lastSeen),
        },
      ];
      const eventColumns: readonly Column<SecurityEvent>[] = [
        {
          key: "time",
          label: "Timestamp (UTC)",
          render: (event) => formatTimestamp(event.timestamp),
        },
        {
          key: "severity",
          label: "Severity",
          render: (event) => severityBadge(event.severity),
        },
        { key: "action", label: "Action", render: (event) => event.action },
        { key: "source", label: "Source", render: (event) => event.source },
        {
          key: "detail",
          label: "Detail",
          render: (event) =>
            button("Inspect", () => void showEventDetail(event.id), {
              className: "button button-secondary",
            }),
        },
      ];
      const severityRows = overview.severity.map(({ severity, count }) => ({
        severity,
        count,
      }));
      const severityTable = table(
        "Open and acknowledged alerts by severity",
        [
          {
            key: "severity",
            label: "Severity",
            render: (row) => severityBadge(row.severity),
          },
          {
            key: "count",
            label: "Alerts",
            render: (row) => formatCount(row.count),
          },
        ],
        severityRows,
        "No unresolved alerts.",
      );
      const sourceHealth = table(
        "Ingestion health",
        [
          { key: "source", label: "Source", render: (source) => source.name },
          { key: "status", label: "Status", render: (source) => source.status },
          {
            key: "last-seen",
            label: "Last event",
            render: (source) => formatRelative(source.lastSeen),
          },
          {
            key: "errors",
            label: "Errors",
            render: (source) => formatCount(source.errorCount),
          },
          {
            key: "last-error",
            label: "Last error",
            render: (source) => source.lastError ?? "None",
          },
        ],
        overview.ingestionHealth,
        "No ingestion sources have reported data.",
      );
      replaceChildren(
        content,
        metrics,
        el(
          "div",
          { className: "grid" },
          panel("Severity distribution", severityTable),
          panel("Ingestion health", sourceHealth),
        ),
        panel(
          "Recent alerts",
          table(
            "Recent alerts",
            alertColumns,
            overview.recentAlerts,
            "No active alerts.",
          ),
        ),
        panel(
          "Recent events",
          table(
            "Recent events",
            eventColumns,
            overview.recentEvents,
            "No events recorded.",
          ),
        ),
        el(
          "p",
          { className: "muted updated-at" },
          `Updated ${formatTimestamp(overview.generatedAt)}.`,
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
  }, ["event.created", "alert.updated", "source.health"]);
  void refresh();
  return {
    root,
    dispose: () => {
      disposed = true;
      offStream();
    },
  };
}
