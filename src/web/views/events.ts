import { api } from "../api.js";
import type { EventFilters } from "../api.js";
import type { EventCategory, SecurityEvent, Severity } from "../api-types.js";
import { filterBar } from "../components/filters.js";
import { panel, section, errorState, loading } from "../components/layout.js";
import { severityBadge } from "../components/severity.js";
import { table, type Column } from "../components/table.js";
import { button, el, replaceChildren } from "../dom.js";
import { formatRelative, formatTimestamp } from "../format.js";
import {
  errorMessage,
  refreshOnStream,
  showEventDetail,
  type View,
} from "./shared.js";

const SEVERITIES: readonly Severity[] = [
  "info",
  "low",
  "medium",
  "high",
  "critical",
];
const CATEGORIES: readonly EventCategory[] = [
  "authentication",
  "privilege",
  "session",
  "account",
  "other",
];

export function eventsView(): View {
  const filters = filterBar(
    [
      {
        name: "range",
        label: "Time range",
        value: "24h",
        options: [
          { value: "15m", label: "Last 15 minutes" },
          { value: "1h", label: "Last hour" },
          { value: "6h", label: "Last 6 hours" },
          { value: "24h", label: "Last 24 hours" },
          { value: "7d", label: "Last 7 days" },
        ],
      },
      { name: "source", label: "Source", value: "" },
      {
        name: "severity",
        label: "Severity",
        value: "",
        options: [
          { value: "", label: "Any severity" },
          ...SEVERITIES.map((value) => ({ value, label: value })),
        ],
      },
      {
        name: "category",
        label: "Category",
        value: "",
        options: [
          { value: "", label: "Any category" },
          ...CATEGORIES.map((value) => ({ value, label: value })),
        ],
      },
      { name: "username", label: "Username", value: "" },
      { name: "ip", label: "Source IP", value: "" },
      { name: "search", label: "Search message", value: "" },
    ],
    (values) => {
      currentFilters = values;
      page = 1;
      void refresh();
    },
  );
  const result = el("div", {}, loading("Loading events"));
  const exportStatus = el("p", { className: "form-status", role: "status" });
  const root = section(
    "Events",
    filters,
    el(
      "div",
      { className: "button-row" },
      button("Export JSON", () => void download("json"), {
        className: "button button-secondary",
      }),
      button("Export CSV", () => void download("csv"), {
        className: "button button-secondary",
      }),
      exportStatus,
    ),
    panel("Event records", result),
  );
  let currentFilters: Readonly<Record<string, string>> = { range: "24h" };
  let page = 1;
  let requestId = 0;
  let disposed = false;

  const download = async (format: "json" | "csv"): Promise<void> => {
    exportStatus.textContent = `Preparing ${format.toUpperCase()} export…`;
    const exportSeverity = pick(SEVERITIES, currentFilters["severity"]);
    const exportCategory = pick(CATEGORIES, currentFilters["category"]);
    const exportFilters: EventFilters = {
      range: currentFilters["range"] ?? "24h",
      page,
      limit: 50,
      ...(currentFilters["source"] === undefined ||
      currentFilters["source"].length === 0
        ? {}
        : { source: currentFilters["source"] }),
      ...(currentFilters["username"] === undefined ||
      currentFilters["username"].length === 0
        ? {}
        : { username: currentFilters["username"] }),
      ...(currentFilters["ip"] === undefined ||
      currentFilters["ip"].length === 0
        ? {}
        : { ip: currentFilters["ip"] }),
      ...(currentFilters["search"] === undefined ||
      currentFilters["search"].length === 0
        ? {}
        : { search: currentFilters["search"] }),
      ...(exportSeverity === undefined ? {} : { severity: exportSeverity }),
      ...(exportCategory === undefined ? {} : { category: exportCategory }),
    };
    try {
      const blob = await api.export(format, exportFilters);
      if (disposed) return;
      const url = URL.createObjectURL(blob);
      const anchor = el("a", {
        href: url,
        download: `sentinel-export.${format}`,
      });
      document.body.append(anchor);
      anchor.click();
      anchor.remove();
      window.setTimeout(() => {
        URL.revokeObjectURL(url);
      }, 1_000);
      exportStatus.textContent = `${format.toUpperCase()} export downloaded.`;
    } catch (error: unknown) {
      exportStatus.textContent = errorMessage(error);
    }
  };

  const refresh = async (): Promise<void> => {
    const request = ++requestId;
    try {
      const severity = pick(SEVERITIES, currentFilters["severity"]);
      const category = pick(CATEGORIES, currentFilters["category"]);
      const response = await api.events({
        range: currentFilters["range"] ?? "24h",
        page,
        limit: 50,
        ...(currentFilters["source"] === undefined ||
        currentFilters["source"].length === 0
          ? {}
          : { source: currentFilters["source"] }),
        ...(currentFilters["username"] === undefined ||
        currentFilters["username"].length === 0
          ? {}
          : { username: currentFilters["username"] }),
        ...(currentFilters["ip"] === undefined ||
        currentFilters["ip"].length === 0
          ? {}
          : { ip: currentFilters["ip"] }),
        ...(currentFilters["search"] === undefined ||
        currentFilters["search"].length === 0
          ? {}
          : { search: currentFilters["search"] }),
        ...(severity === undefined ? {} : { severity }),
        ...(category === undefined ? {} : { category }),
        sort: "timestamp",
        direction: "desc",
      });
      if (disposed || request !== requestId) return;
      const columns: readonly Column<SecurityEvent>[] = [
        {
          key: "time",
          label: "Timestamp (UTC)",
          render: (event) => formatTimestamp(event.timestamp),
        },
        {
          key: "age",
          label: "Observed",
          render: (event) => formatRelative(event.timestamp),
        },
        {
          key: "severity",
          label: "Severity",
          render: (event) => severityBadge(event.severity),
        },
        {
          key: "category",
          label: "Category",
          render: (event) => event.category,
        },
        { key: "action", label: "Action", render: (event) => event.action },
        {
          key: "user",
          label: "Username",
          render: (event) => event.username ?? "Not recorded",
        },
        {
          key: "ip",
          label: "Source IP",
          render: (event) => event.sourceIp ?? "Not recorded",
        },
        {
          key: "detail",
          label: "Detail",
          render: (event) =>
            button("Inspect", () => void showEventDetail(event.id), {
              className: "button button-secondary",
            }),
        },
      ];
      const pageCount = Math.max(1, Math.ceil(response.total / response.limit));
      replaceChildren(
        result,
        el(
          "div",
          { className: "pagination" },
          button(
            "Previous",
            () => {
              page = Math.max(1, page - 1);
              void refresh();
            },
            { disabled: page <= 1 },
          ),
          el(
            "span",
            { "aria-live": "polite" },
            `Page ${response.page} of ${pageCount} · ${response.total} events`,
          ),
          button(
            "Next",
            () => {
              page += 1;
              void refresh();
            },
            { disabled: page >= pageCount },
          ),
        ),
        table("Security events", columns, response.events),
      );
    } catch (error: unknown) {
      if (!disposed && request === requestId) {
        replaceChildren(result, errorState(new Error(errorMessage(error))));
      }
    }
  };

  const offStream = refreshOnStream(() => {
    void refresh();
  }, ["event.created", "source.health"]);
  void refresh();
  return {
    root,
    dispose: () => {
      disposed = true;
      requestId += 1;
      offStream();
    },
  };
}

function pick<T extends string>(
  values: readonly T[],
  value: string | undefined,
): T | undefined {
  return values.find((candidate) => candidate === value);
}
