import { api } from "../api.js";
import type { Alert, AlertNote, AlertState, Severity } from "../api-types.js";
import { dialog } from "../components/dialog.js";
import { filterBar } from "../components/filters.js";
import { errorState, loading, panel, section } from "../components/layout.js";
import { noteEditor } from "../components/note-editor.js";
import { severityBadge } from "../components/severity.js";
import { table, type Column } from "../components/table.js";
import { button, el, replaceChildren } from "../dom.js";
import { formatCount, formatRelative, formatTimestamp } from "../format.js";
import {
  errorMessage,
  refreshOnStream,
  showEventDetail,
  type View,
} from "./shared.js";

const STATES: readonly AlertState[] = ["open", "acknowledged", "resolved"];
const SEVERITIES: readonly Severity[] = [
  "info",
  "low",
  "medium",
  "high",
  "critical",
];

export function alertsView(): View {
  let filters: Readonly<Record<string, string>> = {};
  let page = 1;
  let requestId = 0;
  let disposed = false;
  const content = el("div", {}, loading("Loading alerts"));
  const notice = el("p", { className: "form-status", role: "status" });
  const filter = filterBar(
    [
      {
        name: "state",
        label: "State",
        value: "",
        options: [
          { value: "", label: "Any state" },
          ...STATES.map((state) => ({ value: state, label: state })),
        ],
      },
      {
        name: "severity",
        label: "Severity",
        value: "",
        options: [
          { value: "", label: "Any severity" },
          ...SEVERITIES.map((severity) => ({
            value: severity,
            label: severity,
          })),
        ],
      },
    ],
    (values) => {
      filters = values;
      page = 1;
      void refresh();
    },
  );
  const root = section("Alerts", filter, content);

  const refresh = async (): Promise<void> => {
    const currentRequest = ++requestId;
    try {
      const state = pick(STATES, filters["state"]);
      const severity = pick(SEVERITIES, filters["severity"]);
      const result = await api.alerts({
        page,
        limit: 50,
        ...(state === undefined ? {} : { state }),
        ...(severity === undefined ? {} : { severity }),
      });
      if (disposed || currentRequest !== requestId) return;
      const columns: readonly Column<Alert>[] = [
        { key: "id", label: "ID", render: (alert) => `#${alert.id}` },
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
          key: "first-seen",
          label: "First seen",
          render: (alert) => formatTimestamp(alert.firstSeen),
        },
        {
          key: "last-seen",
          label: "Last seen",
          render: (alert) => formatRelative(alert.lastSeen),
        },
        {
          key: "actions",
          label: "Actions",
          render: (alert) =>
            alertActions(alert, refresh, (message) => {
              notice.textContent = message;
            }),
        },
      ];
      const pageCount = Math.max(1, Math.ceil(result.total / result.limit));
      replaceChildren(
        content,
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
            `Page ${result.page} of ${pageCount} · ${result.total} alerts`,
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
        panel(
          "Persistent alerts",
          table(
            "Alert queue",
            columns,
            result.alerts,
            "No alerts match these filters.",
          ),
        ),
        notice,
      );
    } catch (error: unknown) {
      if (!disposed && currentRequest === requestId) {
        replaceChildren(content, errorState(new Error(errorMessage(error))));
      }
    }
  };

  const offStream = refreshOnStream(() => {
    void refresh();
  }, ["alert.updated", "alert.note", "event.created"]);
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

function alertActions(
  alert: Alert,
  refresh: () => Promise<void>,
  setNotice: (message: string) => void,
): HTMLElement {
  const actions: HTMLElement[] = [
    button(
      "Investigate",
      () => {
        void showAlertDetails(alert.id);
      },
      { className: "button button-secondary" },
    ),
  ];
  if (alert.state === "open") {
    actions.push(
      stateButton("Acknowledge", alert.id, "acknowledged", refresh, setNotice),
    );
    actions.push(
      stateButton("Resolve", alert.id, "resolved", refresh, setNotice),
    );
  } else if (alert.state === "acknowledged") {
    actions.push(
      stateButton("Resolve", alert.id, "resolved", refresh, setNotice),
    );
  } else {
    actions.push(stateButton("Reopen", alert.id, "open", refresh, setNotice));
  }
  return el("div", { className: "button-row" }, ...actions);
}

function stateButton(
  label: string,
  alertId: number,
  state: AlertState,
  refresh: () => Promise<void>,
  setNotice: (message: string) => void,
): HTMLButtonElement {
  const control = button(
    label,
    () => {
      control.disabled = true;
      void api
        .setAlertState(alertId, state)
        .then(async () => {
          await refresh();
          setNotice(`Alert ${alertId} updated.`);
        })
        .catch((error: unknown) => {
          setNotice(errorMessage(error));
        })
        .finally(() => {
          control.disabled = false;
        });
    },
    { className: "button button-secondary" },
  );
  return control;
}

async function showAlertDetails(alertId: number): Promise<void> {
  const content = el("div", {}, loading("Loading investigation"));
  const modal = dialog(`Alert ${alertId} investigation`, content);
  document.body.append(modal);
  modal.addEventListener(
    "close",
    () => {
      modal.remove();
    },
    { once: true },
  );
  modal.showModal();
  try {
    const [alert, notes] = await Promise.all([
      api.alert(alertId),
      api.alertNotes(alertId),
    ]);
    replaceChildren(content, alertDetails(alert, notes, alertId));
  } catch (error: unknown) {
    replaceChildren(content, errorState(new Error(errorMessage(error))));
  }
}

function alertDetails(
  alert: Alert,
  notes: readonly AlertNote[],
  alertId: number,
): HTMLElement {
  const evidence = el(
    "ul",
    { className: "evidence-list" },
    ...alert.eventIds.map((eventId) =>
      el(
        "li",
        {},
        button(
          `Inspect event ${eventId.slice(0, 12)}`,
          () => void showEventDetail(eventId),
          {
            className: "button button-secondary",
          },
        ),
      ),
    ),
  );
  const noteList = el(
    "ol",
    { className: "note-list" },
    ...notes.map((note) =>
      el(
        "li",
        {},
        el(
          "time",
          { dateTime: new Date(note.createdAt).toISOString() },
          formatTimestamp(note.createdAt),
        ),
        el("p", {}, note.note),
      ),
    ),
  );
  const noteRoot = el("div", {}, noteList);
  const editor = noteEditor(async (note) => {
    await api.addAlertNote(alertId, note);
    const updated = await api.alertNotes(alertId);
    replaceChildren(
      noteRoot,
      el(
        "ol",
        { className: "note-list" },
        ...updated.map((item) =>
          el(
            "li",
            {},
            el(
              "time",
              { dateTime: new Date(item.createdAt).toISOString() },
              formatTimestamp(item.createdAt),
            ),
            el("p", {}, item.note),
          ),
        ),
      ),
    );
  });
  return el(
    "div",
    { className: "investigation-detail" },
    severityBadge(alert.severity),
    el("p", {}, alert.rationale),
    el(
      "p",
      { className: "muted" },
      `Rule ${alert.ruleId} · ${alert.occurrences} occurrences · ${alert.state}`,
    ),
    panel("Supporting event IDs", evidence),
    panel("Analyst notes", noteRoot, editor),
  );
}

function pick<T extends string>(
  values: readonly T[],
  value: string | undefined,
): T | undefined {
  return values.find((candidate) => candidate === value);
}
