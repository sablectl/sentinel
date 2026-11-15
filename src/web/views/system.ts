import { api } from "../api.js";
import {
  errorState,
  loading,
  metric,
  panel,
  section,
} from "../components/layout.js";
import { el, replaceChildren } from "../dom.js";
import { formatBytes, formatCount, formatDuration } from "../format.js";
import { errorMessage, refreshOnStream, type View } from "./shared.js";

export function systemView(): View {
  const content = el("div", {}, loading("Checking system health"));
  const root = section(
    "System",
    el(
      "p",
      { className: "muted" },
      "Local storage and runtime status. Sentinel does not transmit telemetry.",
    ),
    content,
  );
  let generation = 0;
  let disposed = false;
  let retentionMessage = "";

  const refresh = async (): Promise<void> => {
    const requestId = ++generation;
    try {
      const system = await api.system();
      if (disposed || requestId !== generation) return;
      const retentionStatus = el("p", {
        className: "form-status",
        role: "status",
      });
      retentionStatus.textContent = retentionMessage;
      const retention = el("input", {
        type: "number",
        name: "retentionDays",
        min: "1",
        max: "3650",
        step: "1",
        value: String(system.retentionDays),
        required: true,
        "aria-describedby": "retention-help",
      });
      const form = el(
        "form",
        { className: "retention-form" },
        el(
          "label",
          { className: "field" },
          el("span", {}, "Retain events for (days)"),
          retention,
        ),
        el(
          "p",
          { id: "retention-help", className: "muted" },
          "Saving a shorter period permanently prunes events and parser failures older than the new limit.",
        ),
        el(
          "button",
          { type: "submit", className: "button button-secondary" },
          "Save retention",
        ),
        retentionStatus,
      );
      form.addEventListener("submit", (event) => {
        event.preventDefault();
        const days = Number(retention.value);
        if (!Number.isSafeInteger(days) || days < 1 || days > 3650) {
          retentionStatus.textContent =
            "Choose an integer from 1 to 3650 days.";
          return;
        }
        retention.disabled = true;
        retentionStatus.textContent =
          "Saving retention and pruning expired records…";
        void api
          .updateRetention(days)
          .then(async (result) => {
            retentionMessage = `Retention saved. ${formatCount(result.pruned)} records pruned.`;
            await refresh();
          })
          .catch((error: unknown) => {
            retentionMessage = errorMessage(error);
            retentionStatus.textContent = retentionMessage;
          })
          .finally(() => {
            retention.disabled = false;
          });
      });
      replaceChildren(
        content,
        el(
          "div",
          { className: "metrics" },
          metric("Version", system.version),
          metric("Uptime", formatDuration(system.uptimeSeconds)),
          metric("Database size", formatBytes(system.database.bytes)),
          metric("Integrity", system.integrity),
        ),
        el(
          "div",
          { className: "grid" },
          panel(
            "Storage",
            el(
              "dl",
              { className: "detail-list" },
              el("dt", {}, "Database path"),
              el("dd", {}, system.database.path),
              el("dt", {}, "Retention"),
              el("dd", {}, `${formatCount(system.retentionDays)} days`),
            ),
            form,
          ),
          panel(
            "Resource limits",
            el(
              "dl",
              { className: "detail-list" },
              el("dt", {}, "Detection window events"),
              el("dd", {}, formatCount(system.detection.maxWindowEvents)),
              el("dt", {}, "Detection window bytes"),
              el("dd", {}, formatBytes(system.detection.maxWindowBytes)),
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
  }, ["system.updated", "system.retention_pruned"]);
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
