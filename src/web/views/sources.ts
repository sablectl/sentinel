import { api } from "../api.js";
import type { SourceStatus } from "../api-types.js";
import { table, type Column } from "../components/table.js";
import { button, el, replaceChildren } from "../dom.js";
import { formatRelative } from "../format.js";
import { errorMessage, refreshOnStream, type View } from "./shared.js";
import { errorState, loading, panel, section } from "../components/layout.js";

export function sourcesView(): View {
  const content = el("div", {}, loading("Loading sources"));
  const root = section(
    "Sources",
    el(
      "p",
      { className: "muted" },
      "Source definitions are read from local configuration; this view reports their ingestion health.",
    ),
    button(
      "Refresh",
      () => {
        void refresh();
      },
      { className: "button button-secondary" },
    ),
    content,
  );
  let generation = 0;
  let disposed = false;

  const refresh = async (): Promise<void> => {
    const requestId = ++generation;
    try {
      const sources = await api.sources();
      if (disposed || requestId !== generation) return;
      const columns: readonly Column<SourceStatus>[] = [
        { key: "name", label: "Name", render: (source) => source.name },
        { key: "type", label: "Parser", render: (source) => source.sourceType },
        { key: "path", label: "File path", render: (source) => source.path },
        { key: "status", label: "Status", render: (source) => source.status },
        {
          key: "last-seen",
          label: "Last event",
          render: (source) => formatRelative(source.lastSeen),
        },
        {
          key: "errors",
          label: "Errors",
          render: (source) => String(source.errorCount),
        },
        {
          key: "last-error",
          label: "Last error",
          render: (source) => source.lastError ?? "None",
        },
      ];
      replaceChildren(
        content,
        panel(
          "Configured sources",
          table("Ingestion sources", columns, sources),
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
  }, ["source.health", "event.created"]);
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
