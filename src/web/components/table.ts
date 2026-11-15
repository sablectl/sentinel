import { el, type Child } from "../dom.js";

export interface Column<Row> {
  readonly key: string;
  readonly label: string;
  readonly render: (row: Row) => Child;
}

export function table<Row>(
  caption: string,
  columns: readonly Column<Row>[],
  rows: readonly Row[],
  emptyText = "No records match the current filters.",
): HTMLElement {
  if (rows.length === 0)
    return el("p", { className: "empty-state" }, emptyText);
  const head = el(
    "thead",
    {},
    el(
      "tr",
      {},
      ...columns.map((column) => el("th", { scope: "col" }, column.label)),
    ),
  );
  const body = el(
    "tbody",
    {},
    ...rows.map((row) =>
      el(
        "tr",
        {},
        ...columns.map((column) =>
          el("td", { "data-label": column.label }, column.render(row)),
        ),
      ),
    ),
  );
  return el(
    "div",
    {
      className: "table-wrap",
      role: "region",
      "aria-label": caption,
      tabindex: "0",
    },
    el("table", {}, el("caption", {}, caption), head, body),
  );
}
