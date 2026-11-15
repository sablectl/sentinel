import { el, uniqueId, type Child } from "../dom.js";

export function section(title: string, ...children: Child[]): HTMLElement {
  const headingId = uniqueId("section-heading");
  return el(
    "section",
    { className: "section", "aria-labelledby": headingId },
    el("h1", { id: headingId, tabindex: "-1" }, title),
    ...children,
  );
}

export function panel(title: string, ...children: Child[]): HTMLElement {
  const headingId = uniqueId("panel-heading");
  return el(
    "section",
    { className: "panel", "aria-labelledby": headingId },
    el("h2", { id: headingId }, title),
    ...children,
  );
}

export function loading(message = "Loading data"): HTMLElement {
  return el("p", { className: "state", role: "status" }, `${message}…`);
}

export function empty(message: string): HTMLElement {
  return el("p", { className: "state" }, message);
}

export function errorState(error: unknown): HTMLElement {
  const message =
    error instanceof Error ? error.message : "The request failed.";
  return el("p", { className: "state state-error", role: "alert" }, message);
}

export function metric(
  label: string,
  value: Child,
  detail?: Child,
): HTMLElement {
  return el(
    "article",
    { className: "metric" },
    el("h2", {}, label),
    el("p", { className: "metric-value" }, value),
    detail === undefined
      ? null
      : el("p", { className: "metric-detail" }, detail),
  );
}
