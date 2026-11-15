import { api } from "../api.js";
import { dialog } from "../components/dialog.js";
import { el, replaceChildren } from "../dom.js";
import { formatTimestamp } from "../format.js";
import type { SecurityEvent } from "../api-types.js";
import { streamEvents } from "../store.js";

export interface View {
  readonly root: HTMLElement;
  dispose(): void;
}

export function refreshOnStream(
  refresh: () => void,
  eventNames: readonly string[],
): () => void {
  let timer: number | undefined;
  const unsubscribe = streamEvents.on((event) => {
    if (!eventNames.includes(event.type)) return;
    if (timer !== undefined) window.clearTimeout(timer);
    timer = window.setTimeout(() => {
      timer = undefined;
      refresh();
    }, 150);
  });
  return () => {
    unsubscribe();
    if (timer !== undefined) window.clearTimeout(timer);
  };
}

export function errorMessage(error: unknown): string {
  return error instanceof Error
    ? error.message
    : "The request could not be completed.";
}

export async function showEventDetail(eventId: string): Promise<void> {
  const content = el("div", { className: "detail-content" }, "Loading event…");
  const modal = dialog("Event detail", content);
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
    const event = await api.event(eventId);
    replaceChildren(content, eventDetails(event));
  } catch (error: unknown) {
    replaceChildren(content, el("p", { role: "alert" }, errorMessage(error)));
  }
}

function eventDetails(event: SecurityEvent): HTMLElement {
  const rows: readonly (readonly [string, string])[] = [
    ["Timestamp (UTC)", formatTimestamp(event.timestamp)],
    ["Source", event.source],
    ["Host", event.host ?? "Not recorded"],
    ["Category", event.category],
    ["Action", event.action],
    ["Outcome", event.outcome],
    ["Severity", event.severity],
    ["Username", event.username ?? "Not recorded"],
    ["Source IP", event.sourceIp ?? "Not recorded"],
    ["Parser", event.parserVersion],
    ["Inferred fields", event.inferred.join(", ") || "None"],
  ];
  return el(
    "div",
    {},
    el(
      "dl",
      { className: "detail-list" },
      ...rows.flatMap(([label, value]) => [
        el("dt", {}, label),
        el("dd", {}, value),
      ]),
    ),
    el("h3", {}, "Message"),
    el("pre", { className: "event-message" }, event.message),
    el("h3", {}, "Structured metadata"),
    el(
      "pre",
      { className: "event-message" },
      JSON.stringify(event.metadata, null, 2),
    ),
  );
}
