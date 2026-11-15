import type { StreamEvent } from "./store.js";
import { streamEvents, updateState } from "./store.js";
import { api } from "./api.js";

const MIN_RECONNECT_MS = 1_000;
const MAX_RECONNECT_MS = 30_000;
const STREAM_EVENTS = [
  "event.created",
  "alert.updated",
  "alert.note",
  "rules.updated",
  "source.health",
  "stream.degraded",
] as const;

function parseMessage(event: Event): unknown {
  if (!(event instanceof MessageEvent) || typeof event.data !== "string") {
    return null;
  }
  try {
    return JSON.parse(event.data) as unknown;
  } catch {
    return null;
  }
}

export function startStream(): () => void {
  let delay = MIN_RECONNECT_MS;
  let source: EventSource | undefined;
  let timer: number | undefined;
  let disposed = false;

  const connect = (): void => {
    if (disposed) return;
    timer = undefined;
    updateState({ connection: "connecting" });
    const active = new EventSource("/api/stream", { withCredentials: true });
    source = active;
    active.onopen = () => {
      if (disposed || source !== active) return;
      delay = MIN_RECONNECT_MS;
      updateState({ connection: "live" });
    };
    for (const type of STREAM_EVENTS) {
      active.addEventListener(type, (event) => {
        if (disposed || source !== active) return;
        const payload = parseMessage(event);
        if (payload === null) return;
        if (type === "stream.degraded" && isRecord(payload)) {
          const dropped = payload["dropped"];
          if (
            typeof dropped === "number" &&
            Number.isSafeInteger(dropped) &&
            dropped > 0
          ) {
            updateState({ degraded: dropped });
          }
        }
        const message: StreamEvent = { type, payload };
        streamEvents.emit(message);
      });
    }
    active.onerror = () => {
      updateState({ connection: "reconnecting" });
      const ended = active.readyState === EventSource.CLOSED;
      active.close();
      if (source === active) source = undefined;
      if (ended) void api.session().catch(() => undefined);
      if (timer !== undefined) return;
      timer = window.setTimeout(connect, delay);
      delay = Math.min(delay * 2, MAX_RECONNECT_MS);
    };
  };

  connect();
  return () => {
    disposed = true;
    if (timer !== undefined) window.clearTimeout(timer);
    source?.close();
    updateState({ connection: "offline" });
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
