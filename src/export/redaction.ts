import type { SecurityEvent } from "../types.js";

export function redactEvents(
  events: readonly SecurityEvent[],
  redactSensitiveFields: boolean,
): readonly SecurityEvent[] {
  if (!redactSensitiveFields) return events;
  return events.map((event) => ({
    ...event,
    host: null,
    username: null,
    sourceIp: null,
    process: null,
    message: "[REDACTED]",
    metadata: {},
  }));
}
