import type { PreparedExport } from "./metadata.js";

export function exportJson(prepared: PreparedExport): string {
  return `${JSON.stringify(
    { metadata: prepared.metadata, events: prepared.events },
    null,
    2,
  )}\n`;
}
