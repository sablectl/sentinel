import type { SecurityEvent } from "../types.js";
import type { PreparedExport } from "./metadata.js";

const HEADERS = [
  "id",
  "timestamp",
  "ingestedAt",
  "source",
  "sourceType",
  "host",
  "category",
  "action",
  "outcome",
  "severity",
  "username",
  "sourceIp",
  "processName",
  "processPid",
  "message",
  "metadata",
  "parserVersion",
  "inferred",
] as const;

export function exportCsv(prepared: PreparedExport): string {
  const rows = [
    `# Sentinel export metadata,${escapeCell(JSON.stringify(prepared.metadata))}`,
    HEADERS.map(escapeCell).join(","),
    ...prepared.events.map((event) =>
      eventCells(event).map(escapeCell).join(","),
    ),
  ];
  return `${rows.join("\r\n")}\r\n`;
}

export function escapeCell(value: string): string {
  const safe = /^[=+\-@\t\r]/.test(value) ? `'${value}` : value;
  return `"${safe.replaceAll('"', '""')}"`;
}

function eventCells(event: SecurityEvent): string[] {
  const metadata = Object.fromEntries(
    Object.entries(event.metadata).sort(([left], [right]) =>
      left < right ? -1 : left > right ? 1 : 0,
    ),
  );
  return [
    event.id,
    String(event.timestamp),
    String(event.ingestedAt),
    event.source,
    event.sourceType,
    event.host ?? "",
    event.category,
    event.action,
    event.outcome,
    event.severity,
    event.username ?? "",
    event.sourceIp ?? "",
    event.process?.name ?? "",
    event.process?.pid === null || event.process === null
      ? ""
      : String(event.process.pid),
    event.message,
    JSON.stringify(metadata),
    event.parserVersion,
    event.inferred.join(";"),
  ];
}
