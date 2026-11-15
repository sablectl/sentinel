import { describe, expect, it } from "vitest";
import type { SecurityEvent } from "../../src/types.js";
import { exportCsv, escapeCell } from "../../src/export/csv.js";
import { exportJson } from "../../src/export/json.js";
import { prepareExport } from "../../src/export/metadata.js";

const event: SecurityEvent = {
  id: "a".repeat(64),
  timestamp: Date.UTC(2025, 10, 14, 12),
  ingestedAt: Date.UTC(2025, 10, 14, 12, 1),
  source: "auth-main",
  sourceType: "ndjson",
  host: "server-01",
  category: "authentication",
  action: "ssh.authentication.failure",
  outcome: "failure",
  severity: "high",
  username: "operator",
  sourceIp: "203.0.113.1",
  process: { name: "sshd", pid: 123 },
  message: "=SUM(A1:A2)",
  metadata: { originalEscaped: "sensitive detail", port: 22 },
  parserVersion: "ndjson/1",
  inferred: [],
};

const filters = {
  from: 1,
  to: 2,
  page: 1,
  limit: 50,
  sort: "timestamp" as const,
  direction: "desc" as const,
};

describe("export preparation", () => {
  it("records metadata and redacts sensitive fields by default when configured", () => {
    const prepared = prepareExport(
      [event],
      filters,
      ["ssh.repeated_failures"],
      true,
      Date.UTC(2025, 10, 14, 13),
    );
    expect(prepared.metadata).toMatchObject({
      generatedAt: "2025-11-14T13:00:00.000Z",
      filters,
      relevantRules: ["ssh.repeated_failures"],
      eventCount: 1,
      redacted: true,
    });
    expect(prepared.metadata.limitations).toMatch(/indicator/);
    expect(prepared.events[0]).toMatchObject({
      host: null,
      username: null,
      sourceIp: null,
      process: null,
      message: "[REDACTED]",
      metadata: {},
    });
    expect(exportJson(prepared)).toContain('"eventCount": 1');
  });

  it("neutralises formula-leading cells in CSV exports", () => {
    for (const value of [
      "=1+1",
      "+SUM(A1)",
      "-1",
      "@SUM(A1)",
      "\t=1",
      "\r=1",
    ]) {
      expect(escapeCell(value)).toBe(`"'${value}"`);
    }
    const prepared = prepareExport([event], filters, [], false);
    const csv = exportCsv(prepared);
    expect(csv).toContain('"\'=SUM(A1:A2)"');
    expect(csv).toContain("# Sentinel export metadata");
  });
});
