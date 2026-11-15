import { describe, expect, it } from "vitest";
import { DetectionEngine } from "../../src/detect/engine.js";
import { EventDatabase } from "../../src/store/database.js";
import { insertEvents } from "../../src/store/queries.js";
import type { SecurityEvent } from "../../src/types.js";

function event(id: string, timestamp: number): SecurityEvent {
  return {
    id,
    timestamp,
    ingestedAt: timestamp + 1,
    source: "fixture",
    sourceType: "ndjson",
    host: "host-01",
    category: "authentication",
    action: "ssh.authentication.failure",
    outcome: "failure",
    severity: "medium",
    username: "operator",
    sourceIp: "203.0.113.1",
    process: null,
    message: "bounded detection fixture",
    metadata: {},
    parserVersion: "ndjson/1",
    inferred: [],
  };
}

describe("DetectionEngine resource bounds", () => {
  it("fails visibly instead of evaluating a window beyond its event cap", () => {
    const database = new EventDatabase({ path: ":memory:" });
    try {
      const timestamp = Date.UTC(2025, 10, 14, 12);
      const events = [
        event("event-1", timestamp),
        event("event-2", timestamp + 1_000),
        event("event-3", timestamp + 2_000),
      ];
      database.withDatabase((connection) => insertEvents(connection, events));
      const engine = new DetectionEngine(database, {
        maxWindowEvents: 2,
        maxWindowBytes: 1_000_000,
      });

      expect(() => engine.evaluateAt(timestamp + 2_000, "event-3")).toThrow(
        /more than 2 events/,
      );
      expect(database.counts().alerts).toBe(0);
    } finally {
      database.close();
    }
  });
});
