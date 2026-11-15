import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { AlertLifecycle } from "../../src/alerts/lifecycle.js";
import { AlertStore } from "../../src/alerts/store.js";
import { DetectionEngine } from "../../src/detect/engine.js";
import { insertEvents } from "../../src/store/queries.js";
import { EventDatabase } from "../../src/store/database.js";
import type { RuleMatch, SecurityEvent } from "../../src/types.js";

const temporaryDirectories: string[] = [];

function makeEvent(id: string, timestamp: number): SecurityEvent {
  return {
    id,
    timestamp,
    ingestedAt: timestamp + 10,
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
    message: "synthetic authentication failure",
    metadata: {},
    parserVersion: "ndjson/1",
    inferred: [],
  };
}

function makeMatch(eventIds: readonly string[], timestamp: number): RuleMatch {
  return {
    ruleId: "ssh.repeated_failures",
    ruleVersion: 1,
    dedupKey: "ssh.repeated_failures:ip:203.0.113.1",
    severity: "high",
    rationale:
      "Repeated SSH authentication failure indicators within the configured window.",
    thresholds: { count: 5, windowMs: 300_000 },
    windowStart: timestamp,
    windowEnd: timestamp,
    eventIds,
  };
}

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

describe("alert persistence and lifecycle", () => {
  it("deduplicates evidence and persists state and analyst notes across restart", async () => {
    const directory = await mkdtemp(join(tmpdir(), "sentinel-alerts-"));
    temporaryDirectories.push(directory);
    const path = join(directory, "state", "events.sqlite");
    const initialTime = Date.UTC(2025, 10, 14, 12);
    const database = new EventDatabase({ path });
    const firstEvent = makeEvent("event-1", initialTime);
    const secondEvent = makeEvent("event-2", initialTime + 1_000);
    const thirdEvent = makeEvent("event-3", initialTime + 2_000);
    database.withDatabase((connection) =>
      insertEvents(connection, [firstEvent, secondEvent, thirdEvent]),
    );
    const alerts = new AlertStore(database);
    const lifecycle = new AlertLifecycle(alerts);

    const first = alerts.upsert(makeMatch([firstEvent.id], initialTime));
    const repeated = alerts.upsert(makeMatch([firstEvent.id], initialTime));
    expect(repeated.occurrences).toBe(1);
    const extended = alerts.upsert(
      makeMatch([firstEvent.id, secondEvent.id], initialTime + 1_000),
    );
    expect(extended).toMatchObject({
      id: first.id,
      firstSeen: initialTime,
      lastSeen: initialTime + 1_000,
      occurrences: 2,
      eventIds: [firstEvent.id, secondEvent.id],
    });

    expect(lifecycle.acknowledge(first.id).state).toBe("acknowledged");
    const note = lifecycle.addNote(first.id, "Review this indicator\u001b[31m");
    expect(note.note).toBe("Review this indicator");
    expect(lifecycle.resolve(first.id).state).toBe("resolved");
    expect(lifecycle.reopen(first.id).state).toBe("open");
    expect(lifecycle.resolve(first.id).state).toBe("resolved");

    const reopenedByNewEvidence = alerts.upsert(
      makeMatch(
        [firstEvent.id, secondEvent.id, thirdEvent.id],
        initialTime + 2_000,
      ),
    );
    expect(reopenedByNewEvidence).toMatchObject({
      state: "open",
      occurrences: 3,
      lastSeen: initialTime + 2_000,
    });
    database.close();

    const restoredDatabase = new EventDatabase({ path });
    try {
      const restored = new AlertStore(restoredDatabase);
      expect(restored.get(first.id)).toMatchObject({
        state: "open",
        occurrences: 3,
        eventIds: [firstEvent.id, secondEvent.id, thirdEvent.id],
      });
      expect(restored.notes(first.id)).toMatchObject([
        { note: "Review this indicator" },
      ]);
      expect(restored.list({ state: "open", severity: "high" })).toHaveLength(
        1,
      );
    } finally {
      restoredDatabase.close();
    }
  });

  it("rejects invalid alert transitions", async () => {
    const directory = await mkdtemp(join(tmpdir(), "sentinel-alert-state-"));
    temporaryDirectories.push(directory);
    const database = new EventDatabase({
      path: join(directory, "state.sqlite"),
    });
    const event = makeEvent("state-event", Date.UTC(2025, 10, 14));
    database.withDatabase((connection) => insertEvents(connection, [event]));
    const lifecycle = new AlertLifecycle(new AlertStore(database));
    const alert = new AlertStore(database).upsert(
      makeMatch([event.id], event.timestamp),
    );
    lifecycle.acknowledge(alert.id);
    expect(() => lifecycle.reopen(alert.id)).toThrow(/must be resolved/);
    database.close();
  });

  it("persists enabled state and tuned thresholds across restart", async () => {
    const directory = await mkdtemp(join(tmpdir(), "sentinel-rules-state-"));
    temporaryDirectories.push(directory);
    const path = join(directory, "state.sqlite");
    const database = new EventDatabase({ path });
    const engine = new DetectionEngine(database);
    const configured = engine.configureRule("ssh.repeated_failures", {
      enabled: false,
      thresholds: { count: 7 },
    });
    expect(configured).toMatchObject({
      enabled: false,
      thresholds: { count: 7, windowMs: 300_000 },
    });
    database.close();

    const reopenedDatabase = new EventDatabase({ path });
    try {
      const restored = new DetectionEngine(reopenedDatabase)
        .listRules()
        .find((rule) => rule.id === "ssh.repeated_failures");
      expect(restored).toMatchObject({
        enabled: false,
        thresholds: { count: 7, windowMs: 300_000 },
      });
    } finally {
      reopenedDatabase.close();
    }
  });

  it("preserves alerts while retention nulls links to pruned evidence events", () => {
    const database = new EventDatabase({ path: ":memory:" });
    try {
      const now = Date.now();
      const oldEvent = makeEvent("expired-event", now - 2 * 86_400_000);
      database.withDatabase((connection) =>
        insertEvents(connection, [oldEvent]),
      );
      const alerts = new AlertStore(database);
      const alert = alerts.upsert(makeMatch([oldEvent.id], oldEvent.timestamp));

      expect(database.prune(1, now)).toBe(1);
      expect(alerts.get(alert.id)).toMatchObject({
        state: "open",
        eventIds: [],
      });
      expect(database.counts()).toMatchObject({ events: 0, alerts: 1 });
      expect(database.integrityCheck()).toBe("ok");
    } finally {
      database.close();
    }
  });
});
