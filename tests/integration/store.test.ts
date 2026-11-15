import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { EventDatabase } from "../../src/store/database.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

describe("SQLite store integration", () => {
  it("creates a durable migrated database that reopens cleanly", async () => {
    const directory = await mkdtemp(join(tmpdir(), "sentinel-integration-"));
    temporaryDirectories.push(directory);
    const path = join(directory, "state", "events.sqlite");

    const first = new EventDatabase({ path });
    expect(first.integrityCheck()).toBe("ok");
    first.close();

    const reopened = new EventDatabase({ path });
    try {
      expect(reopened.integrityCheck()).toBe("ok");
      expect(reopened.schemaVersion).toBeGreaterThan(0);
      expect(reopened.counts().events).toBe(0);
    } finally {
      reopened.close();
    }
  });
});
