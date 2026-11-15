import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { runIngest } from "../../src/cli/ingest.js";
import { parseConfig } from "../../src/config/config.js";
import { EventDatabase } from "../../src/store/database.js";
import { getSourceStatuses } from "../../src/store/queries.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

describe("ingestion integration", () => {
  it("stores events and isolated failures, then resumes without replaying committed records", async () => {
    const directory = await mkdtemp(join(tmpdir(), "sentinel-ingestion-"));
    temporaryDirectories.push(directory);
    const databasePath = join(directory, "state", "events.sqlite");
    const sourcePath = join(directory, "events.ndjson");
    const now = new Date();
    let baseTime = Date.UTC(
      now.getUTCFullYear(),
      now.getUTCMonth(),
      now.getUTCDate(),
      12,
    );
    if (baseTime > Date.now()) baseTime -= 86_400_000;
    baseTime -= 10_000;
    const first = JSON.stringify({
      timestamp: new Date(baseTime).toISOString(),
      action: "ssh.authentication.failure",
      category: "authentication",
      outcome: "failure",
      username: "operator",
      sourceIp: "203.0.113.10",
    });
    const second = JSON.stringify({
      timestamp: new Date(baseTime + 4_000).toISOString(),
      action: "ssh.authentication.success",
      category: "authentication",
      outcome: "success",
      username: "operator",
      sourceIp: "203.0.113.10",
    });
    await writeFile(sourcePath, `${first}\nnot-json\n${second}\n\n`, "utf8");

    const config = parseConfig({
      storage: { path: databasePath },
      ingestion: {
        maxRecordBytes: 4096,
        maxFileBytes: 65_536,
        queueHighWaterMark: 1,
      },
    });
    const initial = await runIngest(
      config,
      "ndjson",
      sourcePath,
      "auth-import",
    );
    expect(initial).toMatchObject({
      records: 4,
      ignored: 1,
      eventsInserted: 2,
      duplicates: 0,
      parseFailures: 1,
      detectionMatches: 1,
    });

    const resumed = await runIngest(
      config,
      "ndjson",
      sourcePath,
      "auth-import",
    );
    expect(resumed).toMatchObject({
      records: 0,
      eventsInserted: 0,
      parseFailures: 0,
    });

    await writeFile(sourcePath, `${first}\n`, "utf8");
    const replayed = await runIngest(
      config,
      "ndjson",
      sourcePath,
      "auth-import",
    );
    expect(replayed).toMatchObject({
      records: 1,
      eventsInserted: 0,
      duplicates: 1,
      detectionMatches: 0,
    });

    const database = new EventDatabase({ path: databasePath });
    try {
      expect(database.counts()).toMatchObject({
        events: 2,
        parseFailures: 1,
        alerts: 1,
      });
      const sources = database.withDatabase(getSourceStatuses);
      expect(sources).toHaveLength(1);
      expect(sources[0]).toMatchObject({
        name: "auth-import",
        sourceType: "ndjson",
        status: "ready",
        errorCount: 1,
        lastError: "NDJSON record is not valid JSON",
      });
      const checkpoint = database.withDatabase((connection) =>
        connection
          .prepare(
            "SELECT offset, size, line_number FROM checkpoints WHERE source_name = ?",
          )
          .get("auth-import"),
      );
      expect(checkpoint?.["offset"]).toBe(Buffer.byteLength(`${first}\n`));
      expect(checkpoint?.["size"]).toBe(Buffer.byteLength(`${first}\n`));
      expect(checkpoint?.["line_number"]).toBe(1);
      const failureLine = database.withDatabase((connection) =>
        connection
          .prepare("SELECT line_number FROM parse_failures WHERE source = ?")
          .get("auth-import"),
      );
      expect(failureLine?.["line_number"]).toBe(2);
    } finally {
      database.close();
    }
  });
});
