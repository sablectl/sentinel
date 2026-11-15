import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { runStart } from "../../src/cli/start.js";
import { parseConfig } from "../../src/config/config.js";
import { EventDatabase } from "../../src/store/database.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

describe("single-process start command", () => {
  it("serves the authenticated API and shuts down cleanly on abort", async () => {
    const directory = await mkdtemp(join(tmpdir(), "sentinel-start-"));
    temporaryDirectories.push(directory);
    const sourcePath = join(directory, "events.ndjson");
    await writeFile(
      sourcePath,
      `${JSON.stringify({ timestamp: Date.now(), action: "service.started" })}\n`,
      "utf8",
    );
    const databasePath = join(directory, "state", "events.sqlite");
    const config = parseConfig({
      storage: { path: databasePath },
      ingestion: {
        sources: [
          { name: "service-source", sourceType: "ndjson", path: sourcePath },
        ],
      },
    });
    const controller = new AbortController();
    let resolvePort: ((port: number) => void) | undefined;
    const output: string[] = [];
    const listening = new Promise<number>((resolve) => {
      resolvePort = resolve;
    });
    const start = runStart(config, {
      listenPort: 0,
      signal: controller.signal,
      output: (line) => {
        output.push(line);
      },
      onListening: (port) => {
        resolvePort?.(port);
      },
    });
    const port = await listening;
    const response = await fetch(`http://127.0.0.1:${port}/api/overview`);
    expect(response.status).toBe(401);
    expect(output.some((line) => line.startsWith("Login URL: http://"))).toBe(
      true,
    );
    const token = (
      await readFile(join(directory, "state", ".events.sqlite.token"), "utf8")
    ).trim();
    expect(output.join("")).not.toContain(token);

    const deadline = Date.now() + 5_000;
    let eventCount = 0;
    while (eventCount === 0 && Date.now() < deadline) {
      const database = new EventDatabase({ path: databasePath });
      try {
        eventCount = database.counts().events;
      } finally {
        database.close();
      }
      if (eventCount === 0) {
        await new Promise((resolve) => setTimeout(resolve, 25));
      }
    }
    expect(eventCount).toBe(1);
    controller.abort();
    await start;

    const database = new EventDatabase({ path: config.storage.path });
    try {
      expect(database.integrityCheck()).toBe("ok");
      expect(database.counts().sources).toBe(1);
    } finally {
      database.close();
    }
  });
});
