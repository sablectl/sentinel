import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { writeExportFile } from "../../src/export/write-file.js";
import { runExport } from "../../src/cli/export.js";
import { parseConfig } from "../../src/config/config.js";
import { AlertStore } from "../../src/alerts/store.js";
import { EventDatabase } from "../../src/store/database.js";
import { insertEvents } from "../../src/store/queries.js";
import type { RuleMatch, SecurityEvent } from "../../src/types.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

describe("atomic export files", () => {
  it("creates a private output file and restrictive new directory", async () => {
    const directory = await mkdtemp(join(tmpdir(), "sentinel-export-"));
    temporaryDirectories.push(directory);
    const targetDirectory = join(directory, "exports");
    const path = writeExportFile(
      join(targetDirectory, "events.csv"),
      "a,b\n1,2\n",
    );
    expect((await lstat(targetDirectory)).mode & 0o777).toBe(0o700);
    expect((await lstat(path)).mode & 0o777).toBe(0o600);
  });

  it("does not follow a symlink export destination", async () => {
    const directory = await mkdtemp(join(tmpdir(), "sentinel-export-link-"));
    temporaryDirectories.push(directory);
    const target = join(directory, "target.csv");
    await mkdir(join(directory, "exports"));
    await chmod(join(directory, "exports"), 0o700);
    await symlink(target, join(directory, "exports", "events.csv"));
    expect(() =>
      writeExportFile(join(directory, "exports", "events.csv"), "sensitive"),
    ).toThrow(/symlink/);
  });

  it("exports matching events with filters, rule references and default redaction", async () => {
    const directory = await mkdtemp(join(tmpdir(), "sentinel-cli-export-"));
    temporaryDirectories.push(directory);
    const databasePath = join(directory, "state", "events.sqlite");
    const outputPath = join(directory, "exports", "evidence.csv");
    const timestamp = Date.now();
    const event: SecurityEvent = {
      id: "d".repeat(64),
      timestamp,
      ingestedAt: timestamp + 1,
      source: "audit-source",
      sourceType: "ndjson",
      host: "private-host",
      category: "authentication",
      action: "ssh.authentication.failure",
      outcome: "failure",
      severity: "high",
      username: "private-user",
      sourceIp: "203.0.113.99",
      process: null,
      message: "private message",
      metadata: { credential: "private-metadata" },
      parserVersion: "ndjson/1",
      inferred: [],
    };
    const database = new EventDatabase({ path: databasePath });
    database.withDatabase((connection) => insertEvents(connection, [event]));
    const ruleMatch: RuleMatch = {
      ruleId: "ssh.repeated_failures",
      ruleVersion: 1,
      dedupKey: "ssh.repeated_failures:ip:fixture",
      severity: "high",
      rationale: "Repeated SSH authentication failure indicators.",
      thresholds: { count: 5, windowMs: 300_000 },
      windowStart: timestamp,
      windowEnd: timestamp,
      eventIds: [event.id],
    };
    new AlertStore(database).upsert(ruleMatch);
    database.close();

    const config = parseConfig({ storage: { path: databasePath } });
    const result = runExport(config, {
      format: "csv",
      outputPath,
      filters: { range: "15m", severity: "high" },
    });
    const exported = await readFile(outputPath, "utf8");
    expect(result).toMatchObject({ eventCount: 1, filteredTotal: 1 });
    expect((await lstat(outputPath)).mode & 0o777).toBe(0o600);
    expect(exported).toContain("ssh.repeated_failures");
    expect(exported).toContain("redacted");
    expect(exported).not.toContain("private-host");
    expect(exported).not.toContain("private-user");
    expect(exported).not.toContain("private message");
    expect(exported).not.toContain("private-metadata");
  });
});
