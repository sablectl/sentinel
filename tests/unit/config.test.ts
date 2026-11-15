import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  ConfigError,
  defaultConfig,
  isLoopbackHost,
  loadConfig,
  parseConfig,
} from "../../src/config/config.js";

const temporaryDirectories: string[] = [];

async function temporaryDirectory(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "sentinel-config-"));
  temporaryDirectories.push(directory);
  return directory;
}

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

describe("configuration defaults", () => {
  it("binds to loopback with bounded retention and a local database path", () => {
    const config = defaultConfig();
    expect(config.server.host).toBe("127.0.0.1");
    expect(config.server.allowRemote).toBe(false);
    expect(config.server.token).toBeNull();
    expect(config.server.maxStreamEventsPerSecond).toBe(100);
    expect(config.export.redactSensitiveFields).toBe(true);
    expect(config.storage.retentionDays).toBe(30);
    expect(config.storage.path).toContain("sentinel");
    expect(config.ingestion.maxRecordBytes).toBe(65_536);
    expect(config.ingestion.queueHighWaterMark).toBe(512);
    expect(config.ingestion.sources).toEqual([]);
    expect(config.detection.maxWindowEvents).toBe(2_000);
    expect(config.detection.maxWindowBytes).toBe(67_108_864);
    expect(isLoopbackHost(config.server.host)).toBe(true);
  });

  it("recognises valid loopback addresses without accepting malformed IPv4", () => {
    expect(isLoopbackHost("localhost")).toBe(true);
    expect(isLoopbackHost("::1")).toBe(true);
    expect(isLoopbackHost("127.30.0.1")).toBe(true);
    expect(isLoopbackHost("127.0.0.999")).toBe(false);
    expect(isLoopbackHost("192.0.2.1")).toBe(false);
  });
});

describe("parseConfig", () => {
  it("accepts defaults and rejects a non-object document", () => {
    expect(parseConfig({})).toEqual(defaultConfig());
    expect(() => parseConfig([])).toThrow(ConfigError);
    expect(() => parseConfig("invalid")).toThrow(ConfigError);
  });

  it("rejects unknown settings and invalid value ranges", () => {
    expect(() => parseConfig({ unknown: true })).toThrow(/not a known setting/);
    expect(() => parseConfig({ server: { port: 0 } })).toThrow(
      /server.port must be between/,
    );
    expect(() => parseConfig({ storage: { retentionDays: 3651 } })).toThrow(
      /storage.retentionDays must be between/,
    );
    expect(() =>
      parseConfig({
        ingestion: { maxRecordBytes: 32, maxFileBytes: 16 },
      }),
    ).toThrow(/maxFileBytes must be at least/);
    expect(() =>
      parseConfig({
        ingestion: { maxRecordBytes: 1_048_576, queueHighWaterMark: 65_536 },
      }),
    ).toThrow(/must not exceed 256 MiB/);
    expect(() =>
      parseConfig({ detection: { maxWindowEvents: 10_001 } }),
    ).toThrow(/detection.maxWindowEvents must be between/);
  });

  it("requires explicit remote permission and a sufficiently long token off loopback", () => {
    expect(() => parseConfig({ server: { host: "0.0.0.0" } })).toThrow(
      /allowRemote/,
    );
    expect(() =>
      parseConfig({ server: { host: "0.0.0.0", allowRemote: true } }),
    ).toThrow(/token is required/);
    expect(() =>
      parseConfig({
        server: { host: "0.0.0.0", allowRemote: true, token: "too-short" },
      }),
    ).toThrow(/between 32 and 512/);

    const config = parseConfig({
      server: {
        host: "192.0.2.8",
        allowRemote: true,
        token: "a".repeat(32),
      },
    });
    expect(config.server.host).toBe("192.0.2.8");
  });

  it("validates configured source names, types and paths", () => {
    const config = parseConfig({
      ingestion: {
        sources: [
          {
            name: "auth-main",
            sourceType: "authlog",
            path: "/var/log/auth.log",
          },
        ],
      },
    });
    expect(config.ingestion.sources).toEqual([
      {
        name: "auth-main",
        sourceType: "authlog",
        path: "/var/log/auth.log",
        enabled: true,
      },
    ]);
    expect(() =>
      parseConfig({
        ingestion: {
          sources: [
            { name: "duplicate", sourceType: "ndjson", path: "/tmp/a" },
            { name: "duplicate", sourceType: "syslog", path: "/tmp/b" },
          ],
        },
      }),
    ).toThrow(/duplicate name/);
  });

  it("reports the configuration error without exposing a supplied token", () => {
    const secret = "private-token-that-must-not-be-in-error-output";
    try {
      parseConfig({ server: { host: "0.0.0.0", token: secret } });
      expect.unreachable("invalid configuration must fail");
    } catch (error: unknown) {
      expect(error).toBeInstanceOf(ConfigError);
      expect((error as ConfigError).message).not.toContain(secret);
    }
  });
});

describe("loadConfig", () => {
  it("merges JSON, environment and command-line overrides in precedence order", async () => {
    const directory = await temporaryDirectory();
    const path = join(directory, "config.json");
    await writeFile(
      path,
      JSON.stringify({
        server: { port: 7000 },
        storage: { retentionDays: 10 },
      }),
      "utf8",
    );
    const environment: NodeJS.ProcessEnv = {};
    environment["SENTINEL_PORT"] = "7001";
    environment["SENTINEL_RETENTION_DAYS"] = "11";
    environment["SENTINEL_MAX_RECORD_BYTES"] = "4096";
    environment["SENTINEL_MAX_WINDOW_EVENTS"] = "1500";
    environment["SENTINEL_MAX_STREAM_EVENTS_PER_SECOND"] = "80";
    environment["SENTINEL_EXPORT_REDACT_SENSITIVE_FIELDS"] = "false";
    environment["SENTINEL_MAX_WINDOW_BYTES"] = "33554432";
    environment["SENTINEL_SOURCES"] = JSON.stringify([
      { name: "json-import", sourceType: "ndjson", path: "/tmp/events.jsonl" },
    ]);

    const config = await loadConfig(
      path,
      { server: { port: 7002 } },
      environment,
    );
    expect(config.server.port).toBe(7002);
    expect(config.storage.retentionDays).toBe(11);
    expect(config.ingestion.maxRecordBytes).toBe(4096);
    expect(config.detection.maxWindowEvents).toBe(1500);
    expect(config.server.maxStreamEventsPerSecond).toBe(80);
    expect(config.export.redactSensitiveFields).toBe(false);
    expect(config.detection.maxWindowBytes).toBe(33_554_432);
    expect(config.ingestion.sources[0]?.name).toBe("json-import");
  });

  it("rejects invalid JSON and missing explicitly selected files", async () => {
    const directory = await temporaryDirectory();
    const path = join(directory, "invalid.json");
    await writeFile(path, "{", "utf8");
    await expect(loadConfig(path)).rejects.toThrow(/not valid JSON/);
    await expect(loadConfig(join(directory, "missing.json"))).rejects.toThrow(
      /could not be read/,
    );
  });
});
