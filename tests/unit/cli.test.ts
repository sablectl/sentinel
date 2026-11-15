import { describe, expect, it } from "vitest";
import { parseArguments, UsageError } from "../../src/cli/args.js";

describe("CLI arguments", () => {
  it("parses doctor options", () => {
    expect(
      parseArguments([
        "doctor",
        "--db",
        "/tmp/events.sqlite",
        "--port",
        "8080",
        "--max-window-events",
        "1500",
      ]),
    ).toEqual({
      command: "doctor",
      configPath: undefined,
      sourceName: undefined,
      sourcePath: undefined,
      sourceType: undefined,
      action: undefined,
      identifier: undefined,
      note: undefined,
      thresholds: undefined,
      alertState: undefined,
      alertSeverity: undefined,
      limit: undefined,
      exportFormat: undefined,
      outputPath: undefined,
      exportFilters: {},
      overrides: {
        server: { port: 8080 },
        storage: { path: "/tmp/events.sqlite" },
        ingestion: {},
        detection: { maxWindowEvents: 1500 },
      },
    });
  });

  it("parses rule configuration and alert state operations", () => {
    expect(
      parseArguments([
        "rules",
        "tune",
        "ssh.repeated_failures",
        "--thresholds",
        '{"count":9}',
      ]),
    ).toMatchObject({
      command: "rules",
      action: "tune",
      identifier: "ssh.repeated_failures",
      thresholds: { count: 9 },
    });
    expect(
      parseArguments([
        "alerts",
        "list",
        "--state",
        "open",
        "--severity",
        "high",
        "--limit",
        "25",
      ]),
    ).toMatchObject({
      command: "alerts",
      action: "list",
      alertState: "open",
      alertSeverity: "high",
      limit: 25,
    });
    expect(() =>
      parseArguments(["alerts", "list", "--state", "unknown"]),
    ).toThrow(/--state must be/);
  });

  it("parses bounded JSON/CSV export options and filters", () => {
    expect(
      parseArguments([
        "export",
        "--format",
        "csv",
        "--output",
        "./results.csv",
        "--range",
        "7d",
        "--severity",
        "high",
      ]),
    ).toMatchObject({
      command: "export",
      exportFormat: "csv",
      outputPath: "./results.csv",
      exportFilters: { range: "7d", severity: "high" },
    });
    expect(() => parseArguments(["export", "--format", "xml"])).toThrow(
      /--format must be/,
    );
  });

  it("prints help when requested and rejects unknown commands and options", () => {
    expect(parseArguments(["--help"]).command).toBe("help");
    expect(() => parseArguments(["bogus"])).toThrow(UsageError);
    expect(() => parseArguments(["doctor", "--unknown"])).toThrow(UsageError);
    expect(() => parseArguments(["doctor", "--db"])).toThrow(
      /requires a value/,
    );
  });
});
