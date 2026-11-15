import { describe, expect, it } from "vitest";
import type { RawRecord, SourceType } from "../../src/types.js";
import { parseAuthlog } from "../../src/parse/authlog.js";
import { parseJournal } from "../../src/parse/journal.js";
import { parseNdjson } from "../../src/parse/ndjson.js";
import { parseSyslog } from "../../src/parse/syslog.js";
import { parseYearlessTimestamp } from "../../src/parse/common.js";

const INGESTED_AT = Date.UTC(2026, 10, 14, 12, 35);

function rawRecord(
  content: string,
  sourceType: SourceType,
  oversized = false,
): RawRecord {
  return {
    source: "fixture",
    sourceType,
    offset: 12,
    nextOffset: 12 + Buffer.byteLength(content) + 1,
    lineNumber: 1,
    nextLineNumber: 2,
    content,
    empty: content.length === 0,
    oversized,
    fileId: "1:2",
    checkpointHash: "checkpoint-hash",
  };
}

describe("authentication log parser", () => {
  it("normalises failed SSH authentication and flags the inferred year", () => {
    const result = parseAuthlog(
      rawRecord(
        "Nov 14 12:34:56 web-01 sshd[1122]: Failed password for invalid user admin from 203.0.113.8 port 53212 ssh2",
        "authlog",
      ),
      { ingestedAt: INGESTED_AT, referenceTime: INGESTED_AT },
    );

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.event).toMatchObject({
      timestamp: Date.UTC(2026, 10, 14, 12, 34, 56),
      host: "web-01",
      category: "authentication",
      action: "ssh.authentication.failure",
      outcome: "failure",
      username: "admin",
      sourceIp: "203.0.113.8",
      process: { name: "sshd", pid: 1122 },
      inferred: ["timestamp.year"],
      parserVersion: "authlog/1",
    });
  });

  it("isolates malformed and oversized authentication records", () => {
    expect(parseAuthlog(rawRecord("not an auth log", "authlog")).ok).toBe(
      false,
    );
    const oversized = parseAuthlog(
      rawRecord("Nov 14 12:34:56 host sshd: text", "authlog", true),
    );
    expect(oversized.ok).toBe(false);
    if (!oversized.ok) expect(oversized.failure.reason).toMatch(/size limit/);
  });

  it("strips terminal control sequences while retaining an escaped original", () => {
    const result = parseAuthlog(
      rawRecord(
        "Nov 14 12:34:56 host sshd: Accepted password for alice from 203.0.113.9 port 22 \u001b[31mssh2\u001b[0m\u0000",
        "authlog",
      ),
      { ingestedAt: INGESTED_AT, referenceTime: INGESTED_AT },
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.event.message).not.toContain("\u001b");
    expect(result.event.message).not.toContain("\u0000");
    expect(result.event.metadata["originalEscaped"]).toContain("\\u001b");
  });
});

describe("NDJSON parser", () => {
  it("accepts a canonical event and leaves absent attributes null", () => {
    const result = parseNdjson(
      rawRecord(
        JSON.stringify({
          timestamp: "2025-11-14T12:34:56Z",
          action: "account.audit",
          message: "account record",
        }),
        "ndjson",
      ),
      { ingestedAt: INGESTED_AT },
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.event).toMatchObject({
      timestamp: Date.UTC(2025, 10, 14, 12, 34, 56),
      category: "other",
      outcome: "unknown",
      severity: "info",
      host: null,
      username: null,
      sourceIp: null,
      process: null,
      parserVersion: "ndjson/1",
      ingestedAt: INGESTED_AT,
    });
  });

  it("rejects malformed JSON, invalid IP fields and nested metadata", () => {
    expect(parseNdjson(rawRecord("{", "ndjson")).ok).toBe(false);
    expect(
      parseNdjson(
        rawRecord(
          JSON.stringify({
            timestamp: 1,
            action: "test",
            sourceIp: "999.1.1.1",
          }),
          "ndjson",
        ),
      ).ok,
    ).toBe(false);
    expect(
      parseNdjson(
        rawRecord(
          JSON.stringify({
            timestamp: 1,
            action: "test",
            metadata: { nested: {} },
          }),
          "ndjson",
        ),
      ).ok,
    ).toBe(false);
  });

  it("sanitises untrusted canonical fields and metadata", () => {
    const result = parseNdjson(
      rawRecord(
        JSON.stringify({
          timestamp: "2025-11-14T12:34:56Z",
          action: "audit\u001b[31m",
          host: "host-01\u0000",
          username: "operator\u001b[0m",
          metadata: { note: "review\u001b[32m" },
        }),
        "ndjson",
      ),
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.event).toMatchObject({
      action: "audit",
      host: "host-01",
      username: "operator",
      metadata: {
        note: "review",
      },
    });
    expect(result.event.metadata["originalEscaped"]).toContain("\\u001b");
  });

  it("rejects impossible calendar dates instead of normalising them", () => {
    expect(
      parseNdjson(
        rawRecord(
          JSON.stringify({
            timestamp: "2025-02-31T12:00:00Z",
            action: "date.check",
          }),
          "ndjson",
        ),
      ).ok,
    ).toBe(false);
  });

  it("produces a stable event identifier across ingestion times", () => {
    const raw = rawRecord(
      JSON.stringify({
        timestamp: 1,
        action: "test",
        metadata: { z: 2, a: 1 },
      }),
      "ndjson",
    );
    const first = parseNdjson(raw, { ingestedAt: 10 });
    const second = parseNdjson(raw, { ingestedAt: 20 });
    expect(first.ok && second.ok && first.event.id).toBe(
      second.ok ? second.event.id : "",
    );
  });
});

describe("journal export parser", () => {
  it("parses a text export record and SSH indicator fields", () => {
    const content = [
      "__REALTIME_TIMESTAMP=1763123696000000",
      "MESSAGE=Failed password for invalid user root from 203.0.113.7 port 22 ssh2",
      "_HOSTNAME=web-02",
      "SYSLOG_IDENTIFIER=sshd",
      "_PID=77",
      "PRIORITY=4",
    ].join("\n");
    const result = parseJournal(rawRecord(content, "journal"), {
      ingestedAt: INGESTED_AT,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.event).toMatchObject({
      sourceType: "journal",
      host: "web-02",
      category: "authentication",
      action: "ssh.authentication.failure",
      username: "root",
      sourceIp: "203.0.113.7",
      process: { name: "sshd", pid: 77 },
      timestamp: 1_763_123_696_000,
      parserVersion: "journal-export/1",
    });
  });

  it("isolates binary fields and absent timestamps", () => {
    expect(parseJournal(rawRecord("MESSAGE\n4\ntest", "journal")).ok).toBe(
      false,
    );
    expect(parseJournal(rawRecord("MESSAGE=test", "journal")).ok).toBe(false);
  });
});

describe("syslog parser", () => {
  it("parses RFC 3164 and RFC 5424 authentication records", () => {
    const rfc3164 = parseSyslog(
      rawRecord(
        "<34>Nov 14 12:34:56 edge-01 sshd[55]: Failed password for root from 203.0.113.4 port 22 ssh2",
        "syslog",
      ),
      { ingestedAt: INGESTED_AT, referenceTime: INGESTED_AT },
    );
    const rfc5424 = parseSyslog(
      rawRecord(
        "<34>1 2025-11-14T12:34:56Z edge-01 sshd 55 ID47 - Accepted password for alice from 203.0.113.4 port 22 ssh2",
        "syslog",
      ),
      { ingestedAt: INGESTED_AT },
    );
    expect(rfc3164.ok && rfc3164.event.inferred).toEqual(["timestamp.year"]);
    expect(rfc5424.ok).toBe(true);
    if (rfc5424.ok) {
      expect(rfc5424.event).toMatchObject({
        host: "edge-01",
        action: "ssh.authentication.success",
        outcome: "success",
        username: "alice",
        sourceIp: "203.0.113.4",
        timestamp: Date.UTC(2025, 10, 14, 12, 34, 56),
      });
    }
  });

  it("rejects unsupported records and invalid priority values", () => {
    expect(parseSyslog(rawRecord("unsupported message", "syslog")).ok).toBe(
      false,
    );
    expect(
      parseSyslog(
        rawRecord(
          "<999>1 2025-11-14T12:34:56Z host app 1 id - message",
          "syslog",
        ),
      ).ok,
    ).toBe(false);
  });
});

describe("yearless timestamps", () => {
  it("chooses the nearest year around a year boundary", () => {
    const reference = Date.UTC(2026, 0, 1, 0, 0);
    expect(parseYearlessTimestamp("Dec 31 23:59:59", reference)).toEqual({
      timestamp: Date.UTC(2025, 11, 31, 23, 59, 59),
      inferred: true,
    });
  });

  it("uses the source's observed timestamp range for yearless auth records", () => {
    const observedRange = {
      start: Date.UTC(2025, 11, 31, 23, 55),
      end: Date.UTC(2026, 0, 1, 0, 5),
    };
    const beforeMidnight = parseAuthlog(
      rawRecord(
        "Dec 31 23:59:59 host sshd: session opened for user root",
        "authlog",
      ),
      { observedRange, referenceTime: Date.UTC(2027, 6, 1) },
    );
    const afterMidnight = parseAuthlog(
      rawRecord(
        "Jan  1 00:00:01 host sshd: session opened for user root",
        "authlog",
      ),
      { observedRange, referenceTime: Date.UTC(2027, 6, 1) },
    );
    expect(beforeMidnight.ok && beforeMidnight.event.timestamp).toBe(
      Date.UTC(2025, 11, 31, 23, 59, 59),
    );
    expect(afterMidnight.ok && afterMidnight.event.timestamp).toBe(
      Date.UTC(2026, 0, 1, 0, 0, 1),
    );
  });
});
