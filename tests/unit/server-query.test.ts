import { describe, expect, it } from "vitest";
import {
  parseAlertQuery,
  parseCorrelationQuery,
  parseEventQuery,
} from "../../src/server/query.js";

const NOW = Date.UTC(2025, 10, 14, 12);

describe("HTTP query validation", () => {
  it("applies a bounded default event range and validates allowed filters", () => {
    const parsed = parseEventQuery(
      new URLSearchParams("range=1h&limit=25&sort=severity"),
      NOW,
    );
    expect(parsed).toMatchObject({
      ok: true,
      value: {
        from: NOW - 3_600_000,
        to: NOW,
        page: 1,
        limit: 25,
        sort: "severity",
        direction: "desc",
      },
    });
  });

  it("rejects repeated, unknown, unsafe and inconsistent event parameters", () => {
    expect(parseEventQuery(new URLSearchParams("page=1&page=2"), NOW).ok).toBe(
      false,
    );
    expect(
      parseEventQuery(new URLSearchParams("sort=timestamp%20DESC"), NOW).ok,
    ).toBe(false);
    expect(parseEventQuery(new URLSearchParams("from=100&to=10"), NOW).ok).toBe(
      false,
    );
    expect(
      parseEventQuery(new URLSearchParams("range=1h&from=10"), NOW).ok,
    ).toBe(false);
    expect(
      parseEventQuery(new URLSearchParams("source=log&sql=1"), NOW).ok,
    ).toBe(false);
    expect(parseEventQuery(new URLSearchParams("ip=999.0.0.1"), NOW).ok).toBe(
      false,
    );
  });

  it("validates alert and correlation filters and caps pagination", () => {
    expect(
      parseAlertQuery(new URLSearchParams("state=open&severity=high&page=2")),
    ).toMatchObject({
      ok: true,
      value: { state: "open", severity: "high", limit: 100, offset: 100 },
    });
    expect(
      parseAlertQuery(new URLSearchParams("state=resolved%20OR%201=1")).ok,
    ).toBe(false);
    expect(
      parseCorrelationQuery(
        new URLSearchParams(
          "by=username&windowMs=120000&limit=50&value=operator",
        ),
        NOW,
      ),
    ).toMatchObject({
      ok: true,
      value: {
        by: "username",
        windowMs: 120_000,
        limit: 50,
        endTime: NOW,
        value: "operator",
      },
    });
    expect(
      parseCorrelationQuery(new URLSearchParams("windowMs=999999999"), NOW).ok,
    ).toBe(false);
  });
});
