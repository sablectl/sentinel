import { describe, expect, it } from "vitest";
import type { RuleThresholds, SecurityEvent } from "../../src/types.js";
import { correlate, CORRELATION_LABEL } from "../../src/correlate/correlate.js";
import {
  getRule,
  RULES,
  validateRuleThresholds,
} from "../../src/detect/registry.js";

const BASE_TIME = Date.UTC(2025, 10, 14, 12);

function event(
  index: number,
  overrides: Partial<SecurityEvent> = {},
): SecurityEvent {
  return {
    id: `event-${index}`,
    timestamp: BASE_TIME + index * 1_000,
    ingestedAt: BASE_TIME,
    source: "fixture",
    sourceType: "ndjson",
    host: "host-01",
    category: "authentication",
    action: "ssh.authentication.failure",
    outcome: "failure",
    severity: "medium",
    username: "operator",
    sourceIp: "203.0.113.10",
    process: null,
    message: "synthetic fixture event",
    metadata: {},
    parserVersion: "ndjson/1",
    inferred: [],
    ...overrides,
  };
}

function evaluate(
  ruleId: string,
  events: readonly SecurityEvent[],
  thresholds?: RuleThresholds,
) {
  const rule = getRule(ruleId);
  if (rule === undefined) throw new Error(`missing test rule ${ruleId}`);
  return rule.evaluate(
    events,
    validateRuleThresholds(rule, thresholds ?? rule.defaults),
  );
}

describe("initial detection rules", () => {
  it("repeated SSH failures fires at five and stays quiet below threshold", () => {
    expect(
      evaluate(
        "ssh.repeated_failures",
        Array.from({ length: 5 }, (_, index) => event(index)),
      ),
    ).toHaveLength(1);
    expect(
      evaluate(
        "ssh.repeated_failures",
        Array.from({ length: 4 }, (_, index) => event(index)),
      ),
    ).toEqual([]);
  });

  it("username spray fires for eight distinct usernames but not seven", () => {
    const eightUsers = Array.from({ length: 8 }, (_, index) =>
      event(index, { username: `account-${index}` }),
    );
    expect(evaluate("ssh.username_spray", eightUsers)).toHaveLength(1);
    expect(evaluate("ssh.username_spray", eightUsers.slice(0, 7))).toEqual([]);
  });

  it("failure followed by success requires the same IP and username within the window", () => {
    const failure = event(0);
    const success = event(1, {
      action: "ssh.authentication.success",
      outcome: "success",
      severity: "info",
    });
    expect(
      evaluate("ssh.failure_then_success", [failure, success]),
    ).toHaveLength(1);
    expect(
      evaluate("ssh.failure_then_success", [
        failure,
        event(901, {
          action: "ssh.authentication.success",
          outcome: "success",
        }),
      ]),
    ).toEqual([]);
    expect(
      evaluate("ssh.failure_then_success", [
        failure,
        event(1, {
          action: "ssh.authentication.success",
          outcome: "success",
          username: "different-user",
        }),
      ]),
    ).toEqual([]);
  });

  it("authentication burst fires at twenty events and not nineteen", () => {
    const events = Array.from({ length: 20 }, (_, index) => event(index));
    expect(evaluate("auth.burst", events)).toHaveLength(1);
    expect(evaluate("auth.burst", events.slice(0, 19))).toEqual([]);
  });

  it("sudo failures fires at three and stays quiet at two", () => {
    const failures = Array.from({ length: 3 }, (_, index) =>
      event(index, { action: "sudo.authentication.failure" }),
    );
    expect(evaluate("sudo.repeated_failures", failures)).toHaveLength(1);
    expect(evaluate("sudo.repeated_failures", failures.slice(0, 2))).toEqual(
      [],
    );
  });

  it("privilege sequence requires a sudo indicator before a session indicator", () => {
    const sudo = event(0, { action: "sudo.command", category: "privilege" });
    const session = event(1, {
      action: "session.opened",
      category: "session",
      outcome: "success",
    });
    expect(
      evaluate("privilege.sudo_session_sequence", [sudo, session]),
    ).toHaveLength(1);
    expect(
      evaluate("privilege.sudo_session_sequence", [
        session,
        event(2, { action: "sudo.command", category: "privilege" }),
      ]),
    ).toEqual([]);
    expect(
      evaluate("privilege.sudo_session_sequence", [
        sudo,
        event(601, { action: "session.opened", category: "session" }),
      ]),
    ).toEqual([]);
  });

  it("out-of-hours success fires at 23:00 UTC and not at midday", () => {
    expect(
      evaluate("auth.out_of_hours", [
        event(0, {
          timestamp: Date.UTC(2025, 10, 14, 23),
          action: "ssh.authentication.success",
          outcome: "success",
        }),
      ]),
    ).toHaveLength(1);
    expect(
      evaluate("auth.out_of_hours", [
        event(0, {
          timestamp: Date.UTC(2025, 10, 14, 12),
          action: "ssh.authentication.success",
          outcome: "success",
        }),
      ]),
    ).toEqual([]);
  });

  it("generic threshold breach fires at twenty-five events and not twenty-four", () => {
    const events = Array.from({ length: 25 }, (_, index) => event(index));
    expect(evaluate("event.threshold_breach", events)).toHaveLength(1);
    expect(evaluate("event.threshold_breach", events.slice(0, 24))).toEqual([]);
  });

  it("registers eight stable rule definitions and validates tunable bounds", () => {
    expect(RULES).toHaveLength(8);
    const rule = getRule("ssh.repeated_failures");
    if (rule === undefined) throw new Error("test rule not registered");
    expect(() => validateRuleThresholds(rule, { count: 0 })).toThrow(/between/);
    expect(() =>
      validateRuleThresholds(rule, { count: 10, injected: true }),
    ).toThrow(/unknown threshold/);
  });

  it("does not raise indicators for ordinary daytime authentication successes", () => {
    const ordinary = Array.from({ length: 10 }, (_, index) =>
      event(index, {
        action: "ssh.authentication.success",
        outcome: "success",
        severity: "info",
        username: "operator",
        timestamp: Date.UTC(2025, 10, 14, 12, 0, index),
      }),
    );
    for (const rule of RULES) {
      expect(
        rule.evaluate(ordinary, validateRuleThresholds(rule, rule.defaults)),
      ).toEqual([]);
    }
  });
});

describe("correlation", () => {
  it("orders shared-IP groups deterministically and applies a hard group cap", () => {
    const events = [
      event(2, { sourceIp: "203.0.113.2" }),
      event(0, { sourceIp: "203.0.113.1" }),
      event(1, { sourceIp: "203.0.113.1" }),
      event(3, { sourceIp: null }),
    ];
    const groups = correlate(events, {
      by: "ip",
      windowMs: 60_000,
      limit: 1,
    });
    expect(groups).toHaveLength(1);
    expect(groups[0]).toMatchObject({
      key: "203.0.113.1",
      label: CORRELATION_LABEL,
      events: [{ id: "event-0" }, { id: "event-1" }],
    });
  });

  it("supports rule-id groupings without implying attribution", () => {
    const item = event(1);
    const groups = correlate([item], {
      by: "rule",
      windowMs: 60_000,
      limit: 10,
      ruleIdsByEvent: new Map([[item.id, ["ssh.repeated_failures"]]]),
    });
    expect(groups[0]?.key).toBe("ssh.repeated_failures");
    expect(groups[0]?.label).toBe(CORRELATION_LABEL);
  });

  it("rejects invalid limits and windows", () => {
    expect(() =>
      correlate([event(0)], { by: "host", windowMs: 1, limit: 10 }),
    ).toThrow(/invalid/);
    expect(() =>
      correlate([event(0)], { by: "host", windowMs: 60_000, limit: 1_001 }),
    ).toThrow(/invalid/);
  });
});
