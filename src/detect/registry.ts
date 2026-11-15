import type { DetectionRule, EventCategory, RuleThresholds } from "../types.js";
import authBurst from "./rules/auth-burst.js";
import failureThenSuccess from "./rules/ssh-failure-then-success.js";
import outOfHours from "./rules/out-of-hours.js";
import privilegeSequence from "./rules/privilege-sequence.js";
import repeatedSshFailures from "./rules/ssh-repeated-failures.js";
import sshUsernameSpray from "./rules/ssh-username-spray.js";
import sudoFailures from "./rules/sudo-failures.js";
import thresholdBreach from "./rules/threshold-breach.js";

const CATEGORIES: readonly EventCategory[] = [
  "authentication",
  "privilege",
  "session",
  "account",
  "other",
];

export const RULES: readonly DetectionRule[] = [
  repeatedSshFailures,
  sshUsernameSpray,
  failureThenSuccess,
  authBurst,
  sudoFailures,
  privilegeSequence,
  outOfHours,
  thresholdBreach,
];

const RULES_BY_ID = new Map(RULES.map((rule) => [rule.id, rule]));

if (RULES_BY_ID.size !== RULES.length) {
  throw new Error("detection rule identifiers must be unique");
}

export class RuleConfigurationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RuleConfigurationError";
  }
}

export function getRule(ruleId: string): DetectionRule | undefined {
  return RULES_BY_ID.get(ruleId);
}

export function validateRuleThresholds(
  rule: DetectionRule,
  input: unknown,
): RuleThresholds {
  if (!isRecord(input)) {
    throw new RuleConfigurationError("rule thresholds must be an object");
  }
  const output: Record<string, number | string | boolean> = {
    ...rule.defaults,
  };

  for (const [key, value] of Object.entries(input)) {
    const fallback = rule.defaults[key];
    if (fallback === undefined) {
      throw new RuleConfigurationError(
        `unknown threshold '${key}' for ${rule.id}`,
      );
    }
    if (typeof fallback === "number") {
      if (typeof value !== "number" || !Number.isSafeInteger(value)) {
        throw new RuleConfigurationError(
          `${rule.id}.${key} must be an integer`,
        );
      }
      const bounds = numericBounds(key);
      if (value < bounds.minimum || value > bounds.maximum) {
        throw new RuleConfigurationError(
          `${rule.id}.${key} must be between ${bounds.minimum} and ${bounds.maximum}`,
        );
      }
      output[key] = value;
      continue;
    }
    if (typeof fallback === "string") {
      if (typeof value !== "string") {
        throw new RuleConfigurationError(`${rule.id}.${key} must be a string`);
      }
      if (key === "category" && !CATEGORIES.includes(value as EventCategory)) {
        throw new RuleConfigurationError(
          `${rule.id}.${key} is not a supported event category`,
        );
      }
      if (value.length === 0 || value.length > 128) {
        throw new RuleConfigurationError(
          `${rule.id}.${key} has an invalid length`,
        );
      }
      output[key] = value;
      continue;
    }
    if (typeof value !== "boolean") {
      throw new RuleConfigurationError(`${rule.id}.${key} must be a boolean`);
    }
    output[key] = value;
  }

  if (
    typeof output["startHour"] === "number" &&
    typeof output["endHour"] === "number" &&
    output["startHour"] === output["endHour"]
  ) {
    throw new RuleConfigurationError(
      `${rule.id} startHour and endHour must differ`,
    );
  }
  return output;
}

function numericBounds(key: string): { minimum: number; maximum: number } {
  if (key === "windowMs") return { minimum: 1_000, maximum: 604_800_000 };
  if (key === "startHour" || key === "endHour") {
    return { minimum: 0, maximum: 23 };
  }
  if (key === "count") return { minimum: 1, maximum: 100_000 };
  return { minimum: 0, maximum: 1_000_000 };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
