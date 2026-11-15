import type { DetectionRule, RuleMatch, RuleThresholds } from "../types.js";
import { AlertStore } from "../alerts/store.js";
import { getEventsInWindow } from "../store/detection-queries.js";
import {
  getRuleConfiguration,
  getRuleConfigurations,
  saveRuleConfiguration,
} from "../store/detection-queries.js";
import type { EventDatabase } from "../store/database.js";
import { getLatestEventTimestamp } from "../store/detection-queries.js";
import { getRule, RULES, validateRuleThresholds } from "./registry.js";

const DEFAULT_REPLAY_WINDOW_MS = 86_400_000;
const MAX_MATCHES_PER_EVALUATION = 1_000;

export interface DetectionEngineOptions {
  readonly maxWindowEvents: number;
  readonly maxWindowBytes: number;
}

export interface RuleView {
  readonly id: string;
  readonly version: number;
  readonly name: string;
  readonly description: string;
  readonly severity: DetectionRule["severity"];
  readonly categories: DetectionRule["categories"];
  readonly enabled: boolean;
  readonly thresholds: RuleThresholds;
  readonly updatedAt: number | null;
}

export interface DetectionResult {
  readonly matches: readonly RuleMatch[];
  readonly alerts: ReturnType<AlertStore["upsert"]>[];
  readonly recordedMatches: number;
  readonly newAlerts: number;
  readonly evidenceUpdates: number;
}

export class DetectionWindowLimitError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DetectionWindowLimitError";
  }
}

export class DetectionEngine {
  private readonly alerts: AlertStore;

  constructor(
    private readonly database: EventDatabase,
    private readonly options: DetectionEngineOptions = {
      maxWindowEvents: 2_000,
      maxWindowBytes: 67_108_864,
    },
  ) {
    if (
      !Number.isSafeInteger(options.maxWindowEvents) ||
      options.maxWindowEvents < 1 ||
      options.maxWindowEvents > 10_000 ||
      !Number.isSafeInteger(options.maxWindowBytes) ||
      options.maxWindowBytes < 1 ||
      options.maxWindowBytes > 268_435_456
    ) {
      throw new RangeError("detection event window limits are invalid");
    }
    this.alerts = new AlertStore(database);
  }

  listRules(): RuleView[] {
    const stored = this.database.withDatabase(getRuleConfigurations);
    return RULES.map((rule) => {
      const current = stored.get(rule.id);
      const thresholds = validateRuleThresholds(
        rule,
        current?.thresholds ?? rule.defaults,
      );
      return {
        id: rule.id,
        version: rule.version,
        name: rule.name,
        description: rule.description,
        severity: rule.severity,
        categories: rule.categories,
        enabled: current?.enabled ?? true,
        thresholds,
        updatedAt: current?.updatedAt ?? null,
      };
    });
  }

  configureRule(
    ruleId: string,
    configuration: {
      readonly enabled?: boolean;
      readonly thresholds?: unknown;
    },
  ): RuleView {
    const rule = getRule(ruleId);
    if (rule === undefined) throw new RangeError(`unknown rule '${ruleId}'`);
    const current = this.database.withDatabase((connection) =>
      getRuleConfiguration(connection, ruleId),
    );
    const enabled = configuration.enabled ?? current?.enabled ?? true;
    if (typeof enabled !== "boolean") {
      throw new TypeError("rule enabled state must be a boolean");
    }

    let thresholds = validateRuleThresholds(
      rule,
      current?.thresholds ?? rule.defaults,
    );
    if (configuration.thresholds !== undefined) {
      if (!isRecord(configuration.thresholds)) {
        throw new TypeError("rule thresholds must be an object");
      }
      thresholds = validateRuleThresholds(rule, {
        ...thresholds,
        ...configuration.thresholds,
      });
    }

    const updatedAt = Date.now();
    this.database.withDatabase((connection) => {
      saveRuleConfiguration(connection, ruleId, enabled, thresholds, updatedAt);
    });
    const view = this.listRules().find((candidate) => candidate.id === ruleId);
    if (view === undefined) throw new Error("configured rule was not found");
    return view;
  }

  evaluateAt(timestamp: number, triggerEventId: string): DetectionResult {
    if (
      !Number.isSafeInteger(timestamp) ||
      timestamp < 0 ||
      triggerEventId.length === 0
    ) {
      throw new RangeError(
        "detection timestamp must be a non-negative integer",
      );
    }
    const views = this.listRules();
    const enabledRules = views
      .filter((view) => view.enabled)
      .map((view) => {
        const definition = getRule(view.id);
        if (definition === undefined)
          throw new Error("registered rule is unavailable");
        return { definition, thresholds: view.thresholds };
      });
    if (enabledRules.length === 0) {
      return {
        matches: [],
        alerts: [],
        recordedMatches: 0,
        newAlerts: 0,
        evidenceUpdates: 0,
      };
    }

    const maxWindowMs = Math.max(
      DEFAULT_REPLAY_WINDOW_MS,
      ...enabledRules.map(({ thresholds }) => {
        const window = thresholds["windowMs"];
        return typeof window === "number" ? window : 0;
      }),
    );
    const start = Math.max(0, timestamp - maxWindowMs);
    const end = Math.min(Number.MAX_SAFE_INTEGER, timestamp + maxWindowMs);
    const events = this.database.withDatabase((connection) =>
      getEventsInWindow(
        connection,
        start,
        end,
        this.options.maxWindowEvents + 1,
        this.options.maxWindowBytes,
      ),
    );
    if (events.length > this.options.maxWindowEvents) {
      throw new DetectionWindowLimitError(
        `detection window contains more than ${this.options.maxWindowEvents} events; no matches were discarded`,
      );
    }

    const matches = enabledRules
      .flatMap(({ definition, thresholds }) =>
        definition.evaluate(events, thresholds),
      )
      .filter((match) => match.eventIds.includes(triggerEventId));
    if (matches.length > MAX_MATCHES_PER_EVALUATION) {
      throw new DetectionWindowLimitError(
        `detection produced more than ${MAX_MATCHES_PER_EVALUATION} matches; no matches were discarded`,
      );
    }
    const upserts = matches.map((match) => this.alerts.upsertWithResult(match));
    return {
      matches,
      alerts: upserts.map(({ alert }) => alert),
      recordedMatches: upserts.filter(
        ({ created, evidenceAdded }) => created || evidenceAdded > 0,
      ).length,
      newAlerts: upserts.filter(({ created }) => created).length,
      evidenceUpdates: upserts.filter(
        ({ created, evidenceAdded }) => !created && evidenceAdded > 0,
      ).length,
    };
  }

  latestEventTimestamp(): number | null {
    return this.database.withDatabase(getLatestEventTimestamp);
  }

  getAlertStore(): AlertStore {
    return this.alerts;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
