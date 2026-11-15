import type { SecurityEvent } from "../types.js";
import type { EventQuery } from "../store/event-queries.js";
import { redactEvents } from "./redaction.js";

export interface ExportMetadata {
  readonly generatedAt: string;
  readonly filters: Readonly<Record<string, string | number>>;
  readonly relevantRules: readonly string[];
  readonly eventCount: number;
  readonly redacted: boolean;
  readonly limitations: string;
}

export interface PreparedExport {
  readonly metadata: ExportMetadata;
  readonly events: readonly SecurityEvent[];
}

export function prepareExport(
  events: readonly SecurityEvent[],
  filters: EventQuery,
  relevantRules: readonly string[],
  redactSensitiveFields: boolean,
  generatedAt = Date.now(),
): PreparedExport {
  if (
    !Number.isSafeInteger(generatedAt) ||
    generatedAt < 0 ||
    !Number.isFinite(new Date(generatedAt).getTime()) ||
    events.length > 10_000
  ) {
    throw new RangeError("export metadata inputs are invalid");
  }
  const appliedFilters: Record<string, string | number> = {};
  for (const [key, value] of Object.entries(filters)) {
    if (typeof value === "string" || typeof value === "number") {
      appliedFilters[key] = value;
    }
  }
  const uniqueRules = [...new Set(relevantRules)]
    .filter((ruleId) => /^[a-z0-9._-]{1,128}$/.test(ruleId))
    .sort();
  return {
    metadata: {
      generatedAt: new Date(generatedAt).toISOString(),
      filters: appliedFilters,
      relevantRules: uniqueRules,
      eventCount: events.length,
      redacted: redactSensitiveFields,
      limitations:
        "Detection rules identify indicators, not confirmed compromise. Parser coverage is limited to documented formats; missing or redacted fields may change investigation context.",
    },
    events: redactEvents(events, redactSensitiveFields),
  };
}
