export type SourceType = "authlog" | "journal" | "ndjson" | "syslog";
export type EventCategory =
  "authentication" | "privilege" | "session" | "account" | "other";
export type Outcome = "success" | "failure" | "unknown";
export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type AlertState = "open" | "acknowledged" | "resolved";
export type CorrelationField = "ip" | "username" | "host" | "category" | "rule";

export interface SecurityEvent {
  readonly id: string;
  readonly timestamp: number;
  readonly ingestedAt: number;
  readonly source: string;
  readonly sourceType: SourceType;
  readonly host: string | null;
  readonly category: EventCategory;
  readonly action: string;
  readonly outcome: Outcome;
  readonly severity: Severity;
  readonly username: string | null;
  readonly sourceIp: string | null;
  readonly process: {
    readonly name: string;
    readonly pid: number | null;
  } | null;
  readonly message: string;
  readonly metadata: Readonly<Record<string, string | number | boolean>>;
  readonly parserVersion: string;
  readonly inferred: readonly string[];
}

export interface EventPage {
  readonly events: readonly SecurityEvent[];
  readonly page: number;
  readonly limit: number;
  readonly total: number;
}

export interface Overview {
  readonly generatedAt: number;
  readonly totals: {
    readonly events: number;
    readonly parseFailures: number;
    readonly sources: number;
    readonly alerts: number;
  };
  readonly activeAlerts: number;
  readonly recentAlerts: readonly Alert[];
  readonly severity: readonly {
    readonly severity: Severity;
    readonly count: number;
  }[];
  readonly recentEvents: readonly SecurityEvent[];
  readonly ingestionHealth: readonly {
    readonly name: string;
    readonly status: string;
    readonly lastSeen: number | null;
    readonly errorCount: number;
    readonly lastError: string | null;
  }[];
}

export interface RuleView {
  readonly id: string;
  readonly version: number;
  readonly name: string;
  readonly description: string;
  readonly severity: Severity;
  readonly categories: readonly EventCategory[];
  readonly enabled: boolean;
  readonly thresholds: Readonly<Record<string, number | string | boolean>>;
  readonly updatedAt: number | null;
}

export interface Alert {
  readonly id: number;
  readonly ruleId: string;
  readonly dedupKey: string;
  readonly severity: Severity;
  readonly state: AlertState;
  readonly firstSeen: number;
  readonly lastSeen: number;
  readonly occurrences: number;
  readonly rationale: string;
  readonly thresholds: Readonly<Record<string, number | string | boolean>>;
  readonly eventIds: readonly string[];
}

export interface AlertNote {
  readonly id: number;
  readonly alertId: number;
  readonly createdAt: number;
  readonly note: string;
}

export interface SourceStatus {
  readonly name: string;
  readonly sourceType: SourceType;
  readonly path: string;
  readonly status: string;
  readonly lastSeen: number | null;
  readonly errorCount: number;
  readonly lastError: string | null;
}

export interface CorrelationGroup {
  readonly by: CorrelationField;
  readonly key: string;
  readonly label: string;
  readonly events: readonly SecurityEvent[];
}

export interface SystemStatus {
  readonly version: string;
  readonly uptimeSeconds: number;
  readonly integrity: string;
  readonly database: { readonly path: string; readonly bytes: number };
  readonly retentionDays: number;
  readonly detection: {
    readonly maxWindowEvents: number;
    readonly maxWindowBytes: number;
  };
}
