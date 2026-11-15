export type SourceType = "authlog" | "journal" | "ndjson" | "syslog";
export type EventCategory =
  "authentication" | "privilege" | "session" | "account" | "other";
export type EventOutcome = "success" | "failure" | "unknown";
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
  readonly outcome: EventOutcome;
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

export interface ParseFailure {
  readonly source: string;
  readonly offset: number;
  readonly lineNumber: number;
  readonly reason: string;
  readonly sample: string;
}

export interface RawRecord {
  readonly source: string;
  readonly sourceType: SourceType;
  readonly offset: number;
  readonly nextOffset: number;
  readonly lineNumber: number;
  readonly nextLineNumber: number;
  readonly content: string;
  readonly empty: boolean;
  readonly oversized: boolean;
  readonly fileId: string;
  readonly checkpointHash: string;
}

export interface Checkpoint {
  readonly path: string;
  readonly inode: string;
  readonly size: number;
  readonly offset: number;
  readonly lineNumber: number;
  readonly lastHash: string | null;
}

export interface SourceRegistration {
  readonly name: string;
  readonly sourceType: SourceType;
  readonly path: string;
}

export interface CheckpointRepository {
  registerSource(source: SourceRegistration): void;
  load(sourceName: string): Checkpoint | null;
  save(sourceName: string, checkpoint: Checkpoint): void;
}

export interface SourceReader extends SourceRegistration {
  read(signal: AbortSignal): AsyncIterable<RawRecord>;
  checkpoint(): Checkpoint;
  commit(record: RawRecord): void;
}

export interface ParserContext {
  readonly ingestedAt?: number;
  readonly referenceTime?: number;
  readonly observedRange?: { readonly start: number; readonly end: number };
}

export type ParseResult =
  | { readonly ok: true; readonly event: SecurityEvent }
  | { readonly ok: false; readonly failure: ParseFailure };

export type Parser = (
  record: RawRecord,
  context?: ParserContext,
) => ParseResult;

export type RuleThresholds = Readonly<
  Record<string, number | string | boolean>
>;

export interface RuleMatch {
  readonly ruleId: string;
  readonly ruleVersion: number;
  readonly dedupKey: string;
  readonly severity: Severity;
  readonly rationale: string;
  readonly thresholds: RuleThresholds;
  readonly windowStart: number;
  readonly windowEnd: number;
  readonly eventIds: readonly string[];
}

export interface DetectionRule {
  readonly id: string;
  readonly version: number;
  readonly name: string;
  readonly description: string;
  readonly severity: Severity;
  readonly categories: readonly EventCategory[];
  readonly defaults: RuleThresholds;
  evaluate(
    events: readonly SecurityEvent[],
    thresholds: RuleThresholds,
  ): readonly RuleMatch[];
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
  readonly thresholds: RuleThresholds;
  readonly eventIds: readonly string[];
}

export interface AlertNote {
  readonly id: number;
  readonly alertId: number;
  readonly createdAt: number;
  readonly note: string;
}

export interface RuleConfiguration {
  readonly ruleId: string;
  readonly enabled: boolean;
  readonly thresholds: RuleThresholds;
  readonly updatedAt: number;
}
