import { statSync } from "node:fs";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { Config } from "../config/config.js";
import type { AlertLifecycle } from "../alerts/lifecycle.js";
import type { AlertStore } from "../alerts/store.js";
import { correlate } from "../correlate/correlate.js";
import type { DetectionEngine } from "../detect/engine.js";
import { getEventsInWindow } from "../store/detection-queries.js";
import type { EventDatabase } from "../store/database.js";
import { getSourceStatuses } from "../store/queries.js";
import { getEventById, queryEvents } from "../store/event-queries.js";
import { VERSION } from "../version.js";
import { prepareExport } from "../export/metadata.js";
import { exportCsv } from "../export/csv.js";
import { exportJson } from "../export/json.js";
import { getRelevantRuleReferences } from "../export/references.js";
import {
  getRetentionDays,
  setRetentionDays,
} from "../store/system-settings.js";
import type { Session } from "./session.js";
import type { SessionManager } from "./session.js";
import type { EventStream } from "./stream.js";
import { readJsonBody } from "./body.js";
import {
  parseAlertQuery,
  parseCorrelationQuery,
  parseEventQuery,
} from "./query.js";

export interface ApiRouteOptions {
  readonly config: Config;
  readonly database: EventDatabase;
  readonly detection: DetectionEngine;
  readonly alerts: AlertStore;
  readonly lifecycle: AlertLifecycle;
  readonly sessions: SessionManager;
  readonly stream: EventStream;
}

export class ApiRoutes {
  constructor(private readonly options: ApiRouteOptions) {}

  async handle(
    request: IncomingMessage,
    response: ServerResponse,
    url: URL,
    session: Session | null,
  ): Promise<void> {
    const method = request.method ?? "GET";
    const pathname = url.pathname;
    if (pathname === "/api/session" && method === "POST") {
      await this.exchangeSession(request, response);
      return;
    }
    if (session === null) {
      sendJson(response, 401, { error: "authentication required" });
      return;
    }
    if (pathname === "/api/session" && method === "GET") {
      sendJson(response, 200, {
        authenticated: true,
        expiresAt: session.expiresAt,
      });
      return;
    }
    if (pathname === "/api/session/logout" && method === "POST") {
      this.options.sessions.revoke(session);
      response.setHeader(
        "Set-Cookie",
        this.options.sessions.clearCookieHeaders(),
      );
      sendJson(response, 200, { authenticated: false });
      return;
    }
    if (pathname === "/api/overview" && method === "GET") {
      this.overview(response);
      return;
    }
    if (pathname === "/api/events" && method === "GET") {
      this.events(url, response);
      return;
    }
    const eventId = /^\/api\/events\/([0-9a-f]{64})$/.exec(pathname)?.[1];
    if (eventId !== undefined && method === "GET") {
      const event = this.options.database.withDatabase((database) =>
        getEventById(database, eventId),
      );
      if (event === null) sendJson(response, 404, { error: "event not found" });
      else sendJson(response, 200, event);
      return;
    }
    if (pathname === "/api/rules" && method === "GET") {
      sendJson(response, 200, this.options.detection.listRules());
      return;
    }
    const ruleId = /^\/api\/rules\/([a-z0-9._-]{1,128})$/.exec(pathname)?.[1];
    if (ruleId !== undefined && method === "POST") {
      await this.configureRule(request, response, ruleId);
      return;
    }
    if (pathname === "/api/alerts" && method === "GET") {
      this.listAlerts(url, response);
      return;
    }
    const alertId = /^\/api\/alerts\/(\d+)$/.exec(pathname)?.[1];
    if (alertId !== undefined && method === "GET") {
      sendJson(response, 200, this.options.alerts.get(parseAlertId(alertId)));
      return;
    }
    const alertState = /^\/api\/alerts\/(\d+)\/state$/.exec(pathname)?.[1];
    if (alertState !== undefined && method === "POST") {
      await this.updateAlertState(request, response, alertState);
      return;
    }
    const alertNotes = /^\/api\/alerts\/(\d+)\/notes$/.exec(pathname)?.[1];
    if (alertNotes !== undefined && method === "GET") {
      this.listAlertNotes(response, alertNotes);
      return;
    }
    if (alertNotes !== undefined && method === "POST") {
      await this.addAlertNote(request, response, alertNotes);
      return;
    }
    if (pathname === "/api/correlate" && method === "GET") {
      this.correlate(url, response);
      return;
    }
    if (pathname === "/api/export" && method === "POST") {
      await this.export(request, response);
      return;
    }
    if (pathname === "/api/sources" && method === "GET") {
      const sources = this.options.database.withDatabase(getSourceStatuses);
      sendJson(response, 200, sources);
      return;
    }
    if (pathname === "/api/system/retention" && method === "POST") {
      await this.updateRetention(request, response);
      return;
    }
    if (pathname === "/api/system" && method === "GET") {
      this.system(response);
      return;
    }
    sendJson(response, 404, { error: "route not found" });
  }

  private async exchangeSession(
    request: IncomingMessage,
    response: ServerResponse,
  ): Promise<void> {
    const body = await readJsonBody(
      request,
      this.options.config.server.maxBodyBytes,
    );
    if (!hasOnlyKeys(body, ["token"])) {
      sendJson(response, 401, { error: "invalid session token" });
      return;
    }
    const token = body["token"];
    if (typeof token !== "string" || token.length > 512) {
      sendJson(response, 401, { error: "invalid session token" });
      return;
    }
    const session = this.options.sessions.exchange(token);
    if (session === null) {
      sendJson(response, 401, { error: "invalid session token" });
      return;
    }
    response.setHeader(
      "Set-Cookie",
      this.options.sessions.setCookieHeaders(session),
    );
    sendJson(response, 200, {
      authenticated: true,
      expiresAt: session.expiresAt,
    });
  }

  private overview(response: ServerResponse): void {
    const counts = this.options.database.counts();
    const severity = this.options.database.withDatabase((database) =>
      database
        .prepare(
          `SELECT severity, COUNT(*) AS count FROM alerts
           WHERE state != 'resolved' GROUP BY severity ORDER BY severity`,
        )
        .all()
        .map((row) => ({
          severity: row["severity"],
          count: safeNumber(row["count"]),
        })),
    );
    const openAlerts = this.options.alerts.list({ state: "open", limit: 20 });
    const activeAlerts = this.options.database.withDatabase((database) =>
      safeNumber(
        database
          .prepare(
            "SELECT COUNT(*) AS count FROM alerts WHERE state != 'resolved'",
          )
          .get()?.["count"],
      ),
    );
    const recent = this.options.database.withDatabase((database) =>
      queryEvents(database, {
        from: 0,
        to: Number.MAX_SAFE_INTEGER,
        page: 1,
        limit: 10,
        sort: "timestamp",
        direction: "desc",
      }),
    );
    const sources = this.options.database.withDatabase(getSourceStatuses);
    sendJson(response, 200, {
      generatedAt: Date.now(),
      totals: counts,
      activeAlerts,
      recentAlerts: openAlerts,
      severity,
      recentEvents: recent.events,
      ingestionHealth: sources.map((source) => ({
        name: source.name,
        status: source.status,
        lastSeen: source.lastSeen,
        errorCount: source.errorCount,
        lastError: source.lastError,
      })),
    });
  }

  private events(url: URL, response: ServerResponse): void {
    const parsed = parseEventQuery(url.searchParams, Date.now());
    if (!parsed.ok) {
      sendJson(response, 400, { error: parsed.error });
      return;
    }
    const page = this.options.database.withDatabase((database) =>
      queryEvents(database, parsed.value),
    );
    sendJson(response, 200, page);
  }

  private async configureRule(
    request: IncomingMessage,
    response: ServerResponse,
    ruleId: string,
  ): Promise<void> {
    const body = await readJsonBody(
      request,
      this.options.config.server.maxBodyBytes,
    );
    if (!hasOnlyKeys(body, ["enabled", "thresholds"])) {
      sendJson(response, 400, {
        error: "rule configuration contains unknown fields",
      });
      return;
    }
    if (body["enabled"] !== undefined && typeof body["enabled"] !== "boolean") {
      sendJson(response, 400, { error: "enabled must be a boolean" });
      return;
    }
    if (body["enabled"] === undefined && body["thresholds"] === undefined) {
      sendJson(response, 400, { error: "rule configuration is empty" });
      return;
    }
    const rule = this.options.detection.configureRule(ruleId, {
      ...(typeof body["enabled"] === "boolean"
        ? { enabled: body["enabled"] }
        : {}),
      ...(body["thresholds"] === undefined
        ? {}
        : { thresholds: body["thresholds"] }),
    });
    this.options.stream.publish("rules.updated", rule);
    sendJson(response, 200, rule);
  }

  private listAlerts(url: URL, response: ServerResponse): void {
    const parsed = parseAlertQuery(url.searchParams);
    if (!parsed.ok) {
      sendJson(response, 400, { error: parsed.error });
      return;
    }
    const alerts = this.options.alerts.list(parsed.value);
    const total = this.options.alerts.count(parsed.value);
    sendJson(response, 200, {
      alerts,
      page:
        Math.floor((parsed.value.offset ?? 0) / (parsed.value.limit ?? 100)) +
        1,
      limit: parsed.value.limit ?? 100,
      total,
    });
  }

  private async updateAlertState(
    request: IncomingMessage,
    response: ServerResponse,
    idText: string,
  ): Promise<void> {
    const alertId = parseAlertId(idText);
    const body = await readJsonBody(
      request,
      this.options.config.server.maxBodyBytes,
    );
    if (!hasOnlyKeys(body, ["state"])) {
      sendJson(response, 400, { error: "alert state body has unknown fields" });
      return;
    }
    const state = body["state"];
    if (state === "acknowledged") {
      const alert = this.options.lifecycle.acknowledge(alertId);
      this.options.stream.publish("alert.updated", alert);
      sendJson(response, 200, alert);
    } else if (state === "resolved") {
      const alert = this.options.lifecycle.resolve(alertId);
      this.options.stream.publish("alert.updated", alert);
      sendJson(response, 200, alert);
    } else if (state === "open") {
      const alert = this.options.lifecycle.reopen(alertId);
      this.options.stream.publish("alert.updated", alert);
      sendJson(response, 200, alert);
    } else {
      sendJson(response, 400, {
        error: "state must be open, acknowledged or resolved",
      });
    }
  }

  private listAlertNotes(response: ServerResponse, idText: string): void {
    const alertId = parseAlertId(idText);
    this.options.alerts.get(alertId);
    sendJson(response, 200, this.options.alerts.notes(alertId));
  }

  private async addAlertNote(
    request: IncomingMessage,
    response: ServerResponse,
    idText: string,
  ): Promise<void> {
    const alertId = parseAlertId(idText);
    const body = await readJsonBody(
      request,
      this.options.config.server.maxBodyBytes,
    );
    if (!hasOnlyKeys(body, ["note"]) || typeof body["note"] !== "string") {
      sendJson(response, 400, {
        error: "note body must contain only a string note",
      });
      return;
    }
    this.options.alerts.get(alertId);
    const note = this.options.lifecycle.addNote(alertId, body["note"]);
    this.options.stream.publish("alert.note", note);
    sendJson(response, 201, note);
  }

  private correlate(url: URL, response: ServerResponse): void {
    const parsed = parseCorrelationQuery(url.searchParams, Date.now());
    if (!parsed.ok) {
      sendJson(response, 400, { error: parsed.error });
      return;
    }
    const start = Math.max(0, parsed.value.endTime - parsed.value.windowMs);
    const events = this.options.database.withDatabase((database) =>
      getEventsInWindow(
        database,
        start,
        parsed.value.endTime,
        this.options.config.detection.maxWindowEvents,
        this.options.config.detection.maxWindowBytes,
      ),
    );
    const ruleIdsByEvent =
      parsed.value.by === "rule"
        ? this.ruleIdsByEvent(start, parsed.value.endTime)
        : undefined;
    let groups = correlate(events, {
      by: parsed.value.by,
      windowMs: parsed.value.windowMs,
      limit: parsed.value.value === undefined ? parsed.value.limit : 1_000,
      endTime: parsed.value.endTime,
      ...(ruleIdsByEvent === undefined ? {} : { ruleIdsByEvent }),
    });
    if (parsed.value.value !== undefined) {
      groups = groups
        .filter((group) => group.key === parsed.value.value)
        .slice(0, parsed.value.limit);
    }
    sendJson(response, 200, groups);
  }

  private async export(
    request: IncomingMessage,
    response: ServerResponse,
  ): Promise<void> {
    const body = await readJsonBody(
      request,
      this.options.config.server.maxBodyBytes,
    );
    if (!hasOnlyKeys(body, ["format", "filters"])) {
      sendJson(response, 400, {
        error: "export request contains unknown fields",
      });
      return;
    }
    const format = body["format"];
    if (format !== "json" && format !== "csv") {
      sendJson(response, 400, { error: "format must be json or csv" });
      return;
    }
    const rawFilters = body["filters"] ?? {};
    if (!isRecord(rawFilters)) {
      sendJson(response, 400, { error: "export filters must be an object" });
      return;
    }
    const params = new URLSearchParams();
    for (const [key, value] of Object.entries(rawFilters)) {
      if (typeof value !== "string" && typeof value !== "number") {
        sendJson(response, 400, {
          error: "export filters must be scalar values",
        });
        return;
      }
      params.set(key, String(value));
    }
    const parsed = parseEventQuery(params, Date.now());
    if (!parsed.ok) {
      sendJson(response, 400, { error: parsed.error });
      return;
    }
    const page = this.options.database.withDatabase((database) =>
      queryEvents(database, parsed.value),
    );
    const ruleReferences = this.options.database.withDatabase((database) =>
      getRelevantRuleReferences(
        database,
        page.events.map((event) => event.id),
      ),
    );
    const prepared = prepareExport(
      page.events,
      parsed.value,
      ruleReferences,
      this.options.config.export.redactSensitiveFields,
    );
    const contents =
      format === "json" ? exportJson(prepared) : exportCsv(prepared);
    const filename = `sentinel-export-${new Date().toISOString().replace(/[:.]/g, "-")}.${format}`;
    response.statusCode = 200;
    response.setHeader(
      "Content-Type",
      format === "json"
        ? "application/json; charset=utf-8"
        : "text/csv; charset=utf-8",
    );
    response.setHeader(
      "Content-Disposition",
      `attachment; filename="${filename}"`,
    );
    response.setHeader("Content-Length", Buffer.byteLength(contents, "utf8"));
    response.end(contents);
  }

  private ruleIdsByEvent(
    start: number,
    end: number,
  ): ReadonlyMap<string, readonly string[]> {
    const rows = this.options.database.withDatabase((database) =>
      database
        .prepare(
          `SELECT ae.event_id, a.rule_id FROM alert_events ae
           JOIN alerts a ON a.id = ae.alert_id
           WHERE ae.event_id IN (
             SELECT id FROM events WHERE timestamp >= ? AND timestamp <= ?
           )
           ORDER BY ae.event_id, a.rule_id LIMIT ?`,
        )
        .all(start, end, this.options.config.detection.maxWindowEvents * 8),
    );
    const result = new Map<string, string[]>();
    for (const row of rows) {
      const eventId = row["event_id"];
      const ruleId = row["rule_id"];
      if (typeof eventId !== "string" || typeof ruleId !== "string") continue;
      const ids = result.get(eventId);
      if (ids === undefined) result.set(eventId, [ruleId]);
      else if (!ids.includes(ruleId)) ids.push(ruleId);
    }
    return result;
  }

  private system(response: ServerResponse): void {
    const integrity = this.options.database.integrityCheck();
    const retentionDays = this.options.database.withDatabase((database) =>
      getRetentionDays(database, this.options.config.storage.retentionDays),
    );
    const databaseBytes = databaseSize(this.options.config.storage.path);
    sendJson(response, 200, {
      version: VERSION,
      uptimeSeconds: Math.floor(process.uptime()),
      integrity,
      database: {
        path: this.options.config.storage.path,
        bytes: databaseBytes,
      },
      retentionDays,
      detection: this.options.config.detection,
    });
  }

  private async updateRetention(
    request: IncomingMessage,
    response: ServerResponse,
  ): Promise<void> {
    const body = await readJsonBody(
      request,
      this.options.config.server.maxBodyBytes,
    );
    if (!hasOnlyKeys(body, ["retentionDays"])) {
      sendJson(response, 400, {
        error: "retention request contains unknown fields",
      });
      return;
    }
    const retentionDays = body["retentionDays"];
    if (
      typeof retentionDays !== "number" ||
      !Number.isSafeInteger(retentionDays)
    ) {
      sendJson(response, 400, { error: "retentionDays must be an integer" });
      return;
    }
    const updated = this.options.database.withDatabase((database) =>
      setRetentionDays(database, retentionDays),
    );
    const pruned = this.options.database.prune(updated);
    this.options.stream.publish("system.updated", {
      retentionDays: updated,
      pruned,
    });
    sendJson(response, 200, { retentionDays: updated, pruned });
  }
}

export function sendJson(
  response: ServerResponse,
  status: number,
  value: unknown,
): void {
  const body = JSON.stringify(value);
  response.statusCode = status;
  response.setHeader("Content-Type", "application/json; charset=utf-8");
  response.setHeader("Content-Length", Buffer.byteLength(body, "utf8"));
  response.end(body);
}

function parseAlertId(value: string): number {
  if (!/^\d{1,15}$/.test(value))
    throw new RangeError("alert identifier is invalid");
  const id = Number(value);
  if (!Number.isSafeInteger(id) || id < 1)
    throw new RangeError("alert identifier is invalid");
  return id;
}

function hasOnlyKeys(
  value: Record<string, unknown>,
  allowed: readonly string[],
): boolean {
  return Object.keys(value).every((key) => allowed.includes(key));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function safeNumber(value: unknown): number {
  if (typeof value === "number" && Number.isSafeInteger(value)) return value;
  if (typeof value === "bigint" && value <= BigInt(Number.MAX_SAFE_INTEGER)) {
    return Number(value);
  }
  return 0;
}

function databaseSize(path: string): number {
  try {
    return statSync(path).size;
  } catch {
    return 0;
  }
}
