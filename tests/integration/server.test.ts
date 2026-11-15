import {
  mkdir,
  mkdtemp,
  readFile,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { request as httpRequest } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { DetectionEngine } from "../../src/detect/engine.js";
import { parseConfig } from "../../src/config/config.js";
import { EventDatabase } from "../../src/store/database.js";
import { HttpApiServer } from "../../src/server/http.js";
import { SessionManager } from "../../src/server/session.js";
import { insertEvents } from "../../src/store/queries.js";
import { AlertStore } from "../../src/alerts/store.js";
import type { RuleMatch, SecurityEvent } from "../../src/types.js";

interface RunningServer {
  readonly app: HttpApiServer;
  readonly database: EventDatabase;
  readonly baseUrl: string;
  readonly origin: string;
  readonly tokenPath: string;
  readonly staticRoot: string;
  readonly now: { value: number };
}

const running: RunningServer[] = [];
const temporaryDirectories: string[] = [];

async function startServer(
  overrides: {
    readonly maxStreamClients?: number;
    readonly maxBodyBytes?: number;
    readonly requestsPerMinute?: number;
    readonly sessionTtlMs?: number;
    readonly maxStreamEventsPerSecond?: number;
    readonly redactSensitiveFields?: boolean;
    readonly token?: string;
  } = {},
): Promise<RunningServer> {
  const directory = await mkdtemp(join(tmpdir(), "sentinel-http-"));
  temporaryDirectories.push(directory);
  const databasePath = join(directory, "state", "events.sqlite");
  const staticRoot = join(directory, "web");
  await mkdir(join(staticRoot, "views"), { recursive: true });
  await writeFile(join(staticRoot, "index.html"), "<h1>Sentinel</h1>", "utf8");
  await writeFile(join(staticRoot, "views", "events.js"), "export {};", "utf8");
  const config = parseConfig({
    storage: { path: databasePath },
    server: {
      ...(overrides.maxStreamClients === undefined
        ? {}
        : { maxStreamClients: overrides.maxStreamClients }),
      ...(overrides.maxBodyBytes === undefined
        ? {}
        : { maxBodyBytes: overrides.maxBodyBytes }),
      ...(overrides.requestsPerMinute === undefined
        ? {}
        : { requestsPerMinute: overrides.requestsPerMinute }),
      ...(overrides.sessionTtlMs === undefined
        ? {}
        : { sessionTtlMs: overrides.sessionTtlMs }),
      ...(overrides.maxStreamEventsPerSecond === undefined
        ? {}
        : { maxStreamEventsPerSecond: overrides.maxStreamEventsPerSecond }),
      ...(overrides.token === undefined ? {} : { token: overrides.token }),
    },
    export:
      overrides.redactSensitiveFields === undefined
        ? {}
        : { redactSensitiveFields: overrides.redactSensitiveFields },
  });
  const database = new EventDatabase({ path: databasePath });
  const now = { value: Date.now() };
  const tokenPath = join(directory, "state", ".events.sqlite.token");
  const sessions = new SessionManager({
    tokenPath,
    config: config.server,
    now: () => now.value,
  });
  const app = new HttpApiServer({
    config,
    database,
    detection: new DetectionEngine(database, config.detection),
    sessions,
    staticRoot,
  });
  const port = await app.listen(0);
  const server: RunningServer = {
    app,
    database,
    baseUrl: `http://127.0.0.1:${port}`,
    origin: `http://127.0.0.1:${port}`,
    tokenPath,
    staticRoot,
    now,
  };
  running.push(server);
  return server;
}

async function login(server: RunningServer): Promise<{
  readonly cookie: string;
  readonly csrf: string;
}> {
  const token = (await readFile(server.tokenPath, "utf8")).trim();
  const response = await fetch(`${server.baseUrl}/api/session`, {
    method: "POST",
    headers: {
      Origin: server.origin,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ token }),
  });
  expect(response.status).toBe(200);
  const cookies = response.headers
    .getSetCookie()
    .map((value) => value.split(";", 1)[0])
    .filter((value): value is string => value !== undefined);
  const cookie = cookies.join("; ");
  const csrf = cookies
    .map((value) => value.split("=", 2))
    .find(([name]) => name === "sentinel_csrf")?.[1];
  if (csrf === undefined) throw new Error("CSRF cookie was not set");
  return { cookie, csrf };
}

function requestWithHost(url: string, host: string): Promise<number> {
  return new Promise((resolve, reject) => {
    const request = httpRequest(
      url,
      { headers: { Host: host } },
      (response) => {
        response.resume();
        response.once("end", () => {
          resolve(response.statusCode ?? 0);
        });
      },
    );
    request.once("error", reject);
    request.end();
  });
}

afterEach(async () => {
  await Promise.all(
    running.splice(0).map(async ({ app, database }) => {
      await app.close();
      database.close();
    }),
  );
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

describe("HTTP session and admission controls", () => {
  it("serves nested compiled assets without exposing arbitrary files", async () => {
    const server = await startServer();
    const shell = await fetch(`${server.baseUrl}/`);
    expect(shell.status).toBe(200);
    expect(await shell.text()).toContain("Sentinel");
    const module = await fetch(`${server.baseUrl}/views/events.js`);
    expect(module.status).toBe(200);
    expect(await module.text()).toContain("export");
    const unknown = await fetch(`${server.baseUrl}/private.txt`);
    expect(unknown.status).toBe(404);
    const outside = join(server.staticRoot, "..", "outside.js");
    const linked = join(server.staticRoot, "views", "escape.js");
    await writeFile(outside, "private", "utf8");
    await symlink(outside, linked);
    const escaped = await fetch(`${server.baseUrl}/views/escape.js`);
    expect(escaped.status).toBe(404);
  });
  it("creates an owner-only token and rejects unauthorised, invalid-token and forged-origin requests", async () => {
    const server = await startServer();
    expect((await stat(server.tokenPath)).mode & 0o777).toBe(0o600);
    expect((await fetch(`${server.baseUrl}/api/overview`)).status).toBe(401);
    expect((await fetch(`${server.baseUrl}/api/stream`)).status).toBe(401);
    const longTarget = await fetch(
      `${server.baseUrl}/api/events?search=${"x".repeat(2_100)}`,
    );
    expect(longTarget.status).toBe(414);

    const forged = await fetch(`${server.baseUrl}/api/session`, {
      method: "POST",
      headers: {
        Origin: "http://attacker.invalid",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ token: "a".repeat(64) }),
    });
    expect(forged.status).toBe(403);

    const invalidToken = "x".repeat(32);
    const invalid = await fetch(`${server.baseUrl}/api/session`, {
      method: "POST",
      headers: {
        Origin: server.origin,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ token: invalidToken }),
    });
    expect(invalid.status).toBe(401);
    expect(await invalid.text()).not.toContain(invalidToken);
  });

  it("requires a valid session and CSRF header for writes and revokes sessions on logout", async () => {
    const server = await startServer();
    const { cookie, csrf } = await login(server);
    const overview = await fetch(`${server.baseUrl}/api/overview`, {
      headers: { Cookie: cookie, Origin: server.origin },
    });
    expect(overview.status).toBe(200);

    const noCsrf = await fetch(
      `${server.baseUrl}/api/rules/ssh.repeated_failures`,
      {
        method: "POST",
        headers: {
          Cookie: cookie,
          Origin: server.origin,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ enabled: false }),
      },
    );
    expect(noCsrf.status).toBe(403);

    const forgedWrite = await fetch(
      `${server.baseUrl}/api/rules/ssh.repeated_failures`,
      {
        method: "POST",
        headers: {
          Cookie: cookie,
          Origin: "http://attacker.invalid",
          "x-sentinel-csrf": csrf,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ enabled: false }),
      },
    );
    expect(forgedWrite.status).toBe(403);

    const updated = await fetch(
      `${server.baseUrl}/api/rules/ssh.repeated_failures`,
      {
        method: "POST",
        headers: {
          Cookie: cookie,
          Origin: server.origin,
          "x-sentinel-csrf": csrf,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ enabled: false }),
      },
    );
    expect(updated.status).toBe(200);

    const logout = await fetch(`${server.baseUrl}/api/session/logout`, {
      method: "POST",
      headers: {
        Cookie: cookie,
        Origin: server.origin,
        "x-sentinel-csrf": csrf,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({}),
    });
    expect(logout.status).toBe(200);
    const revoked = await fetch(`${server.baseUrl}/api/overview`, {
      headers: { Cookie: cookie, Origin: server.origin },
    });
    expect(revoked.status).toBe(401);
  });

  it("serves authenticated, filtered event pages and event details", async () => {
    const server = await startServer();
    const timestamp = Date.now();
    const event: SecurityEvent = {
      id: "b".repeat(64),
      timestamp,
      ingestedAt: timestamp + 1,
      source: "http-test",
      sourceType: "ndjson",
      host: "host-01",
      category: "authentication",
      action: "ssh.authentication.failure",
      outcome: "failure",
      severity: "medium",
      username: "operator",
      sourceIp: "203.0.113.44",
      process: null,
      message: "fixture ssh failure",
      metadata: { origin: "integration" },
      parserVersion: "ndjson/1",
      inferred: [],
    };
    server.database.withDatabase((connection) =>
      insertEvents(connection, [event]),
    );
    const { cookie } = await login(server);
    const response = await fetch(
      `${server.baseUrl}/api/events?range=1h&source=http-test&severity=medium`,
      { headers: { Cookie: cookie, Origin: server.origin } },
    );
    expect(response.status).toBe(200);
    const page = (await response.json()) as {
      readonly events: readonly SecurityEvent[];
    };
    expect(page.events.map(({ id }) => id)).toEqual([event.id]);

    const detail = await fetch(`${server.baseUrl}/api/events/${event.id}`, {
      headers: { Cookie: cookie, Origin: server.origin },
    });
    expect(detail.status).toBe(200);
    await expect(detail.json()).resolves.toMatchObject({
      id: event.id,
      metadata: { origin: "integration" },
    });
  });

  it("exports metadata-bearing redacted JSON and CSV through a CSRF-protected route", async () => {
    const server = await startServer({ redactSensitiveFields: true });
    const timestamp = Date.now();
    const event: SecurityEvent = {
      id: "c".repeat(64),
      timestamp,
      ingestedAt: timestamp + 1,
      source: "http-export",
      sourceType: "ndjson",
      host: "host-02",
      category: "authentication",
      action: "ssh.authentication.failure",
      outcome: "failure",
      severity: "high",
      username: "private-user",
      sourceIp: "203.0.113.45",
      process: null,
      message: "private message",
      metadata: { private: "secret" },
      parserVersion: "ndjson/1",
      inferred: [],
    };
    server.database.withDatabase((connection) =>
      insertEvents(connection, [event]),
    );
    const { cookie, csrf } = await login(server);
    const response = await fetch(`${server.baseUrl}/api/export`, {
      method: "POST",
      headers: {
        Cookie: cookie,
        Origin: server.origin,
        "x-sentinel-csrf": csrf,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        format: "json",
        filters: { from: timestamp - 1_000, to: timestamp + 1_000 },
      }),
    });
    expect(response.status).toBe(200);
    expect(response.headers.get("content-disposition")).toMatch(
      /sentinel-export-/,
    );
    const exported = await response.text();
    expect(exported).toContain('"eventCount": 1');
    expect(exported).toContain('"redacted": true');
    expect(exported).not.toContain("private-user");
    expect(exported).not.toContain("203.0.113.45");
    expect(exported).not.toContain("private message");
    expect(exported).not.toContain("secret");
  });

  it("persists retention changes and prunes expired events through the System controls", async () => {
    const server = await startServer();
    const timestamp = Date.now() - 40 * 86_400_000;
    const event: SecurityEvent = {
      id: "f".repeat(64),
      timestamp,
      ingestedAt: timestamp + 1,
      source: "retention-source",
      sourceType: "ndjson",
      host: "host-04",
      category: "other",
      action: "retention.fixture",
      outcome: "unknown",
      severity: "info",
      username: null,
      sourceIp: null,
      process: null,
      message: "expired fixture event",
      metadata: {},
      parserVersion: "ndjson/1",
      inferred: [],
    };
    server.database.withDatabase((connection) =>
      insertEvents(connection, [event]),
    );
    const { cookie, csrf } = await login(server);
    const response = await fetch(`${server.baseUrl}/api/system/retention`, {
      method: "POST",
      headers: {
        Cookie: cookie,
        Origin: server.origin,
        "x-sentinel-csrf": csrf,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ retentionDays: 1 }),
    });
    expect(await response.json()).toMatchObject({
      retentionDays: 1,
      pruned: 1,
    });
    expect(server.database.counts().events).toBe(0);
    const system = await fetch(`${server.baseUrl}/api/system`, {
      headers: { Cookie: cookie, Origin: server.origin },
    });
    expect(await system.json()).toMatchObject({ retentionDays: 1 });
  });

  it("serves authenticated alerts, notes, correlation, sources and system data", async () => {
    const server = await startServer();
    const timestamp = Date.now();
    const event: SecurityEvent = {
      id: "e".repeat(64),
      timestamp,
      ingestedAt: timestamp + 1,
      source: "http-alert",
      sourceType: "ndjson",
      host: "host-03",
      category: "authentication",
      action: "ssh.authentication.failure",
      outcome: "failure",
      severity: "high",
      username: "operator",
      sourceIp: "203.0.113.46",
      process: null,
      message: "fixture failure",
      metadata: {},
      parserVersion: "ndjson/1",
      inferred: [],
    };
    server.database.withDatabase((connection) =>
      insertEvents(connection, [event]),
    );
    const match: RuleMatch = {
      ruleId: "ssh.repeated_failures",
      ruleVersion: 1,
      dedupKey: "ssh.repeated_failures:ip:203.0.113.46",
      severity: "high",
      rationale: "Repeated SSH authentication failure indicators.",
      thresholds: { count: 5, windowMs: 300_000 },
      windowStart: timestamp,
      windowEnd: timestamp,
      eventIds: [event.id],
    };
    const alert = new AlertStore(server.database).upsert(match);
    const { cookie, csrf } = await login(server);
    const headers = { Cookie: cookie, Origin: server.origin };
    const paths = [
      "/api/overview",
      "/api/events?range=1h",
      `/api/events/${event.id}`,
      "/api/rules",
      "/api/alerts?state=open",
      `/api/alerts/${alert.id}`,
      `/api/alerts/${alert.id}/notes`,
      `/api/correlate?by=rule&windowMs=3600000&to=${timestamp}&value=ssh.repeated_failures`,
      "/api/sources",
      "/api/system",
    ];
    for (const path of paths) {
      expect(
        (await fetch(`${server.baseUrl}${path}`, { headers })).status,
      ).toBe(200);
    }

    const stateResponse = await fetch(
      `${server.baseUrl}/api/alerts/${alert.id}/state`,
      {
        method: "POST",
        headers: {
          ...headers,
          "x-sentinel-csrf": csrf,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ state: "acknowledged" }),
      },
    );
    expect(await stateResponse.json()).toMatchObject({ state: "acknowledged" });

    const noteResponse = await fetch(
      `${server.baseUrl}/api/alerts/${alert.id}/notes`,
      {
        method: "POST",
        headers: {
          ...headers,
          "x-sentinel-csrf": csrf,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ note: "Analyst review completed" }),
      },
    );
    expect(noteResponse.status).toBe(201);
  });

  it("rejects hostile Host headers and expires sessions", async () => {
    const server = await startServer({ sessionTtlMs: 60_000 });
    const hostileHost = await requestWithHost(
      `${server.baseUrl}/api/session`,
      "attacker.invalid",
    );
    expect(hostileHost).toBe(403);

    const { cookie } = await login(server);
    server.now.value += 60_001;
    const expired = await fetch(`${server.baseUrl}/api/overview`, {
      headers: { Cookie: cookie, Origin: server.origin },
    });
    expect(expired.status).toBe(401);
  });

  it("enforces request-body size limits", async () => {
    const server = await startServer({ maxBodyBytes: 1_024 });
    const { cookie, csrf } = await login(server);
    const response = await fetch(
      `${server.baseUrl}/api/rules/ssh.repeated_failures`,
      {
        method: "POST",
        headers: {
          Cookie: cookie,
          Origin: server.origin,
          "x-sentinel-csrf": csrf,
          "Content-Type": "application/json",
        },
        body: `{"thresholds":"${"x".repeat(1_100)}"}`,
      },
    );
    expect(response.status).toBe(413);
  });

  it("enforces the configured per-client API rate limit", async () => {
    const server = await startServer({ requestsPerMinute: 1 });
    const { cookie } = await login(server);
    const headers = { Cookie: cookie, Origin: server.origin };
    expect(
      (await fetch(`${server.baseUrl}/api/overview`, { headers })).status,
    ).toBe(200);
    expect(
      (await fetch(`${server.baseUrl}/api/overview`, { headers })).status,
    ).toBe(429);
  });

  it("caps concurrent live-stream clients", async () => {
    const server = await startServer({
      maxStreamClients: 1,
      maxStreamEventsPerSecond: 1,
    });
    const { cookie } = await login(server);
    const first = await fetch(`${server.baseUrl}/api/stream`, {
      headers: { Cookie: cookie, Origin: server.origin },
    });
    expect(first.status).toBe(200);
    const reader = first.body?.getReader();
    if (reader === undefined)
      throw new Error("SSE response body was unavailable");
    await reader.read();
    const firstUpdate = reader.read();
    server.app.stream.publish("event.created", { id: "first-event" });
    expect(new TextDecoder().decode((await firstUpdate).value)).toContain(
      "first-event",
    );
    server.app.stream.publish("event.created", { id: "dropped-event" });
    await new Promise((resolve) => setTimeout(resolve, 1_001));
    const degradedUpdate = reader.read();
    server.app.stream.publish("event.created", { id: "next-event" });
    expect(new TextDecoder().decode((await degradedUpdate).value)).toContain(
      "stream.degraded",
    );
    expect(new TextDecoder().decode((await reader.read()).value)).toContain(
      "next-event",
    );

    const second = await fetch(`${server.baseUrl}/api/stream`, {
      headers: { Cookie: cookie, Origin: server.origin },
    });
    expect(second.status).toBe(503);
    await reader.cancel();
  });
});
