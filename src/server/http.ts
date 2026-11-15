import { createServer } from "node:http";
import type { IncomingMessage, Server, ServerResponse } from "node:http";
import { constants as fsConstants } from "node:fs";
import { open, realpath } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { basename, dirname, extname, join, resolve, sep } from "node:path";
import type { Config } from "../config/config.js";
import type { ServerConfig } from "../config/config.js";
import type { EventDatabase } from "../store/database.js";
import { AlertLifecycle } from "../alerts/lifecycle.js";
import { AlertNotFoundError, AlertStore } from "../alerts/store.js";
import { DetectionEngine } from "../detect/engine.js";
import { ApiRoutes, sendJson } from "./routes.js";
import { HttpInputError } from "./body.js";
import { RateLimiter } from "./ratelimit.js";
import { admitRequest, SECURITY_HEADERS, type Rejection } from "./security.js";
import { SessionManager } from "./session.js";
import { EventStream } from "./stream.js";

const DEFAULT_STATIC_ROOT = fileURLToPath(new URL("../web/", import.meta.url));
const WRITE_ROUTE =
  /^\/api\/(?:session\/logout|rules\/[a-z0-9._-]{1,128}|alerts\/\d+\/(?:state|notes)|system\/retention|export)$/;

export interface HttpApiServerOptions {
  readonly config: Config;
  readonly database: EventDatabase;
  readonly detection?: DetectionEngine;
  readonly sessions?: SessionManager;
  readonly stream?: EventStream;
  readonly staticRoot?: string;
}

export class HttpApiServer {
  readonly sessions: SessionManager;
  readonly stream: EventStream;

  private readonly config: Config;
  private serverConfig: ServerConfig;
  private readonly detection: DetectionEngine;
  private readonly alerts: AlertStore;
  private readonly routes: ApiRoutes;
  private readonly staticRoot: string;
  private readonly apiRateLimit: RateLimiter;
  private readonly loginRateLimit: RateLimiter;
  private server: Server | undefined;

  constructor(options: HttpApiServerOptions) {
    if (options.config.storage.path === ":memory:") {
      throw new Error("HTTP server requires a persistent SQLite database path");
    }
    this.config = options.config;
    this.serverConfig = options.config.server;
    this.detection =
      options.detection ??
      new DetectionEngine(options.database, options.config.detection);
    this.sessions =
      options.sessions ??
      new SessionManager({
        tokenPath: join(
          dirname(options.config.storage.path),
          `.${basename(options.config.storage.path)}.token`,
        ),
        config: options.config.server,
      });
    this.stream =
      options.stream ??
      new EventStream(
        options.config.server.maxStreamClients,
        options.config.server.maxStreamEventsPerSecond,
      );
    this.staticRoot = options.staticRoot ?? DEFAULT_STATIC_ROOT;
    this.alerts = new AlertStore(options.database);
    this.routes = new ApiRoutes({
      config: options.config,
      database: options.database,
      detection: this.detection,
      alerts: this.alerts,
      lifecycle: new AlertLifecycle(this.alerts),
      sessions: this.sessions,
      stream: this.stream,
    });
    this.apiRateLimit = new RateLimiter({
      limit: options.config.server.requestsPerMinute,
      windowMs: 60_000,
    });
    this.loginRateLimit = new RateLimiter({ limit: 10, windowMs: 60_000 });
  }

  loginUrl(): string {
    return this.sessions.loginUrl();
  }

  tokenFilePath(): string | null {
    return this.sessions.tokenFilePath();
  }

  async listen(port = this.config.server.port): Promise<number> {
    if (this.server !== undefined)
      throw new Error("HTTP server is already listening");
    const server = createServer(
      { maxHeaderSize: this.config.server.maxHeaderBytes },
      (request, response) => {
        void this.handle(request, response);
      },
    );
    server.requestTimeout = 30_000;
    server.headersTimeout = 10_000;
    server.keepAliveTimeout = 5_000;
    server.maxRequestsPerSocket = 1_000;
    this.server = server;

    await new Promise<void>((resolve, reject) => {
      const onError = (error: Error): void => {
        server.off("listening", onListening);
        this.server = undefined;
        reject(error);
      };
      const onListening = (): void => {
        server.off("error", onError);
        resolve();
      };
      server.once("error", onError);
      server.once("listening", onListening);
      server.listen(port, this.config.server.host);
    });

    const address = server.address();
    if (address === null || typeof address === "string") {
      throw new Error("HTTP server did not bind to a TCP port");
    }
    this.serverConfig = { ...this.config.server, port: address.port };
    this.sessions.setPort(address.port);
    return address.port;
  }

  async close(): Promise<void> {
    this.stream.close();
    this.sessions.clear();
    const server = this.server;
    this.server = undefined;
    if (!server?.listening) return;
    await new Promise<void>((resolve, reject) => {
      server.close((error) => {
        if (error !== undefined) reject(error);
        else resolve();
      });
    });
  }

  private async handle(
    request: IncomingMessage,
    response: ServerResponse,
  ): Promise<void> {
    for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
      response.setHeader(name, value);
    }
    response.setHeader("X-DNS-Prefetch-Control", "off");

    const target = parseRequestTarget(request.url);
    if (target === null) {
      sendJson(response, 400, { error: "request target is invalid" });
      return;
    }
    const pathname = target.pathname;
    const isApi = pathname.startsWith("/api/");
    const loginExchange =
      pathname === "/api/session" && request.method === "POST";
    const write = request.method === "POST" && WRITE_ROUTE.test(pathname);
    const admission = admitRequest(request, this.serverConfig, {
      allowPost: write || loginExchange,
      requireOrigin: write || loginExchange,
    });
    if (admission !== null) {
      this.reject(response, admission);
      return;
    }

    if (!isApi) {
      await this.serveStatic(pathname, request.method, response);
      return;
    }

    const clientKey = request.socket.remoteAddress ?? "unknown";
    if (loginExchange) {
      if (!this.loginRateLimit.consume(clientKey)) {
        this.reject(response, {
          status: 429,
          reason: "too many login attempts",
        });
        return;
      }
      await this.dispatch(request, response, target, null);
      return;
    }
    if (!this.apiRateLimit.consume(clientKey)) {
      this.reject(response, {
        status: 429,
        reason: "request rate limit exceeded",
      });
      return;
    }

    const session = this.sessions.authenticate(request);
    if (session === null) {
      this.reject(response, { status: 401, reason: "authentication required" });
      return;
    }
    if (write && !this.sessions.verifyCsrf(request, session)) {
      this.reject(response, { status: 403, reason: "CSRF validation failed" });
      return;
    }

    if (pathname === "/api/stream" && request.method === "GET") {
      this.openStream(response, target);
      return;
    }
    await this.dispatch(request, response, target, session);
  }

  private async dispatch(
    request: IncomingMessage,
    response: ServerResponse,
    target: URL,
    session: ReturnType<SessionManager["authenticate"]>,
  ): Promise<void> {
    try {
      await this.routes.handle(request, response, target, session);
    } catch (error: unknown) {
      if (response.writableEnded || response.destroyed) return;
      if (error instanceof HttpInputError) {
        sendJson(response, error.status, { error: error.message });
      } else if (error instanceof AlertNotFoundError) {
        sendJson(response, 404, { error: "alert not found" });
      } else if (error instanceof RangeError || error instanceof TypeError) {
        sendJson(response, 400, { error: error.message });
      } else {
        sendJson(response, 500, { error: "internal server error" });
      }
    }
  }

  private openStream(response: ServerResponse, target: URL): void {
    if (target.search.length > 0) {
      sendJson(response, 400, {
        error: "stream does not accept query parameters",
      });
      return;
    }
    if (this.stream.clientCount >= this.config.server.maxStreamClients) {
      this.reject(response, {
        status: 503,
        reason: "stream client limit reached",
      });
      return;
    }
    response.writeHead(200, {
      "Content-Type": "text/event-stream; charset=utf-8",
      "Cache-Control": "no-store, no-transform",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
    });
    response.flushHeaders();
    if (this.stream.subscribe(response) === null) {
      response.end();
      return;
    }
    response.write("retry: 2000\n\n");
  }

  private async serveStatic(
    pathname: string,
    method: string | undefined,
    response: ServerResponse,
  ): Promise<void> {
    let relative: string;
    try {
      relative = decodeURIComponent(
        pathname === "/" ? "/index.html" : pathname,
      ).slice(1);
    } catch {
      sendJson(response, 404, { error: "resource not found" });
      return;
    }
    const segments = relative.split("/");
    const allowed =
      relative === "index.html" ||
      relative === "styles.css" ||
      (relative.endsWith(".js") && /^[a-zA-Z0-9._/-]+$/.test(relative));
    if (
      !allowed ||
      relative.includes("\\") ||
      segments.some(
        (segment) => segment === "" || segment === "." || segment === "..",
      )
    ) {
      sendJson(response, 404, { error: "resource not found" });
      return;
    }
    const root = resolve(this.staticRoot);
    const target = resolve(root, relative);
    if (!target.startsWith(`${root}${sep}`)) {
      sendJson(response, 404, { error: "resource not found" });
      return;
    }
    let descriptor: Awaited<ReturnType<typeof open>> | undefined;
    try {
      const canonicalRoot = await realpath(root);
      const canonicalTarget = await realpath(target);
      if (!canonicalTarget.startsWith(`${canonicalRoot}${sep}`)) {
        sendJson(response, 404, { error: "resource not found" });
        return;
      }
      descriptor = await open(
        canonicalTarget,
        fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW,
      );
      const info = await descriptor.stat();
      if (!info.isFile() || info.size > 4_194_304) {
        sendJson(response, 404, { error: "resource not found" });
        return;
      }
      const body = await descriptor.readFile();
      response.statusCode = 200;
      response.setHeader("Content-Type", contentTypeFor(target));
      response.setHeader("Content-Length", body.byteLength);
      response.end(method === "HEAD" ? undefined : body);
    } catch {
      sendJson(response, 404, { error: "resource not found" });
    } finally {
      await descriptor?.close();
    }
  }

  private reject(response: ServerResponse, rejection: Rejection): void {
    if (response.writableEnded || response.destroyed) return;
    sendJson(response, rejection.status, { error: rejection.reason });
  }
}

function parseRequestTarget(value: string | undefined): URL | null {
  if (value === undefined || !value.startsWith("/") || value.startsWith("//")) {
    return null;
  }
  try {
    return new URL(value, "http://sentinel.invalid");
  } catch {
    return null;
  }
}

function contentTypeFor(path: string): string {
  switch (extname(path)) {
    case ".html":
      return "text/html; charset=utf-8";
    case ".css":
      return "text/css; charset=utf-8";
    case ".js":
      return "text/javascript; charset=utf-8";
    default:
      return "application/octet-stream";
  }
}
