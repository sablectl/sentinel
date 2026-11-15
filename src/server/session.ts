import { randomBytes, timingSafeEqual } from "node:crypto";
import {
  closeSync,
  constants as fsConstants,
  fchmodSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { dirname } from "node:path";
import type { IncomingMessage } from "node:http";
import type { ServerConfig } from "../config/config.js";

const SESSION_COOKIE = "sentinel_session";
const CSRF_COOKIE = "sentinel_csrf";
const TOKEN_BYTES = 32;
const MAX_SESSIONS = 128;

export interface Session {
  readonly id: string;
  readonly csrfToken: string;
  readonly expiresAt: number;
}

export interface SessionManagerOptions {
  readonly tokenPath: string;
  readonly config: ServerConfig;
  readonly now?: () => number;
}

export class SessionManager {
  private readonly config: ServerConfig;
  private readonly now: () => number;
  private readonly bootstrapToken: string;
  private readonly tokenPath: string | null;
  private readonly sessions = new Map<string, Session>();
  private port: number;

  constructor(options: SessionManagerOptions) {
    this.config = options.config;
    this.port = options.config.port;
    this.now = options.now ?? Date.now;
    this.tokenPath = options.config.token === null ? options.tokenPath : null;
    this.bootstrapToken =
      options.config.token ?? loadOrCreateToken(options.tokenPath);
  }

  loginUrl(): string {
    const host =
      this.config.host === "0.0.0.0" || this.config.host === "::"
        ? "127.0.0.1"
        : this.config.host;
    const formattedHost = host.includes(":") ? `[${host}]` : host;
    return `http://${formattedHost}:${this.port}/`;
  }

  tokenFilePath(): string | null {
    return this.tokenPath;
  }

  setPort(port: number): void {
    if (!Number.isInteger(port) || port < 1 || port > 65_535) {
      throw new RangeError("session server port is invalid");
    }
    this.port = port;
  }

  exchange(presentedToken: string): Session | null {
    if (!tokenMatches(presentedToken, this.bootstrapToken)) return null;
    this.removeExpired();
    if (this.sessions.size >= MAX_SESSIONS) return null;
    const session: Session = {
      id: randomBytes(TOKEN_BYTES).toString("base64url"),
      csrfToken: randomBytes(TOKEN_BYTES).toString("base64url"),
      expiresAt: this.now() + this.config.sessionTtlMs,
    };
    this.sessions.set(session.id, session);
    return session;
  }

  authenticate(request: IncomingMessage): Session | null {
    const id = readCookie(request.headers.cookie, SESSION_COOKIE);
    if (id === null) return null;
    const session = this.sessions.get(id);
    if (session === undefined) return null;
    if (session.expiresAt <= this.now()) {
      this.sessions.delete(id);
      return null;
    }
    return session;
  }

  verifyCsrf(request: IncomingMessage, session: Session): boolean {
    const cookieToken = readCookie(request.headers.cookie, CSRF_COOKIE);
    const header = request.headers["x-sentinel-csrf"];
    if (cookieToken === null || typeof header !== "string") return false;
    return (
      tokenMatches(cookieToken, session.csrfToken) &&
      tokenMatches(header, session.csrfToken)
    );
  }

  revoke(session: Session): void {
    this.sessions.delete(session.id);
  }

  clear(): void {
    this.sessions.clear();
  }

  setCookieHeaders(session: Session): string[] {
    const maxAge = Math.max(
      0,
      Math.floor((session.expiresAt - this.now()) / 1000),
    );
    const expires = new Date(session.expiresAt).toUTCString();
    return [
      `${SESSION_COOKIE}=${session.id}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAge}; Expires=${expires}`,
      `${CSRF_COOKIE}=${session.csrfToken}; SameSite=Strict; Path=/; Max-Age=${maxAge}; Expires=${expires}`,
    ];
  }

  clearCookieHeaders(): string[] {
    return [
      `${SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT`,
      `${CSRF_COOKIE}=; SameSite=Strict; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT`,
    ];
  }

  private removeExpired(): void {
    const now = this.now();
    for (const [id, session] of this.sessions) {
      if (session.expiresAt <= now) this.sessions.delete(id);
    }
  }
}

function loadOrCreateToken(path: string): string {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  let descriptor: number;
  try {
    descriptor = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  } catch (error: unknown) {
    if (!isMissingFile(error))
      throw new Error("session token file could not be opened", {
        cause: error,
      });
    const token = randomBytes(TOKEN_BYTES).toString("hex");
    let created: number | undefined;
    try {
      created = openSync(
        path,
        fsConstants.O_WRONLY |
          fsConstants.O_CREAT |
          fsConstants.O_EXCL |
          fsConstants.O_NOFOLLOW,
        0o600,
      );
      writeFileSync(created, token, "utf8");
      fsyncSync(created);
      return token;
    } catch (createError: unknown) {
      if (!isAlreadyExists(createError)) {
        throw new Error("session token file could not be created", {
          cause: createError,
        });
      }
      return loadExistingToken(path);
    } finally {
      if (created !== undefined) closeSync(created);
    }
  }

  try {
    fchmodSync(descriptor, 0o600);
    const token = readFileSync(descriptor, "utf8").trim();
    if (!/^[0-9a-f]{64}$/.test(token)) {
      throw new Error("session token file has an invalid format");
    }
    return token;
  } finally {
    closeSync(descriptor);
  }
}

function loadExistingToken(path: string): string {
  let descriptor: number;
  try {
    descriptor = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  } catch (error: unknown) {
    throw new Error("session token file could not be opened", { cause: error });
  }
  try {
    fchmodSync(descriptor, 0o600);
    const token = readFileSync(descriptor, "utf8").trim();
    if (!/^[0-9a-f]{64}$/.test(token)) {
      throw new Error("session token file has an invalid format");
    }
    return token;
  } finally {
    closeSync(descriptor);
  }
}

function readCookie(
  header: string | string[] | undefined,
  name: string,
): string | null {
  if (typeof header !== "string" || header.length > 8_192) return null;
  for (const item of header.split(";")) {
    const separator = item.indexOf("=");
    if (separator < 0 || item.slice(0, separator).trim() !== name) continue;
    const value = item.slice(separator + 1).trim();
    return /^[A-Za-z0-9_-]{43}$/.test(value) ? value : null;
  }
  return null;
}

function tokenMatches(presented: string, expected: string): boolean {
  const supplied = Buffer.from(presented, "utf8");
  const secret = Buffer.from(expected, "utf8");
  return supplied.length === secret.length && timingSafeEqual(supplied, secret);
}

function isMissingFile(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    error.code === "ENOENT"
  );
}

function isAlreadyExists(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    error.code === "EEXIST"
  );
}
