import { timingSafeEqual } from "node:crypto";
import type { IncomingMessage } from "node:http";
import { isIP } from "node:net";
import type { ServerConfig } from "../config/config.js";
import { isLoopbackHost } from "../config/config.js";

export interface Rejection {
  readonly status: 400 | 401 | 403 | 405 | 413 | 414 | 429 | 503;
  readonly reason: string;
}

export const MAX_URL_LENGTH = 2_048;

export function splitHost(
  value: string,
): { readonly host: string; readonly port: string | null } | null {
  const normalized = value.trim().toLowerCase();
  if (normalized.length === 0 || /[\s\p{Cc}]/u.test(normalized)) {
    return null;
  }
  const bracketed = /^\[([0-9a-f:.]+)\](?::(\d{1,5}))?$/.exec(normalized);
  if (bracketed !== null) {
    const host = bracketed[1] ?? "";
    if (isIP(host) !== 6) return null;
    return { host, port: bracketed[2] ?? null };
  }
  if (normalized.startsWith("[") || normalized.includes("]")) return null;

  const index = normalized.lastIndexOf(":");
  if (index === -1) return { host: normalized, port: null };
  if (normalized.indexOf(":") !== index) return null;
  if (normalized.includes("[") || normalized.includes("]")) return null;
  const port = normalized.slice(index + 1);
  if (!/^\d{1,5}$/.test(port)) return null;
  return { host: normalized.slice(0, index), port };
}

export function isHostAllowed(
  value: string | undefined,
  config: ServerConfig,
): boolean {
  if (value === undefined) return false;
  const split = splitHost(value);
  if (split === null || split.host.length === 0) return false;
  if (split.port !== null) {
    const port = Number(split.port);
    if (
      !Number.isInteger(port) ||
      port < 1 ||
      port > 65_535 ||
      port !== config.port
    ) {
      return false;
    }
  }
  if (
    (config.host === "0.0.0.0" || config.host === "::") &&
    config.allowRemote
  ) {
    return isIP(split.host) !== 0;
  }
  if (split.host === config.host.toLowerCase()) return true;
  return isLoopbackHost(config.host) && isLoopbackHost(split.host);
}

export function isOriginAllowed(
  value: string | undefined,
  config: ServerConfig,
  requestHost?: string,
): boolean {
  if (value === undefined) return true;
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return false;
  }
  if (
    parsed.protocol !== "http:" ||
    parsed.origin !== value ||
    parsed.username.length > 0 ||
    parsed.password.length > 0 ||
    Number(parsed.port || "80") !== config.port
  ) {
    return false;
  }
  const hostname =
    parsed.hostname.startsWith("[") && parsed.hostname.endsWith("]")
      ? parsed.hostname.slice(1, -1)
      : parsed.hostname;
  if (config.host === "0.0.0.0" || config.host === "::") {
    return (
      config.allowRemote && isIP(hostname) !== 0 && requestHost === hostname
    );
  }
  if (hostname === config.host.toLowerCase()) return true;
  return isLoopbackHost(config.host) && isLoopbackHost(hostname);
}

export function tokenMatches(presented: string, expected: string): boolean {
  const supplied = Buffer.from(presented, "utf8");
  const secret = Buffer.from(expected, "utf8");
  if (supplied.length !== secret.length) return false;
  return timingSafeEqual(supplied, secret);
}

export interface AdmissionOptions {
  readonly requireOrigin?: boolean;
  readonly allowPost?: boolean;
}

export function admitRequest(
  request: IncomingMessage,
  config: ServerConfig,
  options: AdmissionOptions = {},
): Rejection | null {
  const method = request.method ?? "GET";
  if (
    method !== "GET" &&
    method !== "HEAD" &&
    !(method === "POST" && options.allowPost === true)
  ) {
    return { status: 405, reason: "method not allowed" };
  }

  const requestUrl = request.url ?? "/";
  if (requestUrl.length > MAX_URL_LENGTH) {
    return { status: 414, reason: "request target is too long" };
  }
  if (!isHostAllowed(request.headers.host, config)) {
    return { status: 403, reason: "host not allowed" };
  }
  const parsedHost = splitHost(request.headers.host ?? "");

  const originHeader = request.headers.origin;
  if (Array.isArray(originHeader)) {
    return { status: 403, reason: "origin not allowed" };
  }
  const origin = typeof originHeader === "string" ? originHeader : undefined;
  if (options.requireOrigin === true && origin === undefined) {
    return { status: 403, reason: "origin required" };
  }
  if (!isOriginAllowed(origin, config, parsedHost?.host)) {
    return { status: 403, reason: "origin not allowed" };
  }
  return null;
}

export const SECURITY_HEADERS: Readonly<Record<string, string>> = {
  "Content-Security-Policy":
    "default-src 'none'; script-src 'self'; style-src 'self'; " +
    "img-src 'self' data:; connect-src 'self'; font-src 'self'; " +
    "base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
  "Cache-Control": "no-store",
};
