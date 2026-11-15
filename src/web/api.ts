import type {
  Alert,
  AlertNote,
  AlertState,
  CorrelationField,
  CorrelationGroup,
  EventCategory,
  EventPage,
  Outcome,
  Overview,
  RuleView,
  SecurityEvent,
  Severity,
  SourceStatus,
  SystemStatus,
} from "./api-types.js";

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export interface EventFilters {
  readonly range?: string;
  readonly from?: number;
  readonly to?: number;
  readonly page?: number;
  readonly limit?: number;
  readonly source?: string;
  readonly username?: string;
  readonly search?: string;
  readonly ip?: string;
  readonly category?: EventCategory;
  readonly outcome?: Outcome;
  readonly severity?: Severity;
  readonly sort?: "timestamp" | "severity" | "source" | "category" | "outcome";
  readonly direction?: "asc" | "desc";
}

export interface AlertFilters {
  readonly state?: AlertState;
  readonly severity?: Severity;
  readonly page?: number;
  readonly limit?: number;
}

export interface CorrelationFilters {
  readonly by: CorrelationField;
  readonly windowMs: number;
  readonly limit: number;
  readonly to?: number;
  readonly value?: string;
}

function readCookie(name: string): string | null {
  for (const item of document.cookie.split(";")) {
    const [key, ...parts] = item.trim().split("=");
    if (key === name) return parts.join("=") || null;
  }
  return null;
}

function queryString(
  values: Readonly<Record<string, string | number | undefined>>,
): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(values)) {
    if (value !== undefined && String(value).length > 0) {
      params.set(key, String(value));
    }
  }
  return params.toString();
}

function errorText(value: unknown): string | null {
  if (
    typeof value === "object" &&
    value !== null &&
    "error" in value &&
    typeof value.error === "string"
  ) {
    return value.error;
  }
  return null;
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set("accept", "application/json");
  if (init.body !== undefined) headers.set("content-type", "application/json");
  if (init.method === "POST" && path !== "/api/session") {
    const csrf = readCookie("sentinel_csrf");
    if (csrf === null)
      throw new ApiError(403, "The local session has expired.");
    headers.set("x-sentinel-csrf", csrf);
  }

  let response: Response;
  try {
    response = await fetch(path, {
      ...init,
      headers,
      credentials: "same-origin",
      cache: "no-store",
    });
  } catch {
    throw new ApiError(0, "Sentinel could not be reached.");
  }
  let body: unknown;
  try {
    body = (await response.json()) as unknown;
  } catch {
    body = null;
  }
  if (!response.ok) {
    if (response.status === 401 && path !== "/api/session") {
      window.dispatchEvent(new Event("sentinel-session-expired"));
    }
    throw new ApiError(
      response.status,
      errorText(body) ?? `Request failed with status ${response.status}.`,
    );
  }
  return body as T;
}

export const api = {
  session: (): Promise<{
    readonly authenticated: boolean;
    readonly expiresAt: number;
  }> => request("/api/session"),
  login: (
    token: string,
  ): Promise<{ readonly authenticated: boolean; readonly expiresAt: number }> =>
    request("/api/session", {
      method: "POST",
      body: JSON.stringify({ token }),
    }),
  logout: (): Promise<{ readonly authenticated: boolean }> =>
    request("/api/session/logout", {
      method: "POST",
      body: JSON.stringify({}),
    }),
  overview: (): Promise<Overview> => request("/api/overview"),
  events: (filters: EventFilters = {}): Promise<EventPage> => {
    const query = queryString({ ...filters });
    return request(query.length === 0 ? "/api/events" : `/api/events?${query}`);
  },
  event: (id: string): Promise<SecurityEvent> =>
    request(`/api/events/${encodeURIComponent(id)}`),
  rules: (): Promise<readonly RuleView[]> => request("/api/rules"),
  configureRule: (
    id: string,
    change: {
      readonly enabled?: boolean;
      readonly thresholds?: Readonly<Record<string, number | string | boolean>>;
    },
  ): Promise<RuleView> =>
    request(`/api/rules/${encodeURIComponent(id)}`, {
      method: "POST",
      body: JSON.stringify(change),
    }),
  alerts: (
    filters: AlertFilters = {},
  ): Promise<{
    readonly alerts: readonly Alert[];
    readonly page: number;
    readonly limit: number;
    readonly total: number;
  }> => {
    const query = queryString({ ...filters });
    return request(query.length === 0 ? "/api/alerts" : `/api/alerts?${query}`);
  },
  alert: (id: number): Promise<Alert> => request(`/api/alerts/${id}`),
  setAlertState: (id: number, state: AlertState): Promise<Alert> =>
    request(`/api/alerts/${id}/state`, {
      method: "POST",
      body: JSON.stringify({ state }),
    }),
  addAlertNote: (id: number, note: string): Promise<AlertNote> =>
    request(`/api/alerts/${id}/notes`, {
      method: "POST",
      body: JSON.stringify({ note }),
    }),
  alertNotes: (id: number): Promise<readonly AlertNote[]> =>
    request(`/api/alerts/${id}/notes`),
  correlate: (
    filters: CorrelationFilters,
  ): Promise<readonly CorrelationGroup[]> => {
    const query = queryString({ ...filters });
    return request(`/api/correlate?${query}`);
  },
  sources: (): Promise<readonly SourceStatus[]> => request("/api/sources"),
  system: (): Promise<SystemStatus> => request("/api/system"),
  updateRetention: (
    retentionDays: number,
  ): Promise<{ readonly retentionDays: number; readonly pruned: number }> =>
    request("/api/system/retention", {
      method: "POST",
      body: JSON.stringify({ retentionDays }),
    }),
  export: async (
    format: "json" | "csv",
    filters: EventFilters,
  ): Promise<Blob> => {
    const csrf = readCookie("sentinel_csrf");
    if (csrf === null)
      throw new ApiError(403, "The local session has expired.");
    const response = await fetch("/api/export", {
      method: "POST",
      headers: {
        accept: format === "json" ? "application/json" : "text/csv",
        "content-type": "application/json",
        "x-sentinel-csrf": csrf,
      },
      credentials: "same-origin",
      cache: "no-store",
      body: JSON.stringify({ format, filters }),
    });
    if (!response.ok) {
      if (response.status === 401) {
        window.dispatchEvent(new Event("sentinel-session-expired"));
      }
      let body: unknown;
      try {
        body = (await response.json()) as unknown;
      } catch {
        body = null;
      }
      throw new ApiError(
        response.status,
        errorText(body) ?? `Export failed with status ${response.status}.`,
      );
    }
    return response.blob();
  },
};

export function describeError(error: unknown): string {
  return error instanceof ApiError
    ? error.status === 0
      ? error.message
      : `${error.message} (status ${error.status})`
    : error instanceof Error
      ? error.message
      : "Unknown error.";
}
