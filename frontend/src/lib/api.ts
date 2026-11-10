import type { ApiErrorEnvelope, FieldError } from "../types/api";

export class ApiClientError extends Error {
  status: number;
  code: string;
  requestId: string;
  fieldErrors: FieldError[];

  constructor(
    status: number,
    code: string,
    message: string,
    requestId = "-",
    fieldErrors: FieldError[] = []
  ) {
    super(message);
    this.name = "ApiClientError";
    this.status = status;
    this.code = code;
    this.requestId = requestId;
    this.fieldErrors = fieldErrors;
  }
}

const API_BASE = "/api/v1";

export interface SessionHeaders {
  token: string | null;
  tenantId: string | null;
}

let sessionProvider: () => SessionHeaders = () => ({ token: null, tenantId: null });
let refreshHandler: (() => Promise<boolean>) | null = null;
let inflightRefresh: Promise<boolean> | null = null;

export function registerSessionProvider(fn: () => SessionHeaders): void {
  sessionProvider = fn;
}

export function registerRefreshHandler(fn: (() => Promise<boolean>) | null): void {
  refreshHandler = fn;
}

async function attemptTokenRefresh(): Promise<boolean> {
  if (!refreshHandler) return false;
  if (!inflightRefresh) {
    inflightRefresh = refreshHandler().finally(() => {
      inflightRefresh = null;
    });
  }
  return inflightRefresh;
}

function buildHeaders(extra?: Record<string, string>): Headers {
  const headers = new Headers(extra);
  const { token, tenantId } = sessionProvider();
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }
  if (tenantId) {
    headers.set("X-Tenant-ID", tenantId);
  }
  return headers;
}

async function parseErrorResponse(res: Response): Promise<ApiClientError> {
  const reqIdHeader = res.headers.get("X-Request-ID") || "-";
  try {
    const body = (await res.json()) as Partial<ApiErrorEnvelope>;
    return new ApiClientError(
      res.status,
      body.code || `HTTP_${res.status}`,
      body.message || res.statusText || "Request failed",
      body.request_id || reqIdHeader,
      Array.isArray(body.field_errors) ? body.field_errors : []
    );
  } catch {
    return new ApiClientError(
      res.status,
      `HTTP_${res.status}`,
      res.statusText || "Request failed",
      reqIdHeader,
      []
    );
  }
}

const NO_REFRESH_PATHS = new Set(["/auth/login", "/auth/refresh", "/auth/logout", "/auth/oidc/callback"]);

export async function apiRequest<T>(
  path: string,
  options: {
    method?: string;
    body?: unknown;
    headers?: Record<string, string>;
  } = {}
): Promise<T> {
  const execute = async () => {
    const headers = buildHeaders(options.headers);
    let fetchBody: BodyInit | undefined;

    if (options.body instanceof FormData) {
      fetchBody = options.body;
    } else if (options.body !== undefined) {
      headers.set("Content-Type", "application/json");
      fetchBody = JSON.stringify(options.body);
    }

    return fetch(`${API_BASE}${path}`, {
      method: options.method || "GET",
      headers,
      body: fetchBody,
    });
  };

  let res = await execute();
  if (res.status === 401 && !NO_REFRESH_PATHS.has(path) && (await attemptTokenRefresh())) {
    res = await execute();
  }

  if (!res.ok) {
    throw await parseErrorResponse(res);
  }
  return (await res.json()) as T;
}

export async function apiDownloadBlob(path: string, filename: string): Promise<void> {
  let res = await fetch(`${API_BASE}${path}`, { method: "GET", headers: buildHeaders() });
  if (res.status === 401 && (await attemptTokenRefresh())) {
    res = await fetch(`${API_BASE}${path}`, { method: "GET", headers: buildHeaders() });
  }
  if (!res.ok) {
    throw await parseErrorResponse(res);
  }
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  try {
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
  } finally {
    URL.revokeObjectURL(url);
  }
}
