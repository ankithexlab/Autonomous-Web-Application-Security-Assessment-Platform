/**
 * API client — centralised fetch wrapper.
 *
 * Design:
 *  - Base URL comes from VITE_API_BASE_URL (set to http://localhost:8000/api/v1).
 *  - Bearer token is read lazily from localStorage key "awsap-auth" so this
 *    module never imports Zustand directly (avoids circular deps and React context
 *    coupling). The key matches the Zustand persist store name in auth-store.ts.
 *  - 401 responses clear auth state and redirect to login so token expiry is
 *    handled globally without per-request try/catch in every feature.
 *  - Error shape matches the backend ApiError interface:
 *      { message: string, code: string, status: number, details?: … }
 */

import type { ApiError } from "@/types"

export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "/api/v1"

// ── Token helpers ────────────────────────────────────────────────

/**
 * Read the access token from Zustand's persisted localStorage entry.
 * Returns null if not authenticated or storage is unavailable.
 */
export function getAccessToken(): string | null {
  try {
    const raw = localStorage.getItem("awsap-auth")
    if (!raw) return null
    const state = JSON.parse(raw) as { state?: { token?: string | null } }
    return state?.state?.token ?? null
  } catch {
    return null
  }
}

/**
 * Clear all persisted auth state and redirect to the login page.
 * Called when the server returns 401 — token is expired or invalid.
 */
function handleUnauthorized(): void {
  try {
    localStorage.removeItem("awsap-auth")
  } catch {
    // Ignore storage errors
  }
  // Hard redirect — avoids needing React Router here
  if (!window.location.pathname.startsWith("/auth")) {
    window.location.href = "/auth/login"
  }
}

// ── Request core ─────────────────────────────────────────────────

interface RequestConfig extends Omit<RequestInit, "body"> {
  body?: unknown
  /** If true, skip attaching the Authorization header (for login/register) */
  skipAuth?: boolean
}

async function request<T>(
  endpoint: string,
  config: RequestConfig = {},
): Promise<T> {
  const { body, headers, skipAuth = false, ...rest } = config

  // Attach Bearer token for authenticated endpoints
  const token = skipAuth ? null : getAccessToken()
  const authHeader: Record<string, string> = token
    ? { Authorization: `Bearer ${token}` }
    : {}

  const response = await fetch(`${API_BASE_URL}${endpoint}`, {
    headers: {
      "Content-Type": "application/json",
      ...authHeader,
      ...headers,
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
    ...rest,
  })

  // Handle token expiry globally
  if (response.status === 401) {
    handleUnauthorized()
    const error: ApiError = await response.json().catch(() => ({
      message: "Session expired. Please sign in again.",
      code: "UNAUTHORIZED",
      status: 401,
    }))
    throw error
  }

  if (!response.ok) {
    const error: ApiError = await response.json().catch(() => ({
      message: response.statusText || "An unexpected error occurred.",
      code: "UNKNOWN",
      status: response.status,
    }))
    throw error
  }

  if (response.status === 204) return undefined as T

  return response.json() as Promise<T>
}

// ── Public API ───────────────────────────────────────────────────

export const apiClient = {
  get: <T>(endpoint: string, config?: RequestConfig) =>
    request<T>(endpoint, { ...config, method: "GET" }),

  post: <T>(endpoint: string, body?: unknown, config?: RequestConfig) =>
    request<T>(endpoint, { ...config, method: "POST", body }),

  put: <T>(endpoint: string, body?: unknown, config?: RequestConfig) =>
    request<T>(endpoint, { ...config, method: "PUT", body }),

  patch: <T>(endpoint: string, body?: unknown, config?: RequestConfig) =>
    request<T>(endpoint, { ...config, method: "PATCH", body }),

  delete: <T>(endpoint: string, config?: RequestConfig) =>
    request<T>(endpoint, { ...config, method: "DELETE" }),
}
