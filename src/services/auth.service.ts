/**
 * Auth service — all authentication API calls.
 *
 * Maps frontend request shapes to backend FastAPI endpoints.
 *
 * Schema translation:
 *   The backend UserRead schema uses snake_case (created_at, last_login_at)
 *   while the frontend User type uses camelCase (createdAt, lastLoginAt).
 *   normaliseUser() performs this mapping in one place so the rest of the
 *   frontend never sees snake_case fields.
 *
 * skipAuth: true is set on register/login/forgot-password because those
 *   endpoints don't require a Bearer token.
 */

import type { User, ApiError } from "@/types"
import { apiClient } from "./api-client"

// ── Request payloads ─────────────────────────────────────────────

export interface LoginPayload {
  email: string
  password: string
}

export interface RegisterPayload {
  name: string
  email: string
  password: string
}

export interface RefreshPayload {
  refresh_token: string
}

export interface UpdateProfilePayload {
  name?: string
  avatar?: string | null
}

export interface ChangePasswordPayload {
  current_password: string
  new_password: string
}

// ── Backend response shapes (snake_case from FastAPI) ────────────

interface BackendUser {
  id: string
  email: string
  name: string
  avatar: string | null
  role: "admin" | "analyst" | "viewer"
  created_at: string
  updated_at: string
  last_login_at: string | null
}

interface BackendTokenResponse {
  access_token: string
  refresh_token: string
  token_type: string
  user: BackendUser
}

interface BackendAccessTokenResponse {
  access_token: string
  token_type: string
}

interface BackendMessageResponse {
  message: string
}

// ── Frontend-normalised response ─────────────────────────────────

export interface AuthResponse {
  user: User
  token: string
  refreshToken: string
}

// ── Normalisation helpers ─────────────────────────────────────────

/**
 * Convert backend snake_case UserRead → frontend camelCase User.
 * This is the single source of truth for the field mapping.
 */
function normaliseUser(raw: BackendUser): User {
  return {
    id: raw.id,
    email: raw.email,
    name: raw.name,
    avatar: raw.avatar ?? undefined,
    role: raw.role,
    createdAt: raw.created_at,
    lastLoginAt: raw.last_login_at ?? undefined,
  }
}

function normaliseTokenResponse(raw: BackendTokenResponse): AuthResponse {
  return {
    user: normaliseUser(raw.user),
    token: raw.access_token,
    refreshToken: raw.refresh_token,
  }
}

/**
 * Extract a user-friendly error message from an ApiError thrown by apiClient.
 * Falls back to a generic message so stack traces never reach the UI.
 */
export function extractErrorMessage(
  error: unknown,
  fallback = "An unexpected error occurred. Please try again.",
): string {
  if (error && typeof error === "object") {
    const apiError = error as ApiError
    const message = typeof apiError.message === "string" ? apiError.message : ""
    const status = apiError.status

    if (
      message === "Failed to fetch" ||
      status === 502 ||
      status === 503 ||
      status === 504 ||
      message.includes("Gateway Timeout") ||
      message.includes("Bad Gateway") ||
      message.includes("ECONNREFUSED")
    ) {
      return "Unable to reach the backend server (http://localhost:8000). Please ensure the backend is running."
    }

    if (message) {
      return message
    }
  }
  return fallback
}


// ── Auth service ─────────────────────────────────────────────────

export const authService = {
  /**
   * POST /auth/register
   * Creates a new account. Returns normalised AuthResponse on success.
   * Throws ApiError on failure (409 = duplicate email, 422 = validation).
   */
  register: async (payload: RegisterPayload): Promise<AuthResponse> => {
    const raw = await apiClient.post<BackendTokenResponse>(
      "/auth/register",
      payload,
      { skipAuth: true },
    )
    return normaliseTokenResponse(raw)
  },

  /**
   * POST /auth/login
   * Authenticates with email + password.
   * Throws ApiError on failure (401 = invalid credentials).
   */
  login: async (payload: LoginPayload): Promise<AuthResponse> => {
    const raw = await apiClient.post<BackendTokenResponse>(
      "/auth/login",
      payload,
      { skipAuth: true },
    )
    return normaliseTokenResponse(raw)
  },

  /**
   * POST /auth/refresh
   * Exchanges a refresh token for a new access token.
   * Throws ApiError on failure (401 = expired/invalid refresh token).
   */
  refresh: async (refreshToken: string): Promise<string> => {
    const raw = await apiClient.post<BackendAccessTokenResponse>(
      "/auth/refresh",
      { refresh_token: refreshToken } satisfies RefreshPayload,
      { skipAuth: true },
    )
    return raw.access_token
  },

  /**
   * GET /auth/me
   * Returns the currently authenticated user from the backend.
   * Requires a valid Bearer token (injected automatically by api-client).
   */
  me: async (): Promise<User> => {
    const raw = await apiClient.get<BackendUser>("/auth/me")
    return normaliseUser(raw)
  },

  /**
   * PATCH /auth/me
   * Updates profile details (name, avatar) for the current user.
   */
  updateProfile: async (payload: UpdateProfilePayload): Promise<User> => {
    const raw = await apiClient.patch<BackendUser>("/auth/me", payload)
    return normaliseUser(raw)
  },

  /**
   * POST /auth/change-password
   * Changes the password for the current user.
   */
  changePassword: async (currentPassword: string, newPassword: string): Promise<void> => {
    await apiClient.post<BackendMessageResponse>("/auth/change-password", {
      current_password: currentPassword,
      new_password: newPassword,
    } satisfies ChangePasswordPayload)
  },


  /**
   * POST /auth/forgot-password
   * Sends a password reset email. Always resolves successfully
   * (backend never reveals whether the email exists).
   */
  forgotPassword: async (email: string): Promise<void> => {
    await apiClient.post<BackendMessageResponse>(
      "/auth/forgot-password",
      { email },
      { skipAuth: true },
    )
  },

  /**
   * POST /auth/reset-password
   * Resets the user's password using the token from the email link.
   * Throws ApiError on failure (401 = expired/invalid token).
   */
  resetPassword: async (token: string, password: string): Promise<void> => {
    await apiClient.post<BackendMessageResponse>(
      "/auth/reset-password",
      { token, password },
      { skipAuth: true },
    )
  },

  /**
   * POST /auth/logout
   * Notifies the backend of logout (best-effort — state is cleared client-side
   * regardless of whether this call succeeds).
   */
  logout: async (): Promise<void> => {
    try {
      await apiClient.post<void>("/auth/logout")
    } catch {
      // Logout is best-effort — ignore backend errors
    }
  },

  /**
   * DELETE /auth/me
   * Permanently deletes the current user's account and cascades all related data.
   * Throws ApiError on failure.
   */
  deleteAccount: async (): Promise<void> => {
    await apiClient.delete<{ message: string }>("/auth/me")
  },
}
