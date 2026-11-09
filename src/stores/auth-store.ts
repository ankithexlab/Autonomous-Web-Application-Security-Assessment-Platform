/**
 * Auth store — Zustand store for authentication state.
 *
 * All operations call the real FastAPI backend via authService.
 *
 * Token storage:
 *   - Access token and refresh token are stored in localStorage via Zustand's
 *     persist middleware (key: "awsap-auth"). This is the same approach as
 *     before — we keep localStorage because the app is a secured internal
 *     security platform (not a public consumer app). In-memory storage would
 *     not survive page refresh, and httpOnly cookies require additional backend
 *     changes outside this phase's scope.
 *   - The api-client reads the token directly from localStorage to avoid
 *     circular imports, so the persist key "awsap-auth" must not change.
 *
 * Error handling:
 *   - login() and register() throw on API failure so the calling component
 *     (login-page.tsx, register-page.tsx) can display the specific error.
 *   - forgotPassword() calls POST /auth/forgot-password (always succeeds from
 *     the user's perspective — backend never reveals if the email exists).
 *   - resetPassword() calls POST /auth/reset-password with the JWT from the
 *     email link. Throws on expired or invalid tokens.
 */

import { create } from "zustand"
import { persist } from "zustand/middleware"
import type { User } from "@/types"
import { authService } from "@/services/auth.service"

interface AuthState {
  user: User | null
  token: string | null
  refreshToken: string | null
  isAuthenticated: boolean
  isLoading: boolean
  // Actions
  login: (email: string, password: string) => Promise<void>
  register: (name: string, email: string, password: string) => Promise<void>
  logout: () => void
  forgotPassword: (email: string) => Promise<void>
  resetPassword: (token: string, password: string) => Promise<void>
  /** Re-validate the stored token against /auth/me and refresh user data */
  rehydrate: () => Promise<void>
  /** Update user state in store directly */
  updateUser: (user: User) => void
  /** Call PATCH /auth/me and update stored user */
  updateProfile: (payload: { name?: string; avatar?: string | null }) => Promise<User>
  /** Call POST /auth/change-password */
  changePassword: (currentPassword: string, newPassword: string) => Promise<void>
  /** Call DELETE /auth/me and clear auth state */
  deleteAccount: () => Promise<void>
}


export const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      user: null,
      token: null,
      refreshToken: null,
      isAuthenticated: false,
      isLoading: false,

      // ── Login ─────────────────────────────────────────────────
      login: async (email: string, password: string) => {
        set({ isLoading: true })
        try {
          const { user, token, refreshToken } = await authService.login({
            email,
            password,
          })
          set({
            user,
            token,
            refreshToken,
            isAuthenticated: true,
            isLoading: false,
          })
        } catch (error) {
          set({ isLoading: false })
          throw error
        }
      },

      // ── Register ──────────────────────────────────────────────
      register: async (name: string, email: string, password: string) => {
        set({ isLoading: true })
        try {
          const { user, token, refreshToken } = await authService.register({
            name,
            email,
            password,
          })
          set({
            user,
            token,
            refreshToken,
            isAuthenticated: true,
            isLoading: false,
          })
        } catch (error) {
          set({ isLoading: false })
          throw error
        }
      },

      // ── Logout ────────────────────────────────────────────────
      logout: () => {
        // Fire and forget — clear local state immediately regardless
        authService.logout().catch(() => {
          // Ignore backend errors on logout
        })
        // Clear sensitive chat history to prevent cross-user and post-logout leaks
        try {
          const keysToRemove: string[] = []
          for (let i = 0; i < localStorage.length; i++) {
            const k = localStorage.key(i)
            if (k && k.startsWith("awasap_sentinel_conversations")) {
              keysToRemove.push(k)
            }
          }
          keysToRemove.forEach((k) => localStorage.removeItem(k))
        } catch {
          // Ignore storage errors
        }
        set({
          user: null,
          token: null,
          refreshToken: null,
          isAuthenticated: false,
          isLoading: false,
        })
      },

      // ── Forgot password ───────────────────────────────────────
      forgotPassword: async (email: string) => {
        await authService.forgotPassword(email)
      },

      // ── Reset password ────────────────────────────────────────
      resetPassword: async (token: string, password: string) => {
        await authService.resetPassword(token, password)
      },

      // ── Rehydrate ─────────────────────────────────────────────
      rehydrate: async () => {
        const { token } = get()
        if (!token) return

        set({ isLoading: true })
        try {
          const user = await authService.me()
          set({ user, isAuthenticated: true, isLoading: false })
        } catch {
          // Token is invalid or expired — clear state
          set({
            user: null,
            token: null,
            refreshToken: null,
            isAuthenticated: false,
            isLoading: false,
          })
        }
      },

      // ── Update user directly ──────────────────────────────────
      updateUser: (user: User) => {
        set({ user })
      },

      // ── Update Profile via API ────────────────────────────────
      updateProfile: async (payload: { name?: string; avatar?: string | null }) => {
        set({ isLoading: true })
        try {
          const updatedUser = await authService.updateProfile(payload)
          set({ user: updatedUser, isLoading: false })
          return updatedUser
        } catch (error) {
          set({ isLoading: false })
          throw error
        }
      },

      // ── Change Password via API ───────────────────────────────
      changePassword: async (currentPassword: string, newPassword: string) => {
        set({ isLoading: true })
        try {
          await authService.changePassword(currentPassword, newPassword)
          set({ isLoading: false })
        } catch (error) {
          set({ isLoading: false })
          throw error
        }
      },

      // ── Delete Account via API ────────────────────────────────
      deleteAccount: async () => {
        set({ isLoading: true })
        try {
          await authService.deleteAccount()
          // Clear all auth state after successful account deletion
          set({
            user: null,
            token: null,
            refreshToken: null,
            isAuthenticated: false,
            isLoading: false,
          })
        } catch (error) {
          set({ isLoading: false })
          throw error
        }
      },
    }),

    {
      name: "awsap-auth",
      // Only persist auth credentials — never persist isLoading
      partialize: (state) => ({
        user: state.user,
        token: state.token,
        refreshToken: state.refreshToken,
        isAuthenticated: state.isAuthenticated,
      }),
    },
  ),
)
