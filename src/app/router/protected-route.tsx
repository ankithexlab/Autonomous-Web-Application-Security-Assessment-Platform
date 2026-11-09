/**
 * ProtectedRoute — wraps dashboard routes that require authentication.
 *
 * Behaviour:
 *  1. On mount, calls rehydrate() once to validate the stored access token
 *     against GET /auth/me. This ensures stale or revoked tokens are detected
 *     and the user is redirected to login even if localStorage still contains
 *     old credentials.
 *  2. While rehydration is in progress (isLoading), shows the PageLoader so
 *     the user never sees a flash of the login page.
 *  3. If isAuthenticated === false after rehydration, redirects to /auth/login
 *     with { from: location } state so the login page can redirect back after
 *     a successful login.
 */

import { useEffect, useRef } from "react"
import { Navigate, Outlet, useLocation } from "react-router"
import { ROUTES } from "@/constants"
import { useAuthStore } from "@/stores/auth-store"
import { PageLoader } from "@/components/feedback"

export function ProtectedRoute() {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated)
  const isLoading = useAuthStore((s) => s.isLoading)
  const token = useAuthStore((s) => s.token)
  const rehydrate = useAuthStore((s) => s.rehydrate)
  const location = useLocation()

  // Run rehydrate exactly once per mount.
  // We guard with hasRehydrated ref so navigating between protected pages
  // does not re-validate the token on every route change.
  const hasRehydrated = useRef(false)
  useEffect(() => {
    if (hasRehydrated.current) return
    hasRehydrated.current = true
    if (token) {
      rehydrate()
    }
  }, [rehydrate, token])

  // While the token is being validated against the backend, show loader
  // to prevent a flash redirect to login.
  if (isLoading) {
    return <PageLoader />
  }

  if (!isAuthenticated) {
    return <Navigate to={ROUTES.AUTH.LOGIN} state={{ from: location }} replace />
  }

  return <Outlet />
}
