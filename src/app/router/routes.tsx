import { lazy, Suspense } from "react"
import { createBrowserRouter } from "react-router"
import { ROUTES } from "@/constants"
import { DashboardLayout } from "@/app/layouts/dashboard-layout"
import { AuthLayout } from "@/app/layouts/auth-layout"
import { ProtectedRoute } from "@/app/router/protected-route"
import { PageLoader } from "@/components/feedback"

/* ── Lazy-loaded feature pages ── */
const DashboardPage = lazy(() =>
  import("@/features/dashboard/pages/dashboard-page").then((m) => ({
    default: m.DashboardPage,
  })),
)
const ProjectsPage = lazy(() =>
  import("@/features/projects/pages/projects-page").then((m) => ({
    default: m.ProjectsPage,
  })),
)
const TargetsPage = lazy(() =>
  import("@/features/targets/pages/targets-page").then((m) => ({
    default: m.TargetsPage,
  })),
)
const ScansPage = lazy(() =>
  import("@/features/scans/pages/scans-page").then((m) => ({
    default: m.ScansPage,
  })),
)
const FindingsPage = lazy(() =>
  import("@/features/findings/pages/findings-page").then((m) => ({
    default: m.FindingsPage,
  })),
)
const ReportsPage = lazy(() =>
  import("@/features/reports/pages/reports-page").then((m) => ({
    default: m.ReportsPage,
  })),
)
const PayloadsPage = lazy(() =>
  import("@/features/payloads/pages/payloads-page").then((m) => ({
    default: m.PayloadsPage,
  })),
)

const AIAssistantPage = lazy(() =>
  import("@/features/ai-assistant/pages/ai-assistant-page").then((m) => ({
    default: m.AIAssistantPage,
  })),
)
const OWASPDashboardPage = lazy(() =>
  import("@/features/owasp/pages/owasp-dashboard-page").then((m) => ({
    default: m.OWASPDashboardPage,
  })),
)
const SettingsPage = lazy(() =>
  import("@/features/settings/pages/settings-page").then((m) => ({
    default: m.SettingsPage,
  })),
)
const LoginPage = lazy(() =>
  import("@/features/auth/pages/login-page").then((m) => ({
    default: m.LoginPage,
  })),
)
const RegisterPage = lazy(() =>
  import("@/features/auth/pages/register-page").then((m) => ({
    default: m.RegisterPage,
  })),
)
const ForgotPasswordPage = lazy(() =>
  import("@/features/auth/pages/forgot-password-page").then((m) => ({
    default: m.ForgotPasswordPage,
  })),
)
const ResetPasswordPage = lazy(() =>
  import("@/features/auth/pages/reset-password-page").then((m) => ({
    default: m.ResetPasswordPage,
  })),
)
const NotFoundPage = lazy(() =>
  import("@/features/auth/pages/not-found-page").then((m) => ({
    default: m.NotFoundPage,
  })),
)

const LandingPage = lazy(() =>
  import("@/features/landing/pages/landing-page").then((m) => ({
    default: m.LandingPage,
  })),
)

function SuspenseWrapper({ children }: { children: React.ReactNode }) {
  return <Suspense fallback={<PageLoader />}>{children}</Suspense>
}

export const router = createBrowserRouter([
  {
    path: ROUTES.HOME,
    element: (
      <SuspenseWrapper>
        <LandingPage />
      </SuspenseWrapper>
    ),
  },

  /* ── Auth routes (public) ── */
  {
    element: (
      <SuspenseWrapper>
        <AuthLayout />
      </SuspenseWrapper>
    ),
    children: [
      {
        path: ROUTES.AUTH.LOGIN,
        element: <LoginPage />,
      },
      {
        path: ROUTES.AUTH.REGISTER,
        element: <RegisterPage />,
      },
      {
        path: ROUTES.AUTH.FORGOT_PASSWORD,
        element: <ForgotPasswordPage />,
      },
      {
        path: ROUTES.AUTH.RESET_PASSWORD,
        element: <ResetPasswordPage />,
      },
    ],
  },

  /* ── Dashboard routes (protected) ── */
  {
    element: <ProtectedRoute />,
    children: [
      {
        element: (
          <SuspenseWrapper>
            <DashboardLayout />
          </SuspenseWrapper>
        ),
        children: [
          {
            path: ROUTES.DASHBOARD,
            element: <DashboardPage />,
          },
          {
            path: ROUTES.PROJECTS,
            element: <ProjectsPage />,
          },
          {
            path: ROUTES.TARGETS,
            element: <TargetsPage />,
          },
          {
            path: ROUTES.SCANS,
            element: <ScansPage />,
          },
          {
            path: ROUTES.FINDINGS,
            element: <FindingsPage />,
          },
          {
            path: ROUTES.REPORTS,
            element: <ReportsPage />,
          },
          {
            path: ROUTES.PAYLOADS,
            element: <PayloadsPage />,
          },
          {
            path: ROUTES.AI_ASSISTANT,
            element: <AIAssistantPage />,
          },
          {
            path: ROUTES.OWASP.ROOT,
            element: <OWASPDashboardPage />,
          },
          {
            path: ROUTES.OWASP.DASHBOARD,
            element: <OWASPDashboardPage />,
          },
          {
            path: ROUTES.SETTINGS,
            element: <SettingsPage />,
          },
        ],
      },
    ],
  },

  /* ── Catch-all ── */
  {
    path: "*",
    element: (
      <SuspenseWrapper>
        <NotFoundPage />
      </SuspenseWrapper>
    ),
  },
])
