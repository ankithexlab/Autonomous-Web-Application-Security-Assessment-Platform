export const ROUTES = {
  HOME: "/",
  AUTH: {
    LOGIN: "/auth/login",
    REGISTER: "/auth/register",
    FORGOT_PASSWORD: "/auth/forgot-password",
    RESET_PASSWORD: "/auth/reset-password",
  },
  DASHBOARD: "/dashboard",
  PROJECTS: "/projects",
  TARGETS: "/targets",
  SCANS: "/scans",
  FINDINGS: "/findings",
  REPORTS: "/reports",
  PAYLOADS: "/payloads",
  AI_ASSISTANT: "/ai-assistant",
  SETTINGS: "/settings",

  OWASP: {
    ROOT: "/owasp",
    DASHBOARD: "/owasp/dashboard",
  },
} as const

