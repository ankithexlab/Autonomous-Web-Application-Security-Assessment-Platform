import {
  LayoutDashboard,
  FolderKanban,
  Crosshair,
  Radar,
  ShieldAlert,
  ShieldCheck,
  FileBarChart,
  Bot,
  Settings,
  Database,
} from "lucide-react"
import { ROUTES } from "./routes"
import type { NavGroup } from "@/types"

export const NAVIGATION: NavGroup[] = [
  {
    label: "Main",
    items: [
      {
        title: "Dashboard",
        href: ROUTES.DASHBOARD,
        icon: LayoutDashboard,
      },
      {
        title: "Projects",
        href: ROUTES.PROJECTS,
        icon: FolderKanban,
      },
      {
        title: "Targets",
        href: ROUTES.TARGETS,
        icon: Crosshair,
      },
      {
        title: "Scans",
        href: ROUTES.SCANS,
        icon: Radar,
      },
      {
        title: "Findings",
        href: ROUTES.FINDINGS,
        icon: ShieldAlert,
      },
      {
        title: "OWASP Top 10",
        href: ROUTES.OWASP.DASHBOARD,
        icon: ShieldCheck,
      },
      {
        title: "Reports",
        href: ROUTES.REPORTS,
        icon: FileBarChart,
      },
      {
        title: "Payloads",
        href: ROUTES.PAYLOADS,
        icon: Database,
      },
    ],
  },

  {
    label: "AI",
    items: [
      {
        title: "AI Assistant",
        href: ROUTES.AI_ASSISTANT,
        icon: Bot,
      },
    ],
  },
  {
    label: "System",
    items: [
      {
        title: "Settings",
        href: ROUTES.SETTINGS,
        icon: Settings,
      },
    ],
  },
]
