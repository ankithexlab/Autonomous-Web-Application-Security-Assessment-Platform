import { Link, useLocation } from "react-router"
import { ChevronRight, Home } from "lucide-react"
import { ROUTES } from "@/constants"

const routeNameMap: Record<string, string> = {
  dashboard: "Dashboard",
  projects: "Projects",
  targets: "Targets",
  scans: "Scan Center",
  findings: "Vulnerabilities",
  reports: "Reports & Compliance",
  "ai-assistant": "AI Assistant",
  settings: "Settings",
  profile: "User Profile",
}

export function Breadcrumb() {
  const { pathname } = useLocation()
  const pathSegments = pathname.split("/").filter(Boolean)

  if (pathSegments.length === 0) return null

  return (
    <nav aria-label="Breadcrumb" className="hidden sm:flex items-center gap-1.5 text-xs text-muted-foreground">
      <Link
        to={ROUTES.DASHBOARD}
        className="flex items-center gap-1 hover:text-foreground transition-colors"
      >
        <Home className="h-3.5 w-3.5" />
      </Link>

      {pathSegments.map((segment, index) => {
        const isLast = index === pathSegments.length - 1
        const href = `/${pathSegments.slice(0, index + 1).join("/")}`
        const label = routeNameMap[segment] || segment.replace(/-/g, " ")

        return (
          <div key={href} className="flex items-center gap-1.5">
            <ChevronRight className="h-3.5 w-3.5 text-muted-foreground/60" />
            {isLast ? (
              <span className="font-semibold text-foreground capitalize">{label}</span>
            ) : (
              <Link to={href} className="hover:text-foreground transition-colors capitalize">
                {label}
              </Link>
            )}
          </div>
        )
      })}
    </nav>
  )
}
