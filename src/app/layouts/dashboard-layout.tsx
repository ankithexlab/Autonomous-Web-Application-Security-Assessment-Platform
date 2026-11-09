import { Outlet, useLocation } from "react-router"
import { Sidebar } from "@/components/navigation/sidebar"
import { TopNav } from "@/components/navigation/top-nav"
import { NAVIGATION, APP_CONFIG } from "@/constants"

function usePageTitle(): string {
  const { pathname } = useLocation()

  for (const group of NAVIGATION) {
    for (const item of group.items) {
      if (pathname === item.href || pathname.startsWith(item.href + "/")) {
        return item.title
      }
    }
  }

  return ""
}

export function DashboardLayout() {
  const title = usePageTitle()

  return (
    <div className="flex h-screen overflow-hidden bg-background">
      <Sidebar />

      <div className="flex flex-1 flex-col overflow-hidden">
        <TopNav title={title} />

        <main className="flex-1 overflow-y-auto flex flex-col justify-between">
          <div className="mx-auto max-w-7xl px-4 py-6 lg:px-8 w-full flex-1">
            <Outlet />
          </div>

          {/* Core Dashboard Footer */}
          <footer className="border-t border-border/60 py-3 px-6 text-xs text-muted-foreground flex flex-col sm:flex-row items-center justify-between gap-2 bg-background/50">
            <div className="flex items-center gap-2">
              <span className="flex h-2 w-2 rounded-full bg-emerald-500" />
              <span>Engine Status: Operational</span>
            </div>
            <div className="flex items-center gap-4">
              <span>{APP_CONFIG.name} v{APP_CONFIG.version}</span>
              <span>•</span>
              <span>© {new Date().getFullYear()} Autonomous Security Platform</span>
            </div>
          </footer>
        </main>
      </div>
    </div>
  )
}
