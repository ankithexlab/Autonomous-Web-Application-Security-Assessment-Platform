import { Outlet } from "react-router"
import { Logo } from "@/components/common/logo"

export function AuthLayout() {
  return (
    <div className="flex min-h-screen items-center justify-center bg-background">
      {/* Background gradient */}
      <div className="pointer-events-none fixed inset-0 bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-primary/5 via-background to-background" />

      <div className="relative z-10 mx-auto flex w-full max-w-md flex-col items-center gap-8 px-4">
        <Logo />
        <div className="w-full rounded-xl border border-border bg-card p-8 shadow-lg">
          <Outlet />
        </div>
        <p className="text-xs text-muted-foreground">
          AWASAP — Autonomous Web Application Security Assessment Platform
        </p>
      </div>
    </div>
  )
}
