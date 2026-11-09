import { Shield } from "lucide-react"
import { cn } from "@/utils"

interface LogoProps {
  collapsed?: boolean
  className?: string
}

export function Logo({ collapsed = false, className }: LogoProps) {
  return (
    <div className={cn("flex items-center gap-3", className)}>
      <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary">
        <Shield className="h-5 w-5" />
      </div>
      {!collapsed && (
        <div className="flex flex-col">
          <span className="text-sm font-bold tracking-wider text-foreground">
            AWASAP
          </span>
          <span className="text-[10px] font-medium tracking-wide text-muted-foreground">
            SECURITY PLATFORM
          </span>
        </div>
      )}
    </div>
  )
}
