import { cn } from "@/utils"
import type { Severity } from "@/types"

const severityConfig: Record<
  Severity,
  { label: string; className: string }
> = {
  critical: {
    label: "Critical",
    className: "bg-red-500/15 text-red-400 border-red-500/20",
  },
  high: {
    label: "High",
    className: "bg-orange-500/15 text-orange-400 border-orange-500/20",
  },
  medium: {
    label: "Medium",
    className: "bg-amber-500/15 text-amber-400 border-amber-500/20",
  },
  low: {
    label: "Low",
    className: "bg-blue-500/15 text-blue-400 border-blue-500/20",
  },
  info: {
    label: "Info",
    className: "bg-zinc-500/15 text-zinc-400 border-zinc-500/20",
  },
}

interface SeverityBadgeProps {
  severity?: Severity | string | null
  className?: string
}

export function SeverityBadge({ severity, className }: SeverityBadgeProps) {
  const normSeverity = (severity ? String(severity).toLowerCase() : "info") as Severity
  const config = severityConfig[normSeverity] || severityConfig.info
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide",
        config.className,
        className,
      )}
    >
      {config.label}
    </span>
  )
}
