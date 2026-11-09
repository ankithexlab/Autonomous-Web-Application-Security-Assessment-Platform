import { cn } from "@/utils"
import type { OWASPSeverity } from "../types/owasp"

interface SeverityBadgeProps {
  severity: OWASPSeverity
  className?: string
  showLabel?: boolean
}

const SEVERITY_CONFIG: Record<OWASPSeverity, { label: string; color: string; bg: string; border: string; dot: string }> = {
  critical: {
    label: "Critical",
    color: "text-red-400",
    bg: "bg-red-500/10",
    border: "border-red-500/30",
    dot: "bg-red-400",
  },
  high: {
    label: "High",
    color: "text-orange-400",
    bg: "bg-orange-500/10",
    border: "border-orange-500/30",
    dot: "bg-orange-400",
  },
  medium: {
    label: "Medium",
    color: "text-amber-400",
    bg: "bg-amber-500/10",
    border: "border-amber-500/30",
    dot: "bg-amber-400",
  },
  low: {
    label: "Low",
    color: "text-blue-400",
    bg: "bg-blue-500/10",
    border: "border-blue-500/30",
    dot: "bg-blue-400",
  },
  info: {
    label: "Info",
    color: "text-zinc-400",
    bg: "bg-zinc-500/10",
    border: "border-zinc-500/30",
    dot: "bg-zinc-400",
  },
}

export function OWASPSeverityBadge({ severity, className, showLabel = true }: SeverityBadgeProps) {
  const cfg = SEVERITY_CONFIG[severity]
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-wider",
        cfg.bg,
        cfg.border,
        cfg.color,
        className,
      )}
    >
      <span className={cn("h-1.5 w-1.5 rounded-full shrink-0", cfg.dot)} />
      {showLabel && cfg.label}
    </span>
  )
}
