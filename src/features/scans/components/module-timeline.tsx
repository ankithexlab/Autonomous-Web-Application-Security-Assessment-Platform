import { motion } from "framer-motion"
import {
  CheckCircle2,
  Play,
  Clock,
  XCircle,
  SkipForward,
  AlertTriangle,
} from "lucide-react"
import { cn } from "@/utils"
import type { ScanModule, ScanModuleStatus } from "@/types"

const moduleStatusConfig: Record<
  ScanModuleStatus,
  { icon: typeof CheckCircle2; color: string; bgColor: string; lineColor: string }
> = {
  completed: {
    icon: CheckCircle2,
    color: "text-emerald-400",
    bgColor: "bg-emerald-500/15 border-emerald-500/30",
    lineColor: "bg-emerald-500/40",
  },
  running: {
    icon: Play,
    color: "text-blue-400",
    bgColor: "bg-blue-500/15 border-blue-500/30",
    lineColor: "bg-blue-500/40",
  },
  pending: {
    icon: Clock,
    color: "text-zinc-500",
    bgColor: "bg-zinc-500/10 border-zinc-500/20",
    lineColor: "bg-zinc-500/20",
  },
  failed: {
    icon: XCircle,
    color: "text-red-400",
    bgColor: "bg-red-500/15 border-red-500/30",
    lineColor: "bg-red-500/40",
  },
  skipped: {
    icon: SkipForward,
    color: "text-zinc-500",
    bgColor: "bg-zinc-500/10 border-zinc-500/20",
    lineColor: "bg-zinc-500/20",
  },
}

interface ModuleTimelineProps {
  modules: ScanModule[]
}

export function ModuleTimeline({ modules }: ModuleTimelineProps) {
  return (
    <div className="space-y-0">
      {modules.map((mod, i) => {
        const cfg = moduleStatusConfig[mod.status]
        const StatusIcon = cfg.icon
        const isLast = i === modules.length - 1

        return (
          <motion.div
            key={mod.id}
            initial={{ opacity: 0, x: -8 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.25, delay: i * 0.05 }}
            className="relative flex gap-3"
          >
            {/* Timeline connector */}
            <div className="flex flex-col items-center">
              <div
                className={cn(
                  "flex h-8 w-8 shrink-0 items-center justify-center rounded-full border",
                  cfg.bgColor,
                )}
              >
                <StatusIcon
                  className={cn(
                    "h-3.5 w-3.5",
                    cfg.color,
                    mod.status === "running" && "animate-pulse",
                  )}
                />
              </div>
              {!isLast && (
                <div className={cn("w-0.5 flex-1 min-h-4", cfg.lineColor)} />
              )}
            </div>

            {/* Module content */}
            <div className="flex-1 pb-4">
              <div className="flex items-center gap-2">
                <span className="text-sm font-semibold text-foreground">
                  {mod.name}
                </span>
                <span
                  className={cn(
                    "text-[10px] font-semibold uppercase tracking-wider",
                    cfg.color,
                  )}
                >
                  {mod.status}
                </span>
              </div>

              <p className="mt-0.5 text-xs text-muted-foreground">
                {mod.description}
              </p>

              {/* Progress bar for running modules */}
              {mod.status === "running" && (
                <div className="mt-2 flex items-center gap-2">
                  <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-muted">
                    <motion.div
                      className="h-full rounded-full bg-gradient-to-r from-blue-500 to-blue-400"
                      initial={{ width: 0 }}
                      animate={{ width: `${mod.progress}%` }}
                      transition={{ duration: 1.2, ease: "easeOut" }}
                    />
                  </div>
                  <span className="text-[11px] font-semibold text-blue-400">
                    {mod.progress}%
                  </span>
                </div>
              )}

              {/* Stats row */}
              <div className="mt-1.5 flex items-center gap-3 text-[11px] text-muted-foreground">
                {mod.duration && <span>⏱ {mod.duration}</span>}
                {mod.findingsCount > 0 && (
                  <span className="flex items-center gap-1 font-medium text-amber-400">
                    <AlertTriangle className="h-3 w-3" />
                    {mod.findingsCount} finding{mod.findingsCount !== 1 ? "s" : ""}
                  </span>
                )}
              </div>
            </div>
          </motion.div>
        )
      })}
    </div>
  )
}
