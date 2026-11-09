import { motion } from "framer-motion"
import { CheckCircle2, Play, Clock, XCircle, AlertTriangle, Layers } from "lucide-react"
import { cn } from "@/utils"
import type { ScanEngineReturn } from "../hooks/use-scan-engine"
import type { ScanModuleStatus } from "@/types"

const statusConfig: Record<
  ScanModuleStatus,
  { icon: typeof CheckCircle2; color: string; bgColor: string; lineColor: string; text: string }
> = {
  completed: {
    icon: CheckCircle2,
    color: "text-emerald-400",
    bgColor: "bg-emerald-500/15 border-emerald-500/30",
    lineColor: "bg-emerald-500/40",
    text: "Completed",
  },
  running: {
    icon: Play,
    color: "text-blue-400",
    bgColor: "bg-blue-500/15 border-blue-500/30",
    lineColor: "bg-blue-500/40",
    text: "Scanning...",
  },
  pending: {
    icon: Clock,
    color: "text-muted-foreground",
    bgColor: "bg-muted/40 border-border/60",
    lineColor: "bg-border/60",
    text: "Queued",
  },
  failed: {
    icon: XCircle,
    color: "text-red-400",
    bgColor: "bg-red-500/15 border-red-500/30",
    lineColor: "bg-red-500/40",
    text: "Failed",
  },
  skipped: {
    icon: Clock,
    color: "text-muted-foreground",
    bgColor: "bg-muted/30 border-border/40",
    lineColor: "bg-border/40",
    text: "Skipped",
  },
}

interface ScanCenterTimelineProps {
  engine: ScanEngineReturn
}

export function ScanCenterTimeline({ engine }: ScanCenterTimelineProps) {
  const modules = engine.activeModules.length > 0
    ? engine.activeModules
    : engine.AVAILABLE_MODULES.map((m) => ({
        id: m.id,
        name: m.name,
        description: m.description,
        status: "pending" as ScanModuleStatus,
        progress: 0,
        findingsCount: 0,
        duration: undefined as string | undefined,
      }))

  return (
    <div className="rounded-2xl border border-border/80 bg-card p-5 shadow-sm space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Layers className="h-4 w-4 text-primary" />
          <h3 className="text-sm font-bold text-foreground">Pipeline Execution Timeline</h3>
        </div>
        <span className="text-xs font-mono text-muted-foreground">
          {modules.filter((m) => m.status === "completed").length}/{modules.length} Completed
        </span>
      </div>

      <div className="space-y-0">
        {modules.map((mod, i) => {
          const cfg = statusConfig[mod.status]
          const StatusIcon = cfg.icon
          const isLast = i === modules.length - 1

          return (
            <motion.div
              key={mod.id}
              initial={{ opacity: 0, x: -8 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.2, delay: i * 0.03 }}
              className="relative flex gap-3"
            >
              {/* Connector */}
              <div className="flex flex-col items-center">
                <div
                  className={cn(
                    "flex h-7 w-7 shrink-0 items-center justify-center rounded-full border transition-colors",
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
                {!isLast && <div className={cn("w-0.5 flex-1 min-h-5", cfg.lineColor)} />}
              </div>

              {/* Module Info */}
              <div className="flex-1 pb-3.5">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-foreground">{mod.name}</span>
                  <span className={cn("text-[10px] font-bold uppercase tracking-wider", cfg.color)}>
                    {cfg.text}
                  </span>
                </div>
                <p className="text-[11px] text-muted-foreground mt-0.5">{mod.description}</p>

                {/* Progress bar for running modules */}
                {mod.status === "running" && (
                  <div className="mt-2 flex items-center gap-2">
                    <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-muted/60">
                      <motion.div
                        className="h-full rounded-full bg-blue-500"
                        initial={{ width: 0 }}
                        animate={{ width: `${mod.progress}%` }}
                        transition={{ duration: 0.3 }}
                      />
                    </div>
                    <span className="text-[10px] font-mono font-bold text-blue-400">
                      {mod.progress}%
                    </span>
                  </div>
                )}

                {/* Details badge */}
                <div className="mt-1 flex items-center gap-3 text-[10px] text-muted-foreground">
                  {"duration" in mod && mod.duration && <span>Duration: {mod.duration}</span>}
                  {mod.findingsCount > 0 && (
                    <span className="flex items-center gap-1 font-semibold text-amber-400">
                      <AlertTriangle className="h-3 w-3" />
                      {mod.findingsCount} issue(s)
                    </span>
                  )}
                </div>
              </div>
            </motion.div>
          )
        })}
      </div>
    </div>
  )
}
