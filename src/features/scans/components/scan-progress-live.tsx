import { useEffect, useState } from "react"
import { motion, AnimatePresence } from "framer-motion"
import {
  Activity,
  ShieldAlert,
  Target,
  Clock,
  Layers,
} from "lucide-react"
import { cn } from "@/utils"
import type { Scan } from "@/types"

interface ScanProgressLiveProps {
  scan: Scan
}

/**
 * Real-time progress telemetry for active scans reflecting true backend metrics.
 */
export function ScanProgressLive({ scan }: ScanProgressLiveProps) {
  const isLive = scan.status === "running" || scan.status === "queued"
  const [now, setNow] = useState(Date.now())

  useEffect(() => {
    if (!isLive) return
    const interval = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(interval)
  }, [isLive])

  function formatElapsed(): string {
    if (!scan.startedAt) return "0m 00s"
    const startMs = new Date(scan.startedAt).getTime()
    const diffSec = Math.max(0, Math.floor((now - startMs) / 1000))
    const m = Math.floor(diffSec / 60)
    const s = diffSec % 60
    return `${m}m ${s.toString().padStart(2, "0")}s`
  }

  if (!isLive) return null

  const liveMetrics = [
    {
      label: "Target URL",
      value: scan.targetUrl || "Assessment Target",
      icon: Target,
      color: "text-blue-400",
      bg: "bg-blue-500/10",
    },
    {
      label: "Stage Progress",
      value: `${scan.progress}%`,
      icon: Activity,
      color: "text-emerald-400",
      bg: "bg-emerald-500/10",
    },
    {
      label: "Findings Identified",
      value: `${scan.findingsCount} (${scan.criticalCount} crit, ${scan.highCount} high)`,
      icon: ShieldAlert,
      color: scan.criticalCount > 0 ? "text-red-400" : "text-amber-400",
      bg: scan.criticalCount > 0 ? "bg-red-500/10" : "bg-amber-500/10",
    },
    {
      label: "Scan Type",
      value: scan.type.toUpperCase(),
      icon: Layers,
      color: "text-violet-400",
      bg: "bg-violet-500/10",
    },
    {
      label: "Elapsed Time",
      value: formatElapsed(),
      icon: Clock,
      color: "text-rose-400",
      bg: "bg-rose-500/10",
    },
  ]

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="rounded-xl border border-border bg-card p-4"
    >
      <div className="mb-3 flex items-center gap-2">
        <span className="flex items-center gap-1.5 text-xs font-semibold text-foreground">
          <Activity className="h-3.5 w-3.5 text-primary" />
          Real-Time Metrics
        </span>
        <span className="flex items-center gap-1 rounded-full bg-emerald-500/10 px-2 py-0.5 text-[10px] font-semibold text-emerald-400">
          <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-400" />
          LIVE
        </span>
      </div>

      <div className="grid grid-cols-5 gap-2">
        <AnimatePresence mode="popLayout">
          {liveMetrics.map((metric) => (
            <motion.div
              key={metric.label}
              layout
              className={cn(
                "flex flex-col items-center rounded-lg px-2 py-2.5",
                metric.bg,
              )}
            >
              <metric.icon className={cn("h-4 w-4 mb-1", metric.color)} />
              <motion.span
                key={String(metric.value)}
                initial={{ opacity: 0, scale: 0.8 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ duration: 0.3 }}
                className={cn("text-sm font-bold tabular-nums", metric.color)}
              >
                {metric.value}
              </motion.span>
              <span className="mt-0.5 text-[9px] font-medium uppercase tracking-wider text-muted-foreground">
                {metric.label}
              </span>
            </motion.div>
          ))}
        </AnimatePresence>
      </div>
    </motion.div>
  )
}
