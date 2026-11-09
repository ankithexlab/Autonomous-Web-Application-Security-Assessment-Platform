import { motion } from "framer-motion"
import { Activity, Clock, ShieldAlert, Globe, Layers } from "lucide-react"
import { cn } from "@/utils"
import type { ScanEngineReturn } from "../hooks/use-scan-engine"

interface ScanCenterMetricsProps {
  engine: ScanEngineReturn
}

export function ScanCenterMetrics({ engine }: ScanCenterMetricsProps) {
  function formatTime(seconds: number): string {
    const m = Math.floor(seconds / 60)
    const s = seconds % 60
    return `${m}m ${s.toString().padStart(2, "0")}s`
  }

  const completedModulesCount = engine.activeModules.filter((m) => m.status === "completed").length

  const liveStats = [
    {
      label: "Assessment Target",
      value: engine.selectedTargetUrl ? engine.selectedTargetUrl.replace(/^https?:\/\//, "") : "None Selected",
      icon: Globe,
      color: "text-blue-400",
      bg: "bg-blue-500/10 border-blue-500/20",
    },
    {
      label: "Modules Progress",
      value: `${completedModulesCount} of ${engine.activeModules.length} Done`,
      icon: Layers,
      color: "text-violet-400",
      bg: "bg-violet-500/10 border-violet-500/20",
    },
    {
      label: "Pipeline Stage",
      value: `${engine.overallProgress}% Complete`,
      icon: Activity,
      color: "text-emerald-400",
      bg: "bg-emerald-500/10 border-emerald-500/20",
    },
    {
      label: "Issues Discovered",
      value: `${engine.totalFindingsCount} Findings`,
      icon: ShieldAlert,
      color: engine.criticalCount > 0 ? "text-red-400" : "text-amber-400",
      bg: engine.criticalCount > 0 ? "bg-red-500/10 border-red-500/20" : "bg-amber-500/10 border-amber-500/20",
    },
  ]

  const severityItems = [
    { label: "Critical", count: engine.criticalCount, color: "text-red-400", bg: "bg-red-500/15 border-red-500/30" },
    { label: "High", count: engine.highCount, color: "text-orange-400", bg: "bg-orange-500/15 border-orange-500/30" },
    { label: "Medium", count: engine.mediumCount, color: "text-amber-400", bg: "bg-amber-500/15 border-amber-500/30" },
    { label: "Low", count: engine.lowCount, color: "text-blue-400", bg: "bg-blue-500/15 border-blue-500/30" },
  ]

  return (
    <div className="space-y-4">
      {/* Top Banner: Global Scan Progress & Countdown */}
      <div className="rounded-2xl border border-border/80 bg-card p-5 shadow-sm">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-base font-bold text-foreground">Overall Scan Progress</h3>
              {engine.status === "running" && (
                <span className="flex items-center gap-1 rounded-full bg-emerald-500/10 px-2 py-0.5 text-[10px] font-semibold text-emerald-400">
                  <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-400" />
                  LIVE
                </span>
              )}
            </div>
            <p className="text-xs text-muted-foreground mt-0.5">
              {engine.status === "running" && `Executing active pipeline on ${engine.selectedTargetUrl}`}
              {engine.status === "queued" && "Scan queued — awaiting scanner worker allocation"}
              {engine.status === "completed" && "Scan run finished"}
              {engine.status === "failed" && "Scan execution failed"}
              {engine.status === "cancelled" && "Scan cancelled by operator"}
              {engine.status === "idle" && "Ready to launch scan"}
            </p>
          </div>

          {/* Time metrics */}
          <div className="flex items-center gap-4 text-xs font-mono">
            <div className="flex items-center gap-1.5 rounded-lg bg-muted/40 px-3 py-1.5">
              <Clock className="h-3.5 w-3.5 text-muted-foreground" />
              <span className="text-muted-foreground">Elapsed:</span>
              <span className="font-bold text-foreground">{formatTime(engine.elapsedSeconds)}</span>
            </div>

            <div className="flex items-center gap-1.5 rounded-lg bg-primary/10 px-3 py-1.5 text-primary">
              <span className="text-muted-foreground">ETA:</span>
              <span className="font-bold">
                {engine.status === "running" ? formatTime(engine.estimatedSecondsRemaining) : "--:--"}
              </span>
            </div>
          </div>
        </div>

        {/* Global Progress Bar */}
        <div className="mt-4 space-y-1.5">
          <div className="flex items-center justify-between text-xs">
            <span className="font-bold text-foreground">{engine.overallProgress}% Complete</span>
            <span className="text-muted-foreground">
              {engine.activeModules.filter((m) => m.status === "completed").length} of{" "}
              {engine.activeModules.length} Modules Done
            </span>
          </div>

          <div className="h-3 w-full overflow-hidden rounded-full bg-muted/60">
            <motion.div
              className="h-full rounded-full bg-gradient-to-r from-blue-500 via-indigo-500 to-emerald-400"
              initial={{ width: 0 }}
              animate={{ width: `${engine.overallProgress}%` }}
              transition={{ duration: 0.8, ease: "easeOut" }}
            />
          </div>
        </div>
      </div>

      {/* Live Stats Row */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        {liveStats.map((st) => {
          const Icon = st.icon
          return (
            <div
              key={st.label}
              className={cn("flex flex-col rounded-xl border p-3 shadow-xs", st.bg)}
            >
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-medium text-muted-foreground">{st.label}</span>
                <Icon className={cn("h-3.5 w-3.5", st.color)} />
              </div>
              <span className={cn("mt-1.5 text-xl font-extrabold tabular-nums", st.color)}>
                {st.value}
              </span>
            </div>
          )
        })}
      </div>

      {/* Severity Breakdown Card */}
      <div className="rounded-2xl border border-border/80 bg-card p-4 shadow-sm">
        <div className="flex items-center justify-between mb-3">
          <span className="text-xs font-bold text-foreground flex items-center gap-1.5">
            <ShieldAlert className="h-3.5 w-3.5 text-amber-400" />
            Discovered Vulnerabilities Breakdown
          </span>
          <span className="text-xs font-mono font-bold text-foreground">
            {engine.totalFindingsCount} Total
          </span>
        </div>

        <div className="grid grid-cols-4 gap-2">
          {severityItems.map((item) => (
            <div
              key={item.label}
              className={cn(
                "flex flex-col items-center rounded-xl border p-2.5 text-center transition-all",
                item.bg,
              )}
            >
              <span className={cn("text-lg font-extrabold tabular-nums", item.color)}>
                {item.count}
              </span>
              <span className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                {item.label}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
