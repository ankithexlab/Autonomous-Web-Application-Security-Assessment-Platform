import { motion } from "framer-motion"
import { Radar, Play, Clock, CheckCircle2, XCircle, AlertTriangle } from "lucide-react"
import type { Scan } from "@/types"

interface ScanStatsBarProps {
  scans?: Scan[]
}

export function ScanStatsBar({ scans = [] }: ScanStatsBarProps) {
  const total = scans.length
  const running = scans.filter((s) => s.status === "running").length
  const queued = scans.filter((s) => s.status === "queued").length
  const completed = scans.filter((s) => s.status === "completed").length
  const failed = scans.filter((s) => s.status === "failed" || s.status === "cancelled").length
  const criticalFindings = scans.reduce((acc, s) => acc + (s.criticalCount || 0), 0)

  const stats = [
    { label: "Total Scans", value: total, icon: Radar, color: "text-blue-400", bg: "bg-blue-500/10" },
    { label: "Running", value: running, icon: Play, color: "text-emerald-400", bg: "bg-emerald-500/10" },
    { label: "Queued", value: queued, icon: Clock, color: "text-amber-400", bg: "bg-amber-500/10" },
    { label: "Completed", value: completed, icon: CheckCircle2, color: "text-violet-400", bg: "bg-violet-500/10" },
    { label: "Failed", value: failed, icon: XCircle, color: "text-red-400", bg: "bg-red-500/10" },
    { label: "Critical Findings", value: criticalFindings, icon: AlertTriangle, color: "text-rose-400", bg: "bg-rose-500/10" },
  ]

  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
      {stats.map((stat, i) => (
        <motion.div
          key={stat.label}
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: i * 0.05 }}
          className="flex items-center gap-3 rounded-xl border border-border bg-card px-4 py-3"
        >
          <div className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-lg ${stat.bg}`}>
            <stat.icon className={`h-4 w-4 ${stat.color}`} />
          </div>
          <div>
            <p className="text-xl font-bold tracking-tight text-foreground">{stat.value}</p>
            <p className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">{stat.label}</p>
          </div>
        </motion.div>
      ))}
    </div>
  )
}
