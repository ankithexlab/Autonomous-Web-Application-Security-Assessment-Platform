import { motion } from "framer-motion"
import { FolderKanban, CheckCircle2, PauseCircle, Archive, Target, AlertTriangle } from "lucide-react"
import type { Project } from "@/types"

interface ProjectStatsBarProps {
  projects: Project[]
}

export function ProjectStatsBar({ projects }: ProjectStatsBarProps) {
  const total = projects.length
  const active = projects.filter((p) => p.status === "active").length
  const paused = projects.filter((p) => p.status === "paused").length
  const archived = projects.filter((p) => p.status === "archived").length
  const totalTargets = projects.reduce((acc, p) => acc + p.targetCount, 0)
  const totalCritical = projects.reduce((acc, p) => acc + p.criticalCount, 0)

  const stats = [
    { label: "Total Projects", value: total, icon: FolderKanban, color: "text-blue-400", bg: "bg-blue-500/10" },
    { label: "Active", value: active, icon: CheckCircle2, color: "text-emerald-400", bg: "bg-emerald-500/10" },
    { label: "Paused", value: paused, icon: PauseCircle, color: "text-amber-400", bg: "bg-amber-500/10" },
    { label: "Archived", value: archived, icon: Archive, color: "text-zinc-400", bg: "bg-zinc-500/10" },
    { label: "Total Targets", value: totalTargets, icon: Target, color: "text-teal-400", bg: "bg-teal-500/10" },
    { label: "Critical Issues", value: totalCritical, icon: AlertTriangle, color: "text-rose-400", bg: "bg-rose-500/10" },
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
