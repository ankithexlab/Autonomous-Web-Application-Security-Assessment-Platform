import { motion } from "framer-motion"
import { Crosshair, ShieldCheck, Activity, AlertTriangle } from "lucide-react"
import type { Target } from "@/types"

interface TargetStatsBarProps {
  targets?: Target[]
}

export function TargetStatsBar({ targets = [] }: TargetStatsBarProps) {
  const total = targets.length
  const active = targets.filter((t) => t.status === "active").length
  const verified = targets.filter((t) => t.validationStatus === "verified").length
  const criticalFindings = targets.reduce((sum, t) => sum + (t.criticalFindings || 0), 0)

  const stats = [
    {
      label: "Total Targets",
      value: total,
      icon: Crosshair,
      color: "text-blue-400",
      bg: "bg-blue-500/10",
    },
    {
      label: "Active",
      value: active,
      icon: Activity,
      color: "text-emerald-400",
      bg: "bg-emerald-500/10",
    },
    {
      label: "Verified",
      value: verified,
      icon: ShieldCheck,
      color: "text-violet-400",
      bg: "bg-violet-500/10",
    },
    {
      label: "Critical Findings",
      value: criticalFindings,
      icon: AlertTriangle,
      color: "text-red-400",
      bg: "bg-red-500/10",
    },
  ]

  return (
    <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
      {stats.map((stat, i) => (
        <motion.div
          key={stat.label}
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: i * 0.06 }}
          className="flex items-center gap-3 rounded-xl border border-border bg-card px-4 py-3"
        >
          <div className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-lg ${stat.bg}`}>
            <stat.icon className={`h-4.5 w-4.5 ${stat.color}`} />
          </div>
          <div>
            <p className="text-xl font-bold tracking-tight text-foreground">{stat.value}</p>
            <p className="text-xs text-muted-foreground">{stat.label}</p>
          </div>
        </motion.div>
      ))}
    </div>
  )
}

