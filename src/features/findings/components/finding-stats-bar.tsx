import { motion } from "framer-motion"
import { ShieldAlert, AlertTriangle, ShieldCheck, AlertCircle, Info } from "lucide-react"
import type { Finding } from "@/types"

interface FindingStatsBarProps {
  findings?: Finding[]
}

export function FindingStatsBar({ findings = [] }: FindingStatsBarProps) {
  const total = findings.length
  const critical = findings.filter((f) => f.severity === "critical").length
  const high = findings.filter((f) => f.severity === "high").length
  const medium = findings.filter((f) => f.severity === "medium").length
  const low = findings.filter((f) => f.severity === "low").length
  const resolved = findings.filter((f) => f.status === "resolved").length

  const stats = [
    { label: "Total Findings", value: total, icon: ShieldAlert, color: "text-blue-400", bg: "bg-blue-500/10" },
    { label: "Critical", value: critical, icon: AlertTriangle, color: "text-red-400", bg: "bg-red-500/10" },
    { label: "High", value: high, icon: AlertCircle, color: "text-orange-400", bg: "bg-orange-500/10" },
    { label: "Medium", value: medium, icon: AlertCircle, color: "text-amber-400", bg: "bg-amber-500/10" },
    { label: "Low", value: low, icon: Info, color: "text-sky-400", bg: "bg-sky-500/10" },
    { label: "Resolved", value: resolved, icon: ShieldCheck, color: "text-emerald-400", bg: "bg-emerald-500/10" },
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

