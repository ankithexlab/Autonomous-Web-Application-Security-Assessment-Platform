import { motion } from "framer-motion"
import { FileBarChart, FileText, ShieldCheck, Cpu, Clock, CheckCircle2 } from "lucide-react"
import type { Report } from "@/types"

interface ReportStatsBarProps {
  reports?: Report[]
}

export function ReportStatsBar({ reports = [] }: ReportStatsBarProps) {
  const stats = [
    { label: "Total Reports", value: reports.length, icon: FileBarChart, color: "text-blue-400", bg: "bg-blue-500/10" },
    { label: "Executive", value: reports.filter((r) => r.type === "executive").length, icon: FileText, color: "text-violet-400", bg: "bg-violet-500/10" },
    { label: "Technical", value: reports.filter((r) => r.type === "technical").length, icon: Cpu, color: "text-amber-400", bg: "bg-amber-500/10" },
    { label: "Compliance", value: reports.filter((r) => r.type === "compliance").length, icon: ShieldCheck, color: "text-emerald-400", bg: "bg-emerald-500/10" },
    { label: "Completed", value: reports.filter((r) => r.status === "completed").length, icon: CheckCircle2, color: "text-teal-400", bg: "bg-teal-500/10" },
    { label: "Generating", value: reports.filter((r) => r.status === "generating").length, icon: Clock, color: "text-sky-400", bg: "bg-sky-500/10" },
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
