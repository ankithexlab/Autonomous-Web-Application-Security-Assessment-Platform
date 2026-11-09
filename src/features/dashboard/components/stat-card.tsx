import {
  Radar,
  ShieldAlert,
  AlertTriangle,
  ShieldCheck,
  TrendingUp,
  TrendingDown,
  type LucideIcon,
} from "lucide-react"
import { motion } from "framer-motion"
import { cn } from "@/utils"
import type { DashboardStat } from "../data/dashboard-data"

const ICON_MAP: Record<string, LucideIcon> = {
  radar: Radar,
  "shield-alert": ShieldAlert,
  "alert-triangle": AlertTriangle,
  "shield-check": ShieldCheck,
}

interface StatCardProps {
  stat: DashboardStat
  index: number
}

export function StatCard({ stat, index }: StatCardProps) {
  const Icon = ICON_MAP[stat.icon] ?? Radar
  const isPositive = stat.change > 0
  const isNegativeGood = stat.icon === "shield-alert" || stat.icon === "alert-triangle"
  const isGood = isNegativeGood ? !isPositive : isPositive

  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3, delay: index * 0.08, ease: "easeOut" }}
      className="rounded-xl border border-border bg-card p-5"
    >
      <div className="flex items-start justify-between">
        <div className="space-y-3">
          <p className="text-sm font-medium text-muted-foreground">
            {stat.label}
          </p>
          <p className="text-3xl font-bold tracking-tight text-foreground">
            {typeof stat.value === "number"
              ? stat.value.toLocaleString()
              : stat.value}
          </p>
        </div>
        <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-primary/10">
          <Icon className="h-5 w-5 text-primary" />
        </div>
      </div>

      <div className="mt-3 flex items-center gap-1.5 text-xs">
        {isGood ? (
          <TrendingUp className="h-3.5 w-3.5 text-emerald-500" />
        ) : (
          <TrendingDown className="h-3.5 w-3.5 text-red-400" />
        )}
        <span
          className={cn(
            "font-medium",
            isGood ? "text-emerald-500" : "text-red-400",
          )}
        >
          {isPositive ? "+" : ""}
          {stat.change}%
        </span>
        <span className="text-muted-foreground">{stat.changeLabel}</span>
      </div>
    </motion.div>
  )
}
