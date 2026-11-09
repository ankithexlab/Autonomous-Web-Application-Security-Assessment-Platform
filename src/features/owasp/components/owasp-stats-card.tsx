import { motion } from "framer-motion"
import { cn } from "@/utils"
import type { LucideIcon } from "lucide-react"
import { TrendingDown, TrendingUp, Minus } from "lucide-react"

interface StatsCardProps {
  label: string
  value: string | number
  subtitle?: string
  icon?: LucideIcon
  iconColor?: string
  iconBg?: string
  change?: number
  changeLabel?: string
  highlight?: boolean
  highlightColor?: string
  index?: number
}

export function OWASPStatsCard({
  label,
  value,
  subtitle,
  icon: Icon,
  iconColor = "text-primary",
  iconBg = "bg-primary/10",
  change,
  changeLabel = "vs last scan",
  highlight = false,
  highlightColor = "border-primary/30",
  index = 0,
}: StatsCardProps) {
  const isNegative = change !== undefined && change < 0
  const isPositive = change !== undefined && change > 0

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3, delay: index * 0.06 }}
      className={cn(
        "rounded-xl border bg-card p-4 space-y-3 shadow-xs transition-all hover:shadow-sm",
        highlight ? highlightColor : "border-border",
      )}
    >
      <div className="flex items-start justify-between gap-2">
        <span className="text-xs font-medium text-muted-foreground">{label}</span>
        {Icon && (
          <div className={cn("flex h-8 w-8 shrink-0 items-center justify-center rounded-lg", iconBg)}>
            <Icon className={cn("h-4 w-4", iconColor)} />
          </div>
        )}
      </div>

      <div>
        <span className="text-2xl font-extrabold tracking-tight text-foreground tabular-nums">
          {value}
        </span>
        {subtitle && (
          <p className="text-xs text-muted-foreground mt-0.5">{subtitle}</p>
        )}
      </div>

      {change !== undefined && (
        <div className={cn(
          "flex items-center gap-1 text-xs font-medium",
          isNegative ? "text-emerald-400" : isPositive ? "text-red-400" : "text-muted-foreground",
        )}>
          {isNegative ? <TrendingDown className="h-3 w-3" /> :
           isPositive ? <TrendingUp className="h-3 w-3" /> :
           <Minus className="h-3 w-3" />}
          <span>
            {change === 0 ? "No change" : `${Math.abs(change)}% ${isNegative ? "better" : "worse"}`}
          </span>
          <span className="text-muted-foreground/60">{changeLabel}</span>
        </div>
      )}
    </motion.div>
  )
}
