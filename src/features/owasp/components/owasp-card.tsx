import { motion } from "framer-motion"
import { cn } from "@/utils"
import type { OWASPCategory } from "../types/owasp"
import { OWASP_CATEGORIES } from "../data/owasp-data"

interface OWASPCardProps {
  categoryId: OWASPCategory
  findingsCount: number
  criticalCount: number
  highCount: number
  coveragePercent: number
  status: "covered" | "partial" | "uncovered"
  lastScanned?: string
  compact?: boolean
  index?: number
  onClick?: () => void
}

const statusConfig = {
  covered: { label: "Covered", color: "text-emerald-400", dot: "bg-emerald-400" },
  partial: { label: "Partial", color: "text-amber-400", dot: "bg-amber-400" },
  uncovered: { label: "Uncovered", color: "text-red-400", dot: "bg-red-400" },
}

export function OWASPCard({
  categoryId,
  findingsCount,
  criticalCount,
  highCount,
  coveragePercent,
  status,
  lastScanned,
  compact = false,
  index = 0,
  onClick,
}: OWASPCardProps) {
  const meta = OWASP_CATEGORIES.find((c) => c.id === categoryId)!
  const sc = statusConfig[status]

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3, delay: index * 0.04 }}
      onClick={onClick}
      className={cn(
        "rounded-xl border bg-card p-4 space-y-3 transition-all duration-200 shadow-xs",
        meta.borderColor,
        onClick && "cursor-pointer hover:shadow-md hover:-translate-y-0.5",
      )}
    >
      {/* Header */}
      <div className="flex items-start justify-between gap-2">
        <div>
          <span className={cn("text-[10px] font-bold uppercase tracking-widest", meta.color)}>
            {categoryId}
          </span>
          <h4 className="text-sm font-bold text-foreground leading-tight mt-0.5">
            {meta.shortName}
          </h4>
        </div>
        <div className={cn("flex items-center gap-1.5 text-[10px] font-semibold", sc.color)}>
          <span className={cn("h-2 w-2 rounded-full", sc.dot)} />
          {sc.label}
        </div>
      </div>

      {/* Coverage bar */}
      <div className="space-y-1">
        <div className="flex items-center justify-between text-[11px] text-muted-foreground">
          <span>Coverage</span>
          <span className="font-semibold text-foreground">{coveragePercent}%</span>
        </div>
        <div className="h-1.5 w-full rounded-full bg-muted/40 overflow-hidden">
          <motion.div
            className={cn("h-full rounded-full", meta.bgColor.replace("/10", ""), coveragePercent >= 80 ? "bg-emerald-500" : coveragePercent >= 50 ? "bg-amber-500" : "bg-red-500")}
            initial={{ width: 0 }}
            animate={{ width: `${coveragePercent}%` }}
            transition={{ duration: 0.8, ease: "easeOut", delay: index * 0.04 + 0.2 }}
          />
        </div>
      </div>

      {!compact && (
        <div className="grid grid-cols-3 gap-1.5 text-center">
          <div className={cn("rounded-md px-1.5 py-1", "bg-red-500/10")}>
            <span className="block text-sm font-bold text-red-400">{criticalCount}</span>
            <span className="text-[9px] text-muted-foreground">Critical</span>
          </div>
          <div className="rounded-md px-1.5 py-1 bg-orange-500/10">
            <span className="block text-sm font-bold text-orange-400">{highCount}</span>
            <span className="text-[9px] text-muted-foreground">High</span>
          </div>
          <div className="rounded-md px-1.5 py-1 bg-muted/30">
            <span className="block text-sm font-bold text-foreground">{findingsCount}</span>
            <span className="text-[9px] text-muted-foreground">Total</span>
          </div>
        </div>
      )}

      {lastScanned && (
        <p className="text-[10px] text-muted-foreground/70 font-mono">
          Last scanned: {lastScanned}
        </p>
      )}
    </motion.div>
  )
}
