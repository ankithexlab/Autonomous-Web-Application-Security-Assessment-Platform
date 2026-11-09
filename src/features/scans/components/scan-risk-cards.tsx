import { motion } from "framer-motion"
import { ShieldAlert, AlertTriangle, Bug, ShieldCheck, CheckCircle2 } from "lucide-react"
import { cn } from "@/utils"
import type { Scan } from "@/types"

interface ScanRiskCardsProps {
  scan: Scan
}

export function ScanRiskCards({ scan }: ScanRiskCardsProps) {
  const totalFindings = scan.findingsCount

  // Calculate CVSS average approximation based on severity counts
  const cvssAvg = totalFindings > 0
    ? ((scan.criticalCount * 9.5 + scan.highCount * 7.8 + scan.mediumCount * 5.2 + scan.lowCount * 2.8) / totalFindings).toFixed(1)
    : "0.0"

  const riskLevel = scan.criticalCount > 0 ? "Critical" : scan.highCount > 0 ? "High" : scan.mediumCount > 0 ? "Medium" : "Low"
  const riskBadgeColor = scan.criticalCount > 0
    ? "bg-red-500/10 text-red-400 border-red-500/30"
    : scan.highCount > 0
    ? "bg-orange-500/10 text-orange-400 border-orange-500/30"
    : scan.mediumCount > 0
    ? "bg-amber-500/10 text-amber-400 border-amber-500/30"
    : "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"

  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
      {/* Card 1: Risk Level */}
      <motion.div
        initial={{ opacity: 0, y: 6 }}
        animate={{ opacity: 1, y: 0 }}
        className="rounded-xl border border-border bg-card p-4 space-y-1.5 shadow-xs"
      >
        <div className="flex items-center justify-between text-xs text-muted-foreground">
          <span>Overall Risk</span>
          <ShieldAlert className="h-4 w-4 text-amber-400" />
        </div>
        <div className="flex items-center justify-between">
          <span className="text-xl font-bold text-foreground">{riskLevel}</span>
          <span className={cn("px-2 py-0.5 text-[10px] font-bold rounded-full border", riskBadgeColor)}>
            CVSS {cvssAvg}
          </span>
        </div>
      </motion.div>

      {/* Card 2: Critical Issues */}
      <motion.div
        initial={{ opacity: 0, y: 6 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.05 }}
        className="rounded-xl border border-border bg-card p-4 space-y-1.5 shadow-xs"
      >
        <div className="flex items-center justify-between text-xs text-muted-foreground">
          <span>Critical Vulnerabilities</span>
          <AlertTriangle className="h-4 w-4 text-red-400" />
        </div>
        <div className="flex items-center justify-between">
          <span className="text-xl font-bold text-foreground tabular-nums">{scan.criticalCount}</span>
          <span className="text-[11px] text-red-400 font-medium">Requires immediate patch</span>
        </div>
      </motion.div>

      {/* Card 3: High & Medium Issues */}
      <motion.div
        initial={{ opacity: 0, y: 6 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="rounded-xl border border-border bg-card p-4 space-y-1.5 shadow-xs"
      >
        <div className="flex items-center justify-between text-xs text-muted-foreground">
          <span>High / Medium Findings</span>
          <Bug className="h-4 w-4 text-orange-400" />
        </div>
        <div className="flex items-center justify-between">
          <span className="text-xl font-bold text-foreground tabular-nums">
            {scan.highCount + scan.mediumCount}
          </span>
          <span className="text-[11px] text-muted-foreground font-mono">
            H: {scan.highCount} | M: {scan.mediumCount}
          </span>
        </div>
      </motion.div>

      {/* Card 4: Passed Security Modules */}
      <motion.div
        initial={{ opacity: 0, y: 6 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.15 }}
        className="rounded-xl border border-border bg-card p-4 space-y-1.5 shadow-xs"
      >
        <div className="flex items-center justify-between text-xs text-muted-foreground">
          <span>Modules Executed</span>
          <ShieldCheck className="h-4 w-4 text-emerald-400" />
        </div>
        <div className="flex items-center justify-between">
          <span className="text-xl font-bold text-foreground tabular-nums">
            {scan.modules.filter((m) => m.status === "completed").length}/{scan.modules.length}
          </span>
          <span className="text-[11px] text-emerald-400 font-medium flex items-center gap-1">
            <CheckCircle2 className="h-3 w-3" />
            Verified
          </span>
        </div>
      </motion.div>
    </div>
  )
}
