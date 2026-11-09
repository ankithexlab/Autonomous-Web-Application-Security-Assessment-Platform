import { motion } from "framer-motion"
import { ShieldAlert, TrendingDown } from "lucide-react"
import { cn } from "@/utils"

function getRiskLevelBadge(level: string) {
  switch (level) {
    case "Low":
      return "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"
    case "Moderate":
      return "bg-amber-500/10 text-amber-400 border-amber-500/30"
    case "High":
      return "bg-orange-500/10 text-orange-400 border-orange-500/30"
    default:
      return "bg-red-500/10 text-red-400 border-red-500/30"
  }
}

function getFactorColor(status: "good" | "warning" | "danger") {
  if (status === "good") return "bg-emerald-500"
  if (status === "warning") return "bg-amber-500"
  return "bg-red-500"
}

interface RiskMeterWidgetProps {
  score?: number
  level?: string
  change?: number
  factors?: { label: string; value: number; status: "good" | "warning" | "danger" }[]
}

export function RiskMeterWidget({ score: scoreProp, level: levelProp, change: changeProp, factors: factorsProp }: RiskMeterWidgetProps) {
  // Convert security score (0-100 where 100 is best) into risk score (0-100 where 0 is lowest risk)
  const riskScore = scoreProp !== undefined ? Math.max(0, Math.min(100, Math.round(100 - scoreProp))) : 0
  const level = levelProp || (riskScore > 60 ? "Critical" : riskScore > 35 ? "High" : riskScore > 15 ? "Moderate" : "Low")
  const change = changeProp !== undefined ? changeProp : 0
  const factors: { label: string; value: number; status: "good" | "warning" | "danger" }[] = factorsProp || [
    { label: "Critical Vulnerabilities", value: riskScore > 60 ? 40 : 0, status: riskScore > 60 ? "danger" : "good" },
    { label: "Attack Surface Exposure", value: riskScore > 35 ? 30 : 5, status: riskScore > 35 ? "warning" : "good" },
    { label: "Configuration Hardening", value: 100 - riskScore, status: riskScore > 30 ? "warning" : "good" },
  ]

  // Half-circle arc geometry
  const radius = 65
  const strokeWidth = 10
  const circumference = Math.PI * radius
  const strokeDashoffset = circumference - (riskScore / 100) * circumference

  return (
    <div className="rounded-xl border border-border bg-card p-5 space-y-4 shadow-sm">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-semibold text-foreground flex items-center gap-2">
            <ShieldAlert className="h-4 w-4 text-amber-400" />
            System Risk Index
          </h3>
          <p className="text-xs text-muted-foreground">
            CVSS-weighted vulnerability exposure meter
          </p>
        </div>
        <div className={cn("px-2.5 py-1 text-xs font-bold rounded-full border", getRiskLevelBadge(level))}>
          {level} Risk
        </div>
      </div>

      {/* Semi-circular Radial Meter */}
      <div className="relative flex flex-col items-center justify-center pt-2">
        <div className="relative h-[110px] w-[200px] overflow-hidden">
          <svg className="h-[140px] w-[200px]" viewBox="0 0 200 110">
            <defs>
              <linearGradient id="riskGradient" x1="0%" y1="0%" x2="100%" y2="0%">
                <stop offset="0%" stopColor="#10b981" />
                <stop offset="50%" stopColor="#f59e0b" />
                <stop offset="100%" stopColor="#ef4444" />
              </linearGradient>
            </defs>

            {/* Background Arc */}
            <path
              d="M 20 100 A 80 80 0 0 1 180 100"
              fill="none"
              stroke="var(--border)"
              strokeWidth={strokeWidth}
              strokeLinecap="round"
            />

            {/* Progress Arc */}
            <motion.path
              d="M 20 100 A 80 80 0 0 1 180 100"
              fill="none"
              stroke="url(#riskGradient)"
              strokeWidth={strokeWidth}
              strokeLinecap="round"
              strokeDasharray={circumference}
              initial={{ strokeDashoffset: circumference }}
              animate={{ strokeDashoffset }}
              transition={{ duration: 1.2, ease: "easeOut" }}
            />
          </svg>

          {/* Needle / Gauge Center display */}
          <div className="absolute inset-0 flex flex-col items-center justify-end pb-2">
            <motion.span
              initial={{ opacity: 0, scale: 0.8 }}
              animate={{ opacity: 1, scale: 1 }}
              className="text-3xl font-extrabold tracking-tight text-foreground"
            >
              {riskScore}<span className="text-sm text-muted-foreground font-normal">/100</span>
            </motion.span>
            <div className="flex items-center gap-1 text-[11px] font-medium text-emerald-400">
              <TrendingDown className="h-3 w-3" />
              <span>{Math.abs(change)}% risk variance</span>
            </div>
          </div>
        </div>
      </div>

      {/* Risk Factors Breakdown */}
      <div className="space-y-2.5 pt-1 border-t border-border/50">
        <span className="text-[11px] font-semibold text-muted-foreground tracking-wider uppercase block">
          Key Risk Drivers
        </span>
        {factors.map((factor) => (
          <div key={factor.label} className="space-y-1">
            <div className="flex items-center justify-between text-xs">
              <span className="text-muted-foreground">{factor.label}</span>
              <span className="font-semibold text-foreground">{factor.value}%</span>
            </div>
            <div className="h-1.5 w-full overflow-hidden rounded-full bg-muted/40">
              <motion.div
                className={cn("h-full rounded-full", getFactorColor(factor.status))}
                initial={{ width: 0 }}
                animate={{ width: `${factor.value}%` }}
                transition={{ duration: 0.8, ease: "easeOut" }}
              />
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
