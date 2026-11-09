import { motion } from "framer-motion"
import { TrendingDown, TrendingUp } from "lucide-react"
import { cn } from "@/utils"

interface RiskMeterProps {
  score: number
  label?: string
  subtitle?: string
  change?: number
  size?: "sm" | "md" | "lg"
}

function getRiskLevel(score: number): { label: string; color: string; trackColor: string } {
  if (score <= 25) return { label: "Low Risk", color: "text-emerald-400", trackColor: "#10b981" }
  if (score <= 50) return { label: "Moderate Risk", color: "text-amber-400", trackColor: "#f59e0b" }
  if (score <= 75) return { label: "High Risk", color: "text-orange-400", trackColor: "#f97316" }
  return { label: "Critical Risk", color: "text-red-400", trackColor: "#ef4444" }
}

export function RiskMeter({ score, label = "Risk Score", subtitle, change, size = "md" }: RiskMeterProps) {
  const { label: riskLabel, color } = getRiskLevel(score)

  const sizeConfig = {
    sm: { viewBox: 160, cx: 80, cy: 85, r: 60, sw: 8, textSize: "text-2xl" },
    md: { viewBox: 200, cx: 100, cy: 110, r: 80, sw: 10, textSize: "text-3xl" },
    lg: { viewBox: 240, cx: 120, cy: 130, r: 100, sw: 12, textSize: "text-4xl" },
  }[size]

  const halfCirc = Math.PI * sizeConfig.r
  const dashOffset = halfCirc - (score / 100) * halfCirc

  const d = `M ${sizeConfig.cx - sizeConfig.r} ${sizeConfig.cy} A ${sizeConfig.r} ${sizeConfig.r} 0 0 1 ${sizeConfig.cx + sizeConfig.r} ${sizeConfig.cy}`

  return (
    <div className="flex flex-col items-center space-y-2">
      <div className="relative" style={{ height: sizeConfig.viewBox / 2 + 20, width: sizeConfig.viewBox }}>
        <svg
          width={sizeConfig.viewBox}
          height={sizeConfig.viewBox / 2 + 20}
          viewBox={`0 0 ${sizeConfig.viewBox} ${sizeConfig.viewBox / 2 + 20}`}
          className="overflow-visible"
        >
          <defs>
            <linearGradient id="riskArcGrad" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#10b981" />
              <stop offset="50%" stopColor="#f59e0b" />
              <stop offset="100%" stopColor="#ef4444" />
            </linearGradient>
          </defs>

          {/* Track */}
          <path
            d={d}
            fill="none"
            stroke="var(--border)"
            strokeWidth={sizeConfig.sw}
            strokeLinecap="round"
          />

          {/* Progress */}
          <motion.path
            d={d}
            fill="none"
            stroke="url(#riskArcGrad)"
            strokeWidth={sizeConfig.sw}
            strokeLinecap="round"
            strokeDasharray={halfCirc}
            initial={{ strokeDashoffset: halfCirc }}
            animate={{ strokeDashoffset: dashOffset }}
            transition={{ duration: 1.4, ease: "easeOut", delay: 0.2 }}
          />
        </svg>

        {/* Center Text */}
        <div className="absolute inset-0 flex flex-col items-center justify-end pb-1">
          <motion.span
            initial={{ opacity: 0, scale: 0.8 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: 0.5 }}
            className={cn("font-extrabold tracking-tight text-foreground", sizeConfig.textSize)}
          >
            {score}
            <span className="text-base font-normal text-muted-foreground">/100</span>
          </motion.span>
          <span className={cn("text-xs font-bold mt-0.5", color)}>{riskLabel}</span>
        </div>
      </div>

      <div className="text-center space-y-0.5">
        <p className="text-sm font-semibold text-foreground">{label}</p>
        {subtitle && <p className="text-xs text-muted-foreground">{subtitle}</p>}
        {change !== undefined && (
          <div className={cn("flex items-center justify-center gap-1 text-xs font-medium", change <= 0 ? "text-emerald-400" : "text-red-400")}>
            {change <= 0 ? <TrendingDown className="h-3 w-3" /> : <TrendingUp className="h-3 w-3" />}
            <span>{Math.abs(change)}% {change <= 0 ? "improvement" : "increase"} this week</span>
          </div>
        )}
      </div>
    </div>
  )
}
