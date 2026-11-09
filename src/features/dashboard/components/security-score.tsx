import { motion } from "framer-motion"
import { cn } from "@/utils"

function getScoreColor(score: number): string {
  if (score >= 80) return "text-emerald-500"
  if (score >= 60) return "text-amber-400"
  return "text-red-400"
}

function getScoreGrade(score: number): string {
  if (score >= 90) return "A"
  if (score >= 80) return "B"
  if (score >= 70) return "C"
  if (score >= 60) return "D"
  return "F"
}

function getStrokeColor(score: number): string {
  if (score >= 80) return "#10b981"
  if (score >= 60) return "#f59e0b"
  return "#ef4444"
}

interface SecurityScoreWidgetProps {
  score?: number
  breakdown?: { label: string; score: number }[]
}

export function SecurityScoreWidget({ score, breakdown }: SecurityScoreWidgetProps) {
  const currentScore = score !== undefined ? Math.round(score) : 100
  const scoreBreakdown = breakdown || [
    { label: "Endpoint Security", score: currentScore },
    { label: "Vulnerability Posture", score: currentScore },
    { label: "Access Controls", score: currentScore },
  ]

  const radius = 70
  const strokeWidth = 10
  const circumference = 2 * Math.PI * radius
  const progress = (currentScore / 100) * circumference
  const strokeColor = getStrokeColor(currentScore)

  return (
    <div className="rounded-xl border border-border bg-card p-5">
      <h3 className="text-sm font-semibold text-foreground">Security Posture Score</h3>
      <p className="text-xs text-muted-foreground">
        Live database security risk assessment
      </p>

      {/* Radial gauge */}
      <div className="my-5 flex justify-center">
        <div className="relative h-[180px] w-[180px]">
          <svg
            className="h-full w-full -rotate-90"
            viewBox="0 0 180 180"
          >
            {/* Background track */}
            <circle
              cx="90"
              cy="90"
              r={radius}
              fill="none"
              stroke="currentColor"
              strokeWidth={strokeWidth}
              className="text-muted/30"
            />
            {/* Progress arc */}
            <motion.circle
              cx="90"
              cy="90"
              r={radius}
              fill="none"
              stroke={strokeColor}
              strokeWidth={strokeWidth}
              strokeLinecap="round"
              strokeDasharray={circumference}
              initial={{ strokeDashoffset: circumference }}
              animate={{ strokeDashoffset: circumference - progress }}
              transition={{ duration: 1.2, ease: "easeOut", delay: 0.3 }}
            />
          </svg>
          {/* Center text */}
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <motion.span
              initial={{ opacity: 0, scale: 0.8 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ duration: 0.5, delay: 0.6 }}
              className={cn(
                "text-4xl font-bold tracking-tight",
                getScoreColor(currentScore),
              )}
            >
              {currentScore}
            </motion.span>
            <span className="text-xs font-medium text-muted-foreground">
              Grade {getScoreGrade(currentScore)}
            </span>
          </div>
        </div>
      </div>

      {/* Breakdown bars */}
      <div className="space-y-3">
        {scoreBreakdown.map((item) => (
          <div key={item.label} className="space-y-1">
            <div className="flex items-center justify-between text-xs">
              <span className="text-muted-foreground">{item.label}</span>
              <span
                className={cn(
                  "font-semibold",
                  getScoreColor(item.score),
                )}
              >
                {item.score}
              </span>
            </div>
            <div className="h-1.5 w-full overflow-hidden rounded-full bg-muted/30">
              <motion.div
                className="h-full rounded-full"
                style={{ backgroundColor: getStrokeColor(item.score) }}
                initial={{ width: 0 }}
                animate={{ width: `${item.score}%` }}
                transition={{ duration: 0.8, ease: "easeOut", delay: 0.5 }}
              />
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
