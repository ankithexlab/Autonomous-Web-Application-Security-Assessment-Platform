import { motion } from "framer-motion"
import { ShieldCheck, TrendingUp, Activity, Server, Shield, Key } from "lucide-react"

interface SecurityScoreCardProps {
  score?: number
  grade?: string
  trend?: string
}

export function SecurityScoreCard({
  score = 78,
  grade = "B",
  trend = "+5% vs last month",
}: SecurityScoreCardProps) {
  const ratingText =
    score >= 80 ? "Resilient Security Posture" : score >= 50 ? "Moderate Risk Posture" : "Elevated Risk Posture"
  const ratingDesc =
    score >= 80
      ? "Target assets demonstrate strong defensive controls with minimal exposure."
      : score >= 50
      ? "Identified vulnerabilities require remediation to improve posture."
      : "Critical vulnerabilities require immediate executive remediation."

  const subScores = [
    { label: "Application Code", score: Math.min(100, Math.max(0, Math.round(score * 1.02))), icon: Activity, color: "text-blue-400" },
    { label: "Infrastructure", score: Math.min(100, Math.max(0, Math.round(score * 0.96))), icon: Server, color: "text-amber-400" },
    { label: "Compliance & SOC2", score: Math.min(100, Math.max(0, Math.round(score * 1.05))), icon: Shield, color: "text-emerald-400" },
    { label: "Authentication & Identity", score: Math.min(100, Math.max(0, Math.round(score * 0.92))), icon: Key, color: "text-purple-400" },
  ]

  return (
    <div className="relative overflow-hidden rounded-2xl border border-border/80 bg-card p-5 shadow-sm space-y-4">
      {/* Background Cyber Glow */}
      <div className="pointer-events-none absolute -right-10 -top-10 h-40 w-40 rounded-full bg-primary/10 blur-2xl" />

      {/* Card Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary/10 text-primary">
            <ShieldCheck className="h-4.5 w-4.5" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-foreground">Security Posture Score</h3>
            <p className="text-[11px] text-muted-foreground">Real-time aggregate security health rating</p>
          </div>
        </div>

        <div className="flex items-center gap-1.5 rounded-full bg-emerald-500/10 px-2.5 py-0.5 text-xs font-bold text-emerald-400 border border-emerald-500/20">
          <TrendingUp className="h-3 w-3" />
          <span>{trend}</span>
        </div>
      </div>

      {/* Main Score Meter Display */}
      <div className="flex items-center justify-around gap-4 py-2 border-y border-border/40">
        <div className="relative flex items-center justify-center">
          {/* Radial Ring SVG */}
          <svg className="h-28 w-28 -rotate-90 transform">
            <circle
              cx="56"
              cy="56"
              r="48"
              stroke="currentColor"
              strokeWidth="8"
              className="text-muted/30"
              fill="transparent"
            />
            <motion.circle
              cx="56"
              cy="56"
              r="48"
              stroke="currentColor"
              strokeWidth="8"
              strokeDasharray={2 * Math.PI * 48}
              strokeDashoffset={2 * Math.PI * 48 * (1 - score / 100)}
              strokeLinecap="round"
              className="text-primary"
              fill="transparent"
              initial={{ strokeDashoffset: 2 * Math.PI * 48 }}
              animate={{ strokeDashoffset: 2 * Math.PI * 48 * (1 - score / 100) }}
              transition={{ duration: 1.2, ease: "easeOut" }}
            />
          </svg>
          <div className="absolute flex flex-col items-center justify-center text-center">
            <span className="text-2xl font-extrabold font-mono text-foreground">{score}</span>
            <span className="text-[9px] uppercase tracking-wider text-muted-foreground font-semibold">
              Out of 100
            </span>
          </div>
        </div>

        {/* Grade & Rating */}
        <div className="space-y-1.5 text-left">
          <div className="flex items-center gap-2">
            <span className="text-xs font-semibold text-muted-foreground">Risk Grade:</span>
            <span className="flex h-7 w-7 items-center justify-center rounded-lg bg-blue-500/15 font-mono text-sm font-extrabold text-blue-400 border border-blue-500/30">
              {grade}
            </span>
          </div>
          <p className="text-xs font-bold text-foreground">{ratingText}</p>
          <p className="text-[11px] text-muted-foreground max-w-[180px]">
            {ratingDesc}
          </p>
        </div>
      </div>

      {/* Sub-score Pills */}
      <div className="grid grid-cols-2 gap-2 text-xs font-mono">
        {subScores.map((item) => {
          const Icon = item.icon
          return (
            <div key={item.label} className="flex items-center justify-between rounded-lg bg-muted/20 p-2 border border-border/40">
              <div className="flex items-center gap-1.5 truncate">
                <Icon className={`h-3.5 w-3.5 shrink-0 ${item.color}`} />
                <span className="text-[10px] text-muted-foreground truncate">{item.label}</span>
              </div>
              <span className="font-bold text-foreground text-xs">{item.score}</span>
            </div>
          )
        })}
      </div>
    </div>
  )
}
