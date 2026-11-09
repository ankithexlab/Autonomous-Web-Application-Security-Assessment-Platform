import { motion } from "framer-motion"
import { useNavigate } from "react-router"
import { Sparkles, AlertTriangle, ShieldAlert, CheckCircle2, ArrowRight } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { ROUTES } from "@/constants"

interface AIInsightsCardProps {
  topFindings?: {
    id: string
    title: string
    severity: string
    category: string
    target?: string
  }[]
}

export function AIInsightsCard({ topFindings }: AIInsightsCardProps) {
  const navigate = useNavigate()

  const displayInsights =
    topFindings && topFindings.length > 0
      ? topFindings.slice(0, 3).map((f, idx) => ({
          id: f.id || `ins-real-${idx}`,
          severity: f.severity,
          title: f.title,
          description: `Detected in target ${f.target || "system"}. Category: ${f.category}. Automated remediation recommended.`,
        }))
      : [
          {
            id: "ins-clean-1",
            severity: "low",
            title: "Clean Posture Baseline",
            description:
              "No active critical or high vulnerability vectors identified in current database targets.",
          },
        ]

  return (
    <div className="rounded-xl border border-violet-500/30 bg-card p-5 space-y-4 shadow-sm relative overflow-hidden">
      {/* Background Subtle Gradient */}
      <div className="pointer-events-none absolute right-0 top-0 h-40 w-40 rounded-full bg-violet-500/5 blur-2xl" />

      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-violet-500/15 border border-violet-500/30 text-violet-400">
            <Sparkles className="h-4 w-4" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-foreground flex items-center gap-2">
              Sentinel AI Threat Insights
            </h3>
            <p className="text-[11px] text-muted-foreground">
              Automated neural correlation & risk recommendations
            </p>
          </div>
        </div>
        <Badge variant="outline" className="text-[10px] bg-violet-500/10 text-violet-300 border-violet-500/30">
          Neural 3.5
        </Badge>
      </div>

      {/* Insight Items */}
      <div className="space-y-2.5">
        {displayInsights.map((item, idx) => (
          <motion.div
            key={item.id}
            initial={{ opacity: 0, x: -10 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.3, delay: idx * 0.1 }}
            className="flex items-start gap-3 rounded-lg border border-border/60 bg-muted/20 p-3 hover:bg-muted/40 transition-colors"
          >
            {item.severity === "critical" ? (
              <AlertTriangle className="h-4 w-4 text-red-400 shrink-0 mt-0.5" />
            ) : item.severity === "high" ? (
              <ShieldAlert className="h-4 w-4 text-orange-400 shrink-0 mt-0.5" />
            ) : (
              <CheckCircle2 className="h-4 w-4 text-amber-400 shrink-0 mt-0.5" />
            )}

            <div className="min-w-0 flex-1">
              <span className="text-xs font-bold text-foreground block">
                {item.title}
              </span>
              <p className="text-[11px] text-muted-foreground leading-tight mt-0.5">
                {item.description}
              </p>
            </div>
          </motion.div>
        ))}
      </div>

      {/* Footer CTA */}
      <Button
        size="sm"
        variant="ghost"
        onClick={() => navigate(ROUTES.AI_ASSISTANT)}
        className="w-full gap-2 text-xs font-semibold text-violet-300 hover:text-violet-200 hover:bg-violet-500/15"
      >
        <span>Open Sentinel AI Assistant</span>
        <ArrowRight className="h-3.5 w-3.5" />
      </Button>
    </div>
  )
}
