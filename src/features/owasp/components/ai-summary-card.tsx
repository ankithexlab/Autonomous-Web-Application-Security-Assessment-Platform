import { motion } from "framer-motion"
import { Sparkles, AlertTriangle, ShieldAlert, AlertCircle, ArrowRight } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { cn } from "@/utils"
import type { OWASPSeverity } from "../types/owasp"
import { OWASP_CATEGORIES } from "../data/owasp-data"

interface AISummaryItem {
  id: string
  category: string
  insight: string
  recommendation: string
  severity: OWASPSeverity
  confidence: number
}

interface AISummaryCardProps {
  insights: AISummaryItem[]
  onOpenAssistant?: () => void
}

const SeverityIcon = ({ severity }: { severity: OWASPSeverity }) => {
  if (severity === "critical") return <AlertTriangle className="h-4 w-4 text-red-400 shrink-0 mt-0.5" />
  if (severity === "high") return <ShieldAlert className="h-4 w-4 text-orange-400 shrink-0 mt-0.5" />
  return <AlertCircle className="h-4 w-4 text-amber-400 shrink-0 mt-0.5" />
}

export function AISummaryCard({ insights, onOpenAssistant }: AISummaryCardProps) {
  return (
    <div className="rounded-xl border border-violet-500/30 bg-card p-5 space-y-4 shadow-sm relative overflow-hidden">
      {/* Glow */}
      <div className="pointer-events-none absolute right-0 top-0 h-48 w-48 rounded-full bg-violet-500/5 blur-3xl" />

      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-violet-500/30 bg-violet-500/15 text-violet-400">
            <Sparkles className="h-4 w-4" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-foreground">Sentinel AI — OWASP Insights</h3>
            <p className="text-[11px] text-muted-foreground">Neural threat correlation across OWASP Top 10</p>
          </div>
        </div>
        <Badge variant="outline" className="bg-violet-500/10 text-violet-300 border-violet-500/30 text-[10px] shrink-0">
          Neural 3.5
        </Badge>
      </div>

      {/* Insight Items */}
      <div className="space-y-2.5">
        {insights.length === 0 ? (
          <div className="py-6 text-center text-xs text-muted-foreground">
            No active vulnerabilities detected across OWASP categories. Clean posture baseline verified.
          </div>
        ) : (
          insights.map((item, idx) => {
            const catMeta = OWASP_CATEGORIES.find((c) => c.id === item.category)
            return (
              <motion.div
                key={item.id}
                initial={{ opacity: 0, x: -8 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ duration: 0.3, delay: idx * 0.08 }}
                className="flex items-start gap-3 rounded-lg border border-border/60 bg-muted/20 p-3 hover:bg-muted/40 transition-colors"
              >
                <SeverityIcon severity={item.severity} />
                <div className="min-w-0 flex-1 space-y-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-xs font-bold text-foreground">{item.category}</span>
                    {catMeta && (
                      <span className={cn("text-[10px] font-semibold", catMeta.color)}>
                        {catMeta.shortName}
                      </span>
                    )}
                    <span className="ml-auto text-[10px] font-mono text-muted-foreground">
                      {item.confidence}% confidence
                    </span>
                  </div>
                  <p className="text-[11px] text-muted-foreground leading-tight">{item.insight}</p>
                  <p className="text-[11px] text-violet-300/80 italic leading-tight">
                    → {item.recommendation}
                  </p>
                </div>
              </motion.div>
            )
          })
        )}
      </div>

      {onOpenAssistant && (
        <Button
          size="sm"
          variant="ghost"
          onClick={onOpenAssistant}
          className="w-full gap-2 text-xs font-semibold text-violet-300 hover:text-violet-200 hover:bg-violet-500/15"
        >
          <span>Open Sentinel AI Assistant</span>
          <ArrowRight className="h-3.5 w-3.5" />
        </Button>
      )}
    </div>
  )
}
