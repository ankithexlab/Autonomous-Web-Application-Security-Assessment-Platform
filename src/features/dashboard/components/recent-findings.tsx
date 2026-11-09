import { useNavigate } from "react-router"
import { ArrowUpRight, Target } from "lucide-react"
import { motion } from "framer-motion"
import { cn } from "@/utils"
import { ROUTES } from "@/constants"
import { SeverityBadge } from "./severity-badge"

function getCvssColor(score: number): string {
  if (score >= 9) return "text-red-400"
  if (score >= 7) return "text-orange-400"
  if (score >= 4) return "text-amber-400"
  return "text-blue-400"
}

interface RecentFindingsProps {
  findings?: {
    id: string
    title: string
    severity: "critical" | "high" | "medium" | "low" | "info"
    category: string
    target: string
    created_at: string | null
    cvss_score: number
  }[]
}

export function RecentFindings({ findings }: RecentFindingsProps) {
  const navigate = useNavigate()
  const items = findings || []

  return (
    <div className="rounded-xl border border-border bg-card">
      <div className="flex items-center justify-between border-b border-border p-5">
        <div>
          <h3 className="text-sm font-semibold text-foreground">
            Recent Findings
          </h3>
          <p className="text-xs text-muted-foreground">
            Latest vulnerabilities detected across targets
          </p>
        </div>
        <button
          onClick={() => navigate(ROUTES.FINDINGS)}
          className="inline-flex items-center gap-1 rounded-md border border-border bg-background px-3 py-1.5 text-xs font-medium text-foreground transition-colors hover:bg-accent"
        >
          View all
          <ArrowUpRight className="h-3.5 w-3.5" />
        </button>
      </div>

      {items.length === 0 ? (
        <div className="p-8 text-center text-xs text-muted-foreground">
          No vulnerability findings detected in current database.
        </div>
      ) : (
        <div className="divide-y divide-border">
          {items.map((finding, index) => (
            <motion.div
              key={finding.id}
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{
                duration: 0.25,
                delay: index * 0.05,
                ease: "easeOut",
              }}
              onClick={() => navigate(ROUTES.FINDINGS)}
              className="group flex cursor-pointer items-center gap-4 p-4 transition-colors hover:bg-accent/30"
            >
              <SeverityBadge
                severity={finding.severity}
                className="w-[72px] justify-center shrink-0"
              />

              <div className="min-w-0 flex-1">
                <p className="truncate text-sm font-medium text-foreground group-hover:text-primary transition-colors">
                  {finding.title}
                </p>
                <div className="mt-1 flex items-center gap-3 text-xs text-muted-foreground">
                  <span className="inline-flex items-center gap-1">
                    <Target className="h-3 w-3" />
                    {finding.target}
                  </span>
                  <span className="text-border">•</span>
                  <span>{finding.category}</span>
                  <span className="text-border">•</span>
                  <span>
                    {"discoveredAt" in finding
                      ? (finding as any).discoveredAt
                      : finding.created_at
                        ? new Date(finding.created_at).toLocaleTimeString()
                        : "Just now"}
                  </span>
                </div>
              </div>

              <div className="flex flex-col items-end shrink-0">
                <span
                  className={cn(
                    "text-sm font-bold tabular-nums",
                    getCvssColor((finding as any).cvssScore ?? (finding as any).cvss_score ?? 0),
                  )}
                >
                  {((finding as any).cvssScore ?? (finding as any).cvss_score ?? 0).toFixed(1)}
                </span>
                <span className="text-[10px] uppercase tracking-wide text-muted-foreground">
                  CVSS
                </span>
              </div>
            </motion.div>
          ))}
        </div>
      )}
    </div>
  )
}
