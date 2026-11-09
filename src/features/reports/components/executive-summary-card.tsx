import { Sparkles, AlertTriangle, Award, CheckCircle2 } from "lucide-react"

interface ExecutiveSummaryCardProps {
  summaryText?: string
  keyTakeaways?: string[]
  recommendations?: string[]
}

export function ExecutiveSummaryCard({
  summaryText = "The Acme SaaS Infrastructure demonstrates a solid security baseline, though 3 critical injection and authorization vulnerabilities require immediate remediation prior to upcoming SOC2 compliance audits.",
  keyTakeaways = [
    "Identified 1 Critical SQL Injection vulnerability in authentication endpoints.",
    "Discovered 1 BOLA vulnerability in order management microservices.",
    "OWASP Top 10 compliance score improved by 14% compared to Q1 2026.",
    "All TLS/SSL protocols are updated to TLS 1.3 standard across edge load balancers.",
  ],
  recommendations = [
    "Enforce strict parameterized database query wrappers across Node.js backend services.",
    "Implement context-aware middleware validation for object-level user ownership checks.",
    "Deploy Content-Security-Policy (CSP) headers across frontend web assets.",
  ],
}: ExecutiveSummaryCardProps) {
  return (
    <div className="rounded-2xl border border-border/80 bg-card p-5 shadow-sm space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Sparkles className="h-4.5 w-4.5 text-primary" />
          <h3 className="text-sm font-bold text-foreground">Executive Summary & Audit Insights</h3>
        </div>

        <div className="flex items-center gap-1.5 rounded-full bg-blue-500/10 px-3 py-1 text-xs font-bold text-blue-400 border border-blue-500/20">
          <Award className="h-3.5 w-3.5" />
          <span>SOC2 & PCI-DSS Audit Ready</span>
        </div>
      </div>

      {/* Summary Paragraph */}
      <p className="text-xs leading-relaxed text-muted-foreground border-l-2 border-primary/40 pl-3 py-0.5">
        {summaryText}
      </p>

      {/* Grid: Key Takeaways & Priority Recommendations */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-1">
        {/* Key Takeaways */}
        <div className="space-y-2 rounded-xl bg-muted/20 p-3.5 border border-border/40">
          <span className="text-xs font-bold text-foreground flex items-center gap-1.5">
            <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
            Key Executive Takeaways
          </span>
          <div className="space-y-1.5">
            {keyTakeaways.map((takeaway, idx) => (
              <div key={idx} className="flex items-start gap-2 text-xs text-muted-foreground">
                <span className="text-primary font-bold">›</span>
                <span className="leading-snug">{takeaway}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Priority Recommendations */}
        <div className="space-y-2 rounded-xl bg-muted/20 p-3.5 border border-border/40">
          <span className="text-xs font-bold text-foreground flex items-center gap-1.5">
            <AlertTriangle className="h-3.5 w-3.5 text-amber-400" />
            Priority Action Items
          </span>
          <div className="space-y-1.5">
            {recommendations.map((rec, idx) => (
              <div key={idx} className="flex items-center gap-2 rounded-lg bg-card p-2 text-xs text-foreground border border-border/40">
                <span className="flex h-4 w-4 shrink-0 items-center justify-center rounded-full bg-amber-500/15 text-[10px] font-bold text-amber-400">
                  {idx + 1}
                </span>
                <span className="truncate">{rec}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
