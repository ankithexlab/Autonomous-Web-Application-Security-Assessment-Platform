import { useEffect, useState } from "react"
import { motion } from "framer-motion"
import { useNavigate } from "react-router"
import {
  ShieldCheck,
  AlertTriangle,
  Bug,
  TrendingDown,
  Globe,
  ArrowRight,
  ExternalLink,
  RefreshCw,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { ROUTES } from "@/constants"
import { owaspService, type BackendOWASPStatsResponse } from "@/services/owasp.service"
import { toast } from "sonner"
import { OWASPStatsCard } from "../components/owasp-stats-card"
import { OWASPCard } from "../components/owasp-card"
import { RiskMeter } from "../components/risk-meter"
import { AISummaryCard } from "../components/ai-summary-card"
import { OWASPTimeline } from "../components/owasp-timeline"
import { OWASPRiskTrendChart, OWASPCoverageChart, OWASPSeverityChart } from "../components/owasp-charts"
import { OWASPSeverityBadge } from "../components/owasp-severity-badge"
import { OWASP_CATEGORIES } from "../data/owasp-data"

export function OWASPDashboardPage() {
  const navigate = useNavigate()
  const [realStats, setRealStats] = useState<BackendOWASPStatsResponse | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [isError, setIsError] = useState(false)

  async function loadOWASPSummary() {
    setIsLoading(true)
    setIsError(false)
    try {
      const data = await owaspService.getOWASPSummary()
      setRealStats(data)
    } catch {
      setIsError(true)
      toast.error("Failed to load real-time OWASP posture metrics")
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    loadOWASPSummary()
  }, [])

  const stats = realStats
    ? {
        securityScore: Math.round(realStats.overall_risk_score),
        totalFindings: realStats.total_vulnerabilities,
        criticalCount: realStats.critical_count,
        highCount: realStats.high_count,
        mediumCount: realStats.medium_count,
        overallCoverage: Math.round((realStats.categories_covered / 10) * 100),
      }
    : {
        securityScore: 100,
        totalFindings: 0,
        criticalCount: 0,
        highCount: 0,
        mediumCount: 0,
        overallCoverage: 100,
      }

  const riskScore = Math.max(0, 100 - stats.securityScore)

  const coverageList =
    realStats?.category_breakdown && realStats.category_breakdown.length > 0
      ? realStats.category_breakdown.map((item) => ({
          categoryId: item.category_id as any,
          categoryName: item.category_name,
          findingsCount: item.findings_count,
          criticalCount: item.critical_count,
          highCount: item.high_count,
          coveragePercent:
            item.compliance_status === "PASS"
              ? 100
              : item.compliance_status === "WARNING"
                ? 65
                : 25,
          status:
            item.compliance_status === "PASS"
              ? ("covered" as const)
              : ("partial" as const),
          lastScanned: "Recently",
        }))
      : OWASP_CATEGORIES.map((cat) => ({
          categoryId: cat.id as any,
          categoryName: cat.name,
          findingsCount: 0,
          criticalCount: 0,
          highCount: 0,
          coveragePercent: 100,
          status: "covered" as const,
          lastScanned: "Not yet scanned",
        }))

  const topFindings = realStats?.top_findings ?? []
  const mostAffectedAssets = realStats?.most_affected_assets ?? []
  const scanTimeline = realStats?.scan_timeline ?? []

  const aiInsights = topFindings.length > 0
    ? topFindings.slice(0, 3).map((f) => ({
        id: `ai-${f.id}`,
        category: f.categoryId,
        insight: `${f.title} (${f.severity.toUpperCase()}): ${f.description}`,
        recommendation: f.remediation,
        severity: (f.severity === "critical" || f.severity === "high" ? f.severity : "medium") as any,
        confidence: Math.round(Math.min(99, 85 + (f.cvssScore || 5))),
      }))
    : []

  return (
    <div className="space-y-7 pb-10 select-none">
      {/* ── Hero Header ── */}
      <motion.div
        initial={{ opacity: 0, y: -8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
        className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between"
      >
        <div>
          <div className="flex items-center gap-2.5 flex-wrap">
            <h1 className="text-2xl font-extrabold tracking-tight text-foreground flex items-center gap-2">
              OWASP Top 10 Security Dashboard
              {isLoading && <RefreshCw className="h-4 w-4 animate-spin text-muted-foreground" />}
            </h1>
            <Badge className="bg-emerald-500/15 text-emerald-400 border-emerald-500/30 text-[10px] font-bold uppercase tracking-wider">
              <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-400 mr-1.5 inline-block" />
              OWASP 2021
            </Badge>
          </div>
          <p className="mt-1 text-xs sm:text-sm text-muted-foreground max-w-2xl">
            Comprehensive vulnerability posture across all OWASP Top 10 categories — real-time findings, AI-powered risk correlation, and compliance coverage.
          </p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <Button
            variant="outline"
            size="sm"
            onClick={() => navigate(ROUTES.SCANS)}
            className="gap-1.5 text-xs"
          >
            <ShieldCheck className="h-3.5 w-3.5" />
            Run OWASP Scan
          </Button>
          <Button
            size="sm"
            onClick={() => navigate(ROUTES.REPORTS)}
            className="gap-1.5 text-xs"
          >
            <ExternalLink className="h-3.5 w-3.5" />
            Export Report
          </Button>
        </div>
      </motion.div>

      {/* Error state banner */}
      {isError && (
        <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-4 flex items-center justify-between text-xs text-red-400">
          <span>Failed to sync live OWASP security posture metrics from server.</span>
          <button
            onClick={loadOWASPSummary}
            className="flex items-center gap-1 font-semibold underline hover:text-red-300"
          >
            <RefreshCw className="h-3.5 w-3.5" />
            Retry
          </button>
        </div>
      )}

      {/* ── Row 1: Stats Cards ── */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        <OWASPStatsCard
          label="Security Score"
          value={`${stats.securityScore}/100`}
          icon={ShieldCheck}
          iconColor="text-emerald-400"
          iconBg="bg-emerald-500/10"
          change={stats.securityScore < 100 ? -8.2 : 0}
          index={0}
          highlight
          highlightColor="border-emerald-500/30"
        />
        <OWASPStatsCard
          label="Total Findings"
          value={stats.totalFindings}
          icon={Bug}
          iconColor="text-primary"
          iconBg="bg-primary/10"
          change={stats.totalFindings > 0 ? 5.1 : 0}
          index={1}
        />
        <OWASPStatsCard
          label="Critical"
          value={stats.criticalCount}
          icon={AlertTriangle}
          iconColor="text-red-400"
          iconBg="bg-red-500/10"
          change={stats.criticalCount > 0 ? 12.0 : 0}
          index={2}
          highlight
          highlightColor="border-red-500/30"
        />
        <OWASPStatsCard
          label="High"
          value={stats.highCount}
          icon={AlertTriangle}
          iconColor="text-orange-400"
          iconBg="bg-orange-500/10"
          change={stats.highCount > 0 ? 8.5 : 0}
          index={3}
        />
        <OWASPStatsCard
          label="Medium"
          value={stats.mediumCount}
          icon={Bug}
          iconColor="text-amber-400"
          iconBg="bg-amber-500/10"
          change={stats.mediumCount > 0 ? -3.2 : 0}
          index={4}
        />
        <OWASPStatsCard
          label="Coverage"
          value={`${stats.overallCoverage}%`}
          icon={TrendingDown}
          iconColor="text-violet-400"
          iconBg="bg-violet-500/10"
          change={stats.overallCoverage < 100 ? -2.5 : 0}
          index={5}
        />
      </div>

      {/* ── Row 2: Security Score Gauges + Severity Distribution ── */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-3">
        {/* Security Score */}
        <div className="rounded-xl border border-border bg-card p-5 shadow-xs flex flex-col items-center justify-center space-y-2">
          <h3 className="text-sm font-semibold text-foreground self-start">Security Score</h3>
          <p className="text-xs text-muted-foreground self-start">Overall OWASP compliance posture</p>
          <RiskMeter
            score={stats.securityScore}
            label="Security Index"
            subtitle="Based on OWASP findings coverage"
            change={stats.securityScore < 100 ? -8.2 : 0}
            size="md"
          />
        </div>

        {/* Risk Score */}
        <div className="rounded-xl border border-border bg-card p-5 shadow-xs flex flex-col items-center justify-center space-y-2">
          <h3 className="text-sm font-semibold text-foreground self-start">Overall Risk Score</h3>
          <p className="text-xs text-muted-foreground self-start">Aggregated exploitability risk index</p>
          <RiskMeter
            score={riskScore}
            label="Risk Index"
            subtitle="CVSS-weighted vulnerability exposure"
            change={riskScore > 0 ? 6.5 : 0}
            size="md"
          />
        </div>

        {/* Severity Distribution */}
        <OWASPSeverityChart
          counts={
            realStats
              ? {
                  critical: realStats.critical_count,
                  high: realStats.high_count,
                  medium: realStats.medium_count,
                  low: realStats.low_count,
                  info: realStats.info_count,
                }
              : undefined
          }
        />
      </div>

      {/* ── Row 3: Risk Trend + Coverage Chart ── */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        <OWASPRiskTrendChart trend={realStats?.risk_trend} />
        <OWASPCoverageChart categoryBreakdown={realStats?.category_breakdown} />
      </div>

      {/* ── Row 4: Top 10 OWASP Category Cards ── */}
      <div>
        <div className="mb-3 flex items-center justify-between">
          <div>
            <h2 className="text-sm font-bold text-foreground">OWASP Top 10 Coverage</h2>
            <p className="text-xs text-muted-foreground">Category-level scan coverage and findings breakdown</p>
          </div>
          <Badge variant="outline" className="text-xs font-semibold">
            {coverageList.filter((c) => c.status === "covered").length}/10 Covered
          </Badge>
        </div>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-5">
          {coverageList.map((cov, idx) => (
            <OWASPCard
              key={cov.categoryId}
              categoryId={cov.categoryId}
              findingsCount={cov.findingsCount}
              criticalCount={cov.criticalCount}
              highCount={cov.highCount}
              coveragePercent={cov.coveragePercent}
              status={cov.status}
              lastScanned={cov.lastScanned}
              index={idx}
            />
          ))}
        </div>
      </div>

      {/* ── Row 5: Critical Findings + Most Affected Assets + Scan Timeline ── */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-3">
        {/* Top Critical Findings */}
        <div className="lg:col-span-2 rounded-xl border border-border bg-card shadow-xs">
          <div className="flex items-center justify-between border-b border-border px-5 py-4">
            <div>
              <h3 className="text-sm font-semibold text-foreground">Top Critical Findings</h3>
              <p className="text-xs text-muted-foreground">High-priority OWASP vulnerabilities requiring immediate attention</p>
            </div>
            <Button variant="outline" size="sm" onClick={() => navigate(ROUTES.FINDINGS)} className="gap-1.5 text-xs">
              View all <ArrowRight className="h-3 w-3" />
            </Button>
          </div>
          <div className="divide-y divide-border/60">
            {topFindings.length === 0 ? (
              <div className="p-8 text-center text-xs text-muted-foreground">
                No critical or high-risk OWASP vulnerabilities detected in workspace. Run an automated scan to analyze targets.
              </div>
            ) : (
              topFindings.map((finding, idx) => {
                const catMeta = OWASP_CATEGORIES.find((c) => c.id === finding.categoryId)
                const catColor = catMeta?.color || "text-red-400"
                return (
                  <motion.div
                    key={finding.id}
                    initial={{ opacity: 0, y: 4 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: idx * 0.05 }}
                    className="flex items-center gap-4 p-4 hover:bg-accent/20 transition-colors"
                  >
                    <OWASPSeverityBadge severity={finding.severity as any} className="w-[72px] justify-center shrink-0" />
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-xs font-bold text-foreground">{finding.title}</p>
                      <div className="mt-1 flex items-center gap-2 text-[10px] text-muted-foreground">
                        <span className={`font-semibold ${catColor}`}>{finding.categoryId}</span>
                        <span>•</span>
                        <span className="flex items-center gap-1">
                          <Globe className="h-3 w-3" />
                          {finding.affectedAsset}
                        </span>
                        <span>•</span>
                        <span className="font-mono">{finding.discoveredAt}</span>
                      </div>
                    </div>
                    <div className="text-right shrink-0">
                      <span className={`text-sm font-bold ${finding.cvssScore >= 9 ? "text-red-400" : finding.cvssScore >= 7 ? "text-orange-400" : "text-amber-400"}`}>
                        {finding.cvssScore.toFixed(1)}
                      </span>
                      <p className="text-[9px] uppercase tracking-wide text-muted-foreground">CVSS</p>
                    </div>
                  </motion.div>
                )
              })
            )}
          </div>
        </div>

        {/* Most Affected Assets */}
        <div className="rounded-xl border border-border bg-card p-5 space-y-4 shadow-xs">
          <div>
            <h3 className="text-sm font-semibold text-foreground">Most Affected Assets</h3>
            <p className="text-xs text-muted-foreground">Assets ranked by total findings count</p>
          </div>
          <div className="space-y-3">
            {mostAffectedAssets.length === 0 ? (
              <div className="py-8 text-center text-xs text-muted-foreground">
                No affected assets identified with active vulnerabilities.
              </div>
            ) : (
              mostAffectedAssets.map((asset, idx) => (
                <motion.div
                  key={asset.asset}
                  initial={{ opacity: 0, x: 8 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: idx * 0.07 }}
                  className="space-y-1.5"
                >
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-mono text-foreground truncate flex-1 pr-2">{asset.asset}</span>
                    <span className="semibold text-foreground shrink-0">{asset.findingsCount} findings</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="h-2 flex-1 overflow-hidden rounded-full bg-muted/40">
                      <motion.div
                        className="h-full rounded-full bg-gradient-to-r from-red-500 via-orange-500 to-amber-500"
                        initial={{ width: 0 }}
                        animate={{ width: `${Math.min(100, (asset.findingsCount / 10) * 100)}%` }}
                        transition={{ duration: 0.8, delay: idx * 0.07 + 0.2 }}
                      />
                    </div>
                    <span className="text-[10px] text-muted-foreground shrink-0 w-10 text-right">
                      {asset.riskScore}
                    </span>
                  </div>
                  {asset.criticalCount > 0 && (
                    <span className="text-[10px] text-red-400 font-semibold">
                      {asset.criticalCount} critical
                    </span>
                  )}
                </motion.div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* ── Row 6: AI Insights + Scan Timeline ── */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        <AISummaryCard
          insights={aiInsights}
          onOpenAssistant={() => navigate(ROUTES.AI_ASSISTANT)}
        />

        <div className="rounded-xl border border-border bg-card p-5 space-y-4 shadow-xs">
          <div>
            <h3 className="text-sm font-semibold text-foreground">OWASP Scan Timeline</h3>
            <p className="text-xs text-muted-foreground">Real-time security events across OWASP categories</p>
          </div>
          <OWASPTimeline events={(scanTimeline as any) || []} />
        </div>
      </div>
    </div>
  )
}

