import { useEffect, useState } from "react"
import { motion } from "framer-motion"
import { type DashboardStat } from "../data/dashboard-data"
import { StatCard } from "../components/stat-card"
import { SecurityScoreWidget } from "../components/security-score"
import { RiskMeterWidget } from "../components/risk-meter"
import { RecentScanCard } from "../components/recent-scan-card"
import { VulnerabilityTrendChart } from "../components/vulnerability-trend-chart"
import { SeverityDistributionChart } from "../components/severity-distribution-chart"
import { ScanActivityChart } from "../components/scan-activity-chart"
import { ThreatTrendChart } from "../components/threat-trend-chart"
import { RecentActivity } from "../components/recent-activity"
import { RecentFindings } from "../components/recent-findings"
import { QuickActionsBar } from "../components/quick-actions-bar"
import { AIInsightsCard } from "../components/ai-insights-card"
import { LayoutDashboard, Activity, BarChart3, RefreshCw } from "lucide-react"
import { dashboardService, type DashboardSummary } from "@/services/dashboard.service"
import { toast } from "sonner"

export function DashboardPage() {
  const [activeTab, setActiveTab] = useState<"overview" | "threats" | "analytics">("overview")
  const [summary, setSummary] = useState<DashboardSummary | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [isError, setIsError] = useState(false)

  async function loadSummary() {
    setIsLoading(true)
    setIsError(false)
    try {
      const data = await dashboardService.getSummary()
      setSummary(data)
    } catch {
      setIsError(true)
      toast.error("Failed to load real-time dashboard metrics")
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    loadSummary()
  }, [])

  // Map live summary statistics into StatCard items
  const statsList: DashboardStat[] = summary
    ? [
        {
          label: "Total Scans",
          value: summary.total_scans,
          change: summary.total_scans > 0 ? 100 : 0,
          changeLabel: `${summary.completed_scans} completed, ${summary.running_scans} running`,
          icon: "radar",
        },
        {
          label: "Open Findings",
          value: summary.total_findings,
          change: summary.total_findings > 0 ? 100 : 0,
          changeLabel: `${summary.critical_findings} critical, ${summary.high_findings} high`,
          icon: "shield-alert",
        },
        {
          label: "Critical Issues",
          value: summary.critical_findings,
          change: summary.critical_findings > 0 ? 100 : 0,
          changeLabel: `${summary.high_findings} high severity`,
          icon: "alert-triangle",
        },
        {
          label: "Security Score",
          value: `${Math.round(summary.overall_security_score)}/100`,
          change: 0,
          changeLabel: "Live database score",
          icon: "shield-check",
        },
      ]
    : [
        {
          label: "Total Scans",
          value: 0,
          change: 0,
          changeLabel: "0 completed, 0 running",
          icon: "radar",
        },
        {
          label: "Open Findings",
          value: 0,
          change: 0,
          changeLabel: "0 critical, 0 high",
          icon: "shield-alert",
        },
        {
          label: "Critical Issues",
          value: 0,
          change: 0,
          changeLabel: "0 high severity",
          icon: "alert-triangle",
        },
        {
          label: "Security Score",
          value: "100/100",
          change: 0,
          changeLabel: "No open findings",
          icon: "shield-check",
        },
      ]

  const severityDistributionData = summary
    ? [
        { severity: "critical" as const, count: summary.critical_findings, fill: "var(--chart-5)" },
        { severity: "high" as const, count: summary.high_findings, fill: "var(--chart-3)" },
        { severity: "medium" as const, count: summary.medium_findings, fill: "var(--chart-4)" },
        { severity: "low" as const, count: summary.low_findings, fill: "var(--chart-2)" },
      ]
    : undefined

  return (
    <div className="space-y-6 pb-8 select-none">
      {/* Header with Quick Actions */}
      <motion.div
        initial={{ opacity: 0, y: -8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
        className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between"
      >
        <div>
          <h1 className="text-2xl font-extrabold tracking-tight text-foreground flex items-center gap-2">
            Enterprise Security Operations Center
            {isLoading && <RefreshCw className="h-4 w-4 animate-spin text-muted-foreground" />}
          </h1>
          <p className="mt-1 text-xs sm:text-sm text-muted-foreground">
            Real-time security posture, neural threat correlation, and automated scan diagnostics
          </p>
        </div>

        <QuickActionsBar />
      </motion.div>

      {/* Error state banner */}
      {isError && (
        <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-4 flex items-center justify-between text-xs text-red-400">
          <span>Failed to sync live security dashboard metrics from server.</span>
          <button
            onClick={loadSummary}
            className="flex items-center gap-1 font-semibold underline hover:text-red-300"
          >
            <RefreshCw className="h-3.5 w-3.5" />
            Retry
          </button>
        </div>
      )}

      {/* Navigation View Switcher Tabs */}
      <div className="flex items-center gap-2 border-b border-border pb-1 overflow-x-auto">
        <button
          onClick={() => setActiveTab("overview")}
          className={`flex items-center gap-2 px-3.5 py-2 text-xs font-semibold rounded-lg transition-colors whitespace-nowrap ${
            activeTab === "overview"
              ? "bg-primary text-primary-foreground shadow-sm"
              : "text-muted-foreground hover:text-foreground hover:bg-muted/40"
          }`}
        >
          <LayoutDashboard className="h-3.5 w-3.5" />
          SOC Overview
        </button>
        <button
          onClick={() => setActiveTab("threats")}
          className={`flex items-center gap-2 px-3.5 py-2 text-xs font-semibold rounded-lg transition-colors whitespace-nowrap ${
            activeTab === "threats"
              ? "bg-primary text-primary-foreground shadow-sm"
              : "text-muted-foreground hover:text-foreground hover:bg-muted/40"
          }`}
        >
          <Activity className="h-3.5 w-3.5" />
          Threat & Risk Intelligence
        </button>
        <button
          onClick={() => setActiveTab("analytics")}
          className={`flex items-center gap-2 px-3.5 py-2 text-xs font-semibold rounded-lg transition-colors whitespace-nowrap ${
            activeTab === "analytics"
              ? "bg-primary text-primary-foreground shadow-sm"
              : "text-muted-foreground hover:text-foreground hover:bg-muted/40"
          }`}
        >
          <BarChart3 className="h-3.5 w-3.5" />
          Scan Analytics
        </button>
      </div>

      {/* Top Row: Key Statistics Cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {statsList.map((stat, index) => (
          <StatCard key={stat.label} stat={stat} index={index} />
        ))}
      </div>

      {/* Tab 1: SOC Overview View */}
      {activeTab === "overview" && (
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3 }}
          className="space-y-6"
        >
          {/* Row 1: Scores & Recent Scan */}
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
            <div>
              <SecurityScoreWidget score={summary?.overall_security_score} />
            </div>
            <div>
              <RiskMeterWidget
                score={summary?.overall_security_score}
                factors={summary?.risk_factors}
              />
            </div>
            <div>
              <RecentScanCard scan={summary?.recent_scans ? (summary.recent_scans[0] || null) : undefined} />
            </div>
          </div>

          {/* Row 2: Vulnerability Trend (Monthly Graph) + Severity Distribution */}
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
            <div className="lg:col-span-2">
              <VulnerabilityTrendChart data={summary?.vulnerability_trend} />
            </div>
            <div>
              <SeverityDistributionChart distribution={severityDistributionData} />
            </div>
          </div>

          {/* Row 3: AI Insights + Scan Activity (Weekly Graph) */}
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
            <div>
              <AIInsightsCard topFindings={summary ? summary.recent_findings : undefined} />
            </div>
            <div className="lg:col-span-2">
              <ScanActivityChart data={summary?.scan_activity} />
            </div>
          </div>

          {/* Row 4: Live Activity Timeline + Recent Findings */}
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
            <div>
              <RecentActivity activities={summary ? (summary.recent_activities as any) : undefined} />
            </div>
            <div className="lg:col-span-2">
              <RecentFindings findings={summary ? (summary.recent_findings as any) : undefined} />
            </div>
          </div>
        </motion.div>
      )}

      {/* Tab 2: Threat & Risk Intelligence View */}
      {activeTab === "threats" && (
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3 }}
          className="space-y-6"
        >
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
            <div className="lg:col-span-2">
              <ThreatTrendChart data={summary?.threat_trend} />
            </div>
            <div>
              <RiskMeterWidget
                score={summary?.overall_security_score}
                factors={summary?.risk_factors}
              />
            </div>
          </div>

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
            <div>
              <AIInsightsCard topFindings={summary ? summary.recent_findings : undefined} />
            </div>
            <div className="lg:col-span-2">
              <RecentFindings findings={summary ? (summary.recent_findings as any) : undefined} />
            </div>
          </div>
        </motion.div>
      )}

      {/* Tab 3: Scan Analytics View */}
      {activeTab === "analytics" && (
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3 }}
          className="space-y-6"
        >
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
            <div className="lg:col-span-2">
              <VulnerabilityTrendChart data={summary?.vulnerability_trend} />
            </div>
            <div>
              <SeverityDistributionChart distribution={severityDistributionData} />
            </div>
          </div>

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
            <div>
              <RecentScanCard scan={summary?.recent_scans ? (summary.recent_scans[0] || null) : undefined} />
            </div>
            <div className="lg:col-span-2">
              <ScanActivityChart data={summary?.scan_activity} />
            </div>
          </div>
        </motion.div>
      )}
    </div>
  )
}
