import { useEffect, useState, useMemo } from "react"
import { motion } from "framer-motion"
import { Plus, Search, SlidersHorizontal, FileBarChart, History } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import { EmptyState } from "@/components/feedback"
import { toast } from "sonner"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuCheckboxItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"

/* ── Reports Dashboard Components ── */
import { SecurityScoreCard } from "../components/security-score-card"
import { ExecutiveSummaryCard } from "../components/executive-summary-card"
import { ReportsChartsPanel } from "../components/reports-charts-panel"
import { ExportOptionsBar } from "../components/export-options-bar"
import { ReportHistoryTable } from "../components/report-history-table"
import { ReportPreviewSheet } from "../components/report-preview-sheet"
import { GenerateReportDialog } from "../components/generate-report-dialog"
import { ReportStatsBar } from "../components/report-stats-bar"
import { reportsService, type BackendReportRead } from "@/services/reports.service"
import type { Report, ReportType, ReportFormat, ReportStatus } from "@/types"

export function ReportsPage() {
  const [search, setSearch] = useState("")
  const [typeFilter, setTypeFilter] = useState<ReportType | "all">("all")
  const [formatFilter, setFormatFilter] = useState<ReportFormat | "all">("all")
  const [selectedReport, setSelectedReport] = useState<Report | null>(null)
  const [previewOpen, setPreviewOpen] = useState(false)
  const [generateOpen, setGenerateOpen] = useState(false)
  const [realReports, setRealReports] = useState<Report[]>([])

  const fetchBackendReports = () => {
    reportsService
      .getReports()
      .then((items) => {
        const normalised: Report[] = items.map((r: BackendReportRead) => {
          let counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
          try {
            if (r.findings_summary_json) {
              const parsed = JSON.parse(r.findings_summary_json)
              counts = { ...counts, ...parsed }
            }
          } catch {}

          const score = Math.round(r.overall_score ?? 100)
          const grade: "A" | "B" | "C" | "D" | "F" =
            score >= 90 ? "A" : score >= 80 ? "B" : score >= 70 ? "C" : score >= 60 ? "D" : "F"

          const totalFindings = counts.critical + counts.high + counts.medium + counts.low + counts.info

          return {
            id: r.id,
            projectId: r.project_id,
            projectName: "Security Assessment",
            title: r.title,
            type: (r.report_type?.toLowerCase() as ReportType) || "executive",
            status: (r.status?.toLowerCase() as ReportStatus) || "completed",
            availableFormats: ["pdf", "html", "json", "csv"] as ReportFormat[],
            fileSizeMb: 1.2,
            author: "AWASAP Automated Engine",
            targetUrls: [],
            createdAt: r.created_at,
            updatedAt: r.updated_at,
            executiveSummary: {
              overallRiskScore: score,
              riskGrade: grade,
              summaryText: `Automated security assessment generated ${totalFindings} findings with an overall posture score of ${score}/100.`,
              keyTakeaways: [
                `${counts.critical} critical and ${counts.high} high severity vulnerabilities identified.`,
                `Platform postured at Risk Grade ${grade} based on automated threat heuristics.`,
                `${counts.medium} medium and ${counts.low} low issues require scheduled remediation.`,
              ],
              criticalFindingsCount: counts.critical,
              highFindingsCount: counts.high,
              mediumFindingsCount: counts.medium,
              lowFindingsCount: counts.low,
              recommendations: [
                counts.critical > 0
                  ? "Remediate all Critical severity vulnerabilities immediately."
                  : "Maintain continuous vulnerability monitoring.",
                counts.high > 0
                  ? "Apply patches for High severity issues within 48 hours."
                  : "Ensure secure default configurations across endpoints.",
                "Verify API endpoints against OWASP Top 10 standards.",
              ],
            },
            chartData: {
              severityDistribution: [
                { severity: "Critical", count: counts.critical, fill: "#ef4444" },
                { severity: "High", count: counts.high, fill: "#f97316" },
                { severity: "Medium", count: counts.medium, fill: "#f59e0b" },
                { severity: "Low", count: counts.low, fill: "#3b82f6" },
              ],
              categoryDistribution: [
                { category: "Injection", count: counts.critical },
                { category: "Auth Failures", count: counts.high },
                { category: "Misconfiguration", count: counts.medium },
                { category: "Other", count: counts.low },
              ],
              trendData: [
                { month: "Current", critical: counts.critical, high: counts.high, medium: counts.medium, low: counts.low },
              ],
            },
          }
        })
        setRealReports(normalised)
      })
      .catch(() => {})
  }

  useEffect(() => {
    fetchBackendReports()
    const handleCreated = () => fetchBackendReports()
    window.addEventListener("awsap:report_created", handleCreated)
    return () => window.removeEventListener("awsap:report_created", handleCreated)
  }, [])

  const filteredReports = useMemo(() => {
    return realReports.filter((r) => {
      if (search) {
        const q = search.toLowerCase()
        const match =
          r.title.toLowerCase().includes(q) ||
          r.projectName.toLowerCase().includes(q) ||
          r.author.toLowerCase().includes(q)
        if (!match) return false
      }

      if (typeFilter !== "all" && r.type !== typeFilter) return false
      if (formatFilter !== "all" && !r.availableFormats.includes(formatFilter)) return false

      return true
    })
  }, [search, typeFilter, formatFilter, realReports])

  function handlePreview(report: Report) {
    setSelectedReport(report)
    setPreviewOpen(true)
  }

  function handleDeleteReport(id: string) {
    setRealReports((prev) => prev.filter((r) => r.id !== id))
    if (selectedReport?.id === id) {
      setSelectedReport(null)
      setPreviewOpen(false)
    }
  }

  function handlePreviewJson() {
    if (realReports[0]) {
      setSelectedReport(realReports[0])
      setPreviewOpen(true)
      toast.info("Opened Report Preview for JSON inspection")
    } else {
      toast.info("No generated reports available for JSON preview")
    }
  }

  const activeFiltersCount = [typeFilter, formatFilter].filter((f) => f !== "all").length
  const activeReport = realReports[0]
  const execSummary = activeReport?.executiveSummary

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <motion.div
        initial={{ opacity: 0, y: -8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
        className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between"
      >
        <div>
          <h1 className="text-2xl font-extrabold tracking-tight text-foreground">
            Security Reports & Executive Dashboard
          </h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Executive risk summaries, security posture score, compliance analytics, multi-format export, and report history
          </p>
        </div>
        <Button onClick={() => setGenerateOpen(true)} className="gap-2 self-start font-bold">
          <Plus className="h-4 w-4" />
          Generate New Report
        </Button>
      </motion.div>

      {/* Reports Metrics Summary Bar */}
      <ReportStatsBar reports={realReports} />

      {/* Top Executive Row: Security Score + Executive Summary */}
      <motion.div
        initial={{ opacity: 0, y: 4 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3, delay: 0.05 }}
        className="grid grid-cols-1 gap-5 lg:grid-cols-12"
      >
        <div className="lg:col-span-4">
          <SecurityScoreCard
            score={execSummary?.overallRiskScore ?? 100}
            grade={execSummary?.riskGrade ?? "A"}
            trend={
              execSummary
                ? execSummary.criticalFindingsCount > 0
                  ? "Action Required"
                  : "Stable Posture"
                : "No Reports"
            }
          />
        </div>
        <div className="lg:col-span-8">
          <ExecutiveSummaryCard
            summaryText={
              execSummary?.summaryText ||
              "No security assessment reports generated yet. Click 'Generate New Report' to compile automated vulnerability intelligence and calculate security posture score."
            }
            keyTakeaways={
              execSummary?.keyTakeaways || [
                "Awaiting initial security assessment.",
                "Select an authorized project and target to run vulnerability scans.",
                "Generate a report to track executive compliance and posture rating.",
              ]
            }
            recommendations={
              execSummary?.recommendations || [
                "Create an assessment project.",
                "Add your target URLs and API endpoints.",
                "Run security scans to discover vulnerabilities.",
              ]
            }
          />
        </div>
      </motion.div>

      {/* Interactive Charts Panel */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.3, delay: 0.1 }}
      >
        <ReportsChartsPanel reports={realReports} />
      </motion.div>

      {/* One-Click Multi-Format Export Center */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.3, delay: 0.15 }}
      >
        <ExportOptionsBar
          onPreviewJson={handlePreviewJson}
          latestReport={realReports[0] || null}
        />
      </motion.div>

      {/* Previous Reports History Section */}
      <div className="space-y-4 pt-2">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-2">
            <History className="h-4 w-4 text-primary" />
            <h2 className="text-base font-bold text-foreground">Previous Generated Reports List</h2>
            <Badge variant="secondary" className="font-mono text-xs">
              {filteredReports.length} Reports
            </Badge>
          </div>

          {/* Search & Filter Toolbar */}
          <div className="flex items-center gap-3">
            <div className="relative flex-1 max-w-xs">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                placeholder="Search report titles, projects..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="pl-9 text-xs"
              />
            </div>

            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" size="sm" className="gap-2 text-xs">
                  <SlidersHorizontal className="h-3.5 w-3.5" />
                  Filters
                  {activeFiltersCount > 0 && (
                    <Badge variant="default" className="h-5 min-w-5 rounded-full px-1.5 text-[10px] font-bold">
                      {activeFiltersCount}
                    </Badge>
                  )}
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-48">
                <DropdownMenuLabel className="text-xs">Report Type</DropdownMenuLabel>
                {(["all", "executive", "technical", "compliance", "custom"] as const).map((t) => (
                  <DropdownMenuCheckboxItem
                    key={t}
                    checked={typeFilter === t}
                    onCheckedChange={() => setTypeFilter(t)}
                  >
                    {t === "all" ? "All Types" : t.charAt(0).toUpperCase() + t.slice(1)}
                  </DropdownMenuCheckboxItem>
                ))}

                <DropdownMenuSeparator />

                <DropdownMenuLabel className="text-xs">Export Format</DropdownMenuLabel>
                {(["all", "pdf", "html", "json", "csv"] as const).map((fmt) => (
                  <DropdownMenuCheckboxItem
                    key={fmt}
                    checked={formatFilter === fmt}
                    onCheckedChange={() => setFormatFilter(fmt)}
                  >
                    {fmt === "all" ? "All Formats" : fmt.toUpperCase()}
                  </DropdownMenuCheckboxItem>
                ))}
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </div>

        {/* History Table */}
        {filteredReports.length > 0 ? (
          <ReportHistoryTable
            reports={filteredReports}
            onPreview={handlePreview}
            onDeleteReport={handleDeleteReport}
          />
        ) : (
          <EmptyState
            icon={FileBarChart}
            title="No reports found"
            description="Try adjusting your search terms or filter options."
          />
        )}
      </div>

      {/* Report Preview Slide-out Sheet */}
      <ReportPreviewSheet
        report={selectedReport}
        open={previewOpen}
        onClose={() => setPreviewOpen(false)}
      />

      {/* Generate Report Dialog Modal */}
      <GenerateReportDialog
        open={generateOpen}
        onClose={() => setGenerateOpen(false)}
      />
    </div>
  )
}
