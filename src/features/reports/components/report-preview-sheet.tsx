import { useState, useEffect } from "react"
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
} from "@/components/ui/sheet"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { ScrollArea } from "@/components/ui/scroll-area"
import { toast } from "sonner"
import {
  FileText,
  Download,
  Check,
  Globe,
  User,
  Calendar,
  AlertTriangle,
  Award,
  Sparkles,
  PieChart as PieIcon,
  TrendingUp,
  Eye,
  Printer,
  Loader2,
} from "lucide-react"
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Tooltip,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
} from "recharts"
import { cn, formatRelativeTime } from "@/utils"
import { reportsService } from "@/services/reports.service"
import type { Report, ReportFormat } from "@/types"

interface ReportPreviewSheetProps {
  report: Report | null
  open: boolean
  onClose: () => void
}

const gradeColors: Record<string, string> = {
  A: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
  B: "bg-blue-500/15 text-blue-400 border-blue-500/30",
  C: "bg-amber-500/15 text-amber-400 border-amber-500/30",
  D: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  F: "bg-red-500/15 text-red-400 border-red-500/30",
}

export function ReportPreviewSheet({
  report,
  open,
  onClose,
}: ReportPreviewSheetProps) {
  const [downloadingFormat, setDownloadingFormat] = useState<ReportFormat | null>(null)
  const [downloadSuccess, setDownloadSuccess] = useState<ReportFormat | null>(null)
  const [activeTab, setActiveTab] = useState<"overview" | "document">("overview")
  const [docContent, setDocContent] = useState<string | null>(null)
  const [isLoadingDoc, setIsLoadingDoc] = useState(false)

  // Reset document content when report changes or modal reopens
  useEffect(() => {
    setDocContent(null)
    setActiveTab("overview")
  }, [report?.id, open])

  // Fetch real document content when switching to document/PDF preview
  useEffect(() => {
    if (open && report?.id && activeTab === "document" && docContent === null) {
      setIsLoadingDoc(true)
      reportsService
        .getReportContent(report.id)
        .then((res) => {
          setDocContent(res.text)
        })
        .catch(() => {
          toast.error("Failed to load visual report content from server")
          setDocContent(null)
        })
        .finally(() => {
          setIsLoadingDoc(false)
        })
    }
  }, [open, report?.id, activeTab, docContent])

  if (!report) return null

  async function handleDownload(fmt: ReportFormat) {
    if (!report?.id) return
    setDownloadingFormat(fmt)
    try {
      const filename = `${report.title.toLowerCase().replace(/[^a-z0-9]+/g, "_")}.${fmt}`
      await reportsService.downloadReport(report.id, filename, fmt)
      setDownloadSuccess(fmt)
      toast.success(`${fmt.toUpperCase()} report downloaded successfully`)
      setTimeout(() => setDownloadSuccess(null), 2500)
    } catch (err: any) {
      toast.error(`Download failed: ${err.message || "Failed to download report"}`)
    } finally {
      setDownloadingFormat(null)
    }
  }

  function handlePrintPreview() {
    const iframe = document.getElementById("report-preview-iframe") as HTMLIFrameElement | null
    if (iframe?.contentWindow) {
      iframe.contentWindow.focus()
      iframe.contentWindow.print()
    } else {
      window.print()
    }
  }

  const exec = report.executiveSummary
  const charts = report.chartData

  return (
    <Sheet open={open} onOpenChange={(o) => !o && onClose()}>
      <SheetContent className="w-full sm:max-w-3xl p-0 border-l border-border bg-background">
        <ScrollArea className="h-full">
          <div className="p-6 space-y-6">
            {/* Header */}
            <SheetHeader className="space-y-3">
              <div className="flex items-center gap-3">
                <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl bg-primary/10">
                  <FileText className="h-5 w-5 text-primary" />
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <Badge variant="outline" className="uppercase text-[10px]">
                      {report.type}
                    </Badge>
                    {report.fileSizeMb && (
                      <span className="text-xs text-muted-foreground">
                        {report.fileSizeMb} MB
                      </span>
                    )}
                  </div>
                  <SheetTitle className="truncate text-lg font-bold text-foreground mt-0.5">
                    {report.title}
                  </SheetTitle>
                  <SheetDescription className="text-xs text-muted-foreground flex items-center gap-2 mt-0.5">
                    <User className="h-3 w-3" />
                    <span>{report.author}</span>
                    <span>·</span>
                    <Calendar className="h-3 w-3" />
                    <span>{formatRelativeTime(new Date(report.createdAt))}</span>
                  </SheetDescription>
                </div>
              </div>
            </SheetHeader>

            {/* View Mode Switcher + Export Actions */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 rounded-xl border border-border bg-card p-3">
              <div className="flex items-center gap-1.5 rounded-lg bg-muted/40 p-1">
                <button
                  type="button"
                  onClick={() => setActiveTab("overview")}
                  className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-semibold transition-all ${
                    activeTab === "overview"
                      ? "bg-background text-foreground shadow-xs"
                      : "text-muted-foreground hover:text-foreground"
                  }`}
                >
                  <Sparkles className="h-3.5 w-3.5" />
                  Overview
                </button>
                <button
                  type="button"
                  onClick={() => setActiveTab("document")}
                  className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-semibold transition-all ${
                    activeTab === "document"
                      ? "bg-background text-foreground shadow-xs"
                      : "text-muted-foreground hover:text-foreground"
                  }`}
                >
                  <Eye className="h-3.5 w-3.5" />
                  PDF / Document Preview
                </button>
              </div>

              {/* Real Backend Download Buttons */}
              <div className="flex items-center gap-2">
                {(["pdf", "html", "json", "csv"] as const).map((fmt) => {
                  const isAvailable = report.availableFormats.includes(fmt)
                  if (!isAvailable) return null

                  const isDownloading = downloadingFormat === fmt
                  const isSuccess = downloadSuccess === fmt

                  return (
                    <Button
                      key={fmt}
                      size="sm"
                      variant={fmt === "pdf" ? "default" : "outline"}
                      disabled={isDownloading}
                      onClick={() => handleDownload(fmt)}
                      className="gap-1.5 uppercase font-semibold text-xs"
                    >
                      {isSuccess ? (
                        <Check className="h-3.5 w-3.5 text-emerald-400" />
                      ) : (
                        <Download className={cn("h-3.5 w-3.5", isDownloading && "animate-bounce")} />
                      )}
                      {isDownloading ? "Downloading..." : fmt}
                    </Button>
                  )
                })}
              </div>
            </div>

            {/* Document / PDF Visual Preview Tab */}
            {activeTab === "document" && (
              <div className="rounded-xl border border-border bg-card overflow-hidden space-y-3 p-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2 text-xs font-semibold text-foreground">
                    <FileText className="h-4 w-4 text-primary" />
                    <span>Live Generated Document</span>
                  </div>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={handlePrintPreview}
                    className="gap-1.5 text-xs font-semibold"
                  >
                    <Printer className="h-3.5 w-3.5" />
                    Print / Export PDF
                  </Button>
                </div>

                {isLoadingDoc ? (
                  <div className="h-96 flex flex-col items-center justify-center gap-2 text-muted-foreground text-xs">
                    <Loader2 className="h-6 w-6 animate-spin text-primary" />
                    <span>Loading report document from server...</span>
                  </div>
                ) : docContent ? (
                  <div className="rounded-lg border border-border/80 overflow-hidden bg-slate-950">
                    <iframe
                      id="report-preview-iframe"
                      title="Report Document Preview"
                      srcDoc={docContent}
                      sandbox="allow-same-origin allow-modals"
                      className="w-full h-[520px] border-0"
                    />
                  </div>
                ) : (
                  <div className="h-64 flex flex-col items-center justify-center gap-2 text-muted-foreground text-xs p-6 text-center">
                    <AlertTriangle className="h-6 w-6 text-amber-400" />
                    <span>Unable to load visual preview. You can still download the report file above.</span>
                  </div>
                )}
              </div>
            )}

            {/* Overview Tab Content */}
            {activeTab === "overview" && (
              <>
            {exec && (
              <div className="space-y-4 rounded-xl border border-border bg-card p-5">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Sparkles className="h-4 w-4 text-primary" />
                    <h3 className="text-sm font-semibold text-foreground">
                      Executive Summary & Risk Rating
                    </h3>
                  </div>

                  <div
                    className={cn(
                      "flex items-center gap-1.5 rounded-full border px-3 py-1 font-bold text-xs",
                      gradeColors[exec.riskGrade] || gradeColors.B,
                    )}
                  >
                    <Award className="h-3.5 w-3.5" />
                    <span>Grade {exec.riskGrade}</span>
                    <span className="opacity-60">({exec.overallRiskScore}/100)</span>
                  </div>
                </div>

                <p className="text-xs leading-relaxed text-muted-foreground">
                  {exec.summaryText}
                </p>

                {/* Key Takeaways */}
                {exec.keyTakeaways.length > 0 && (
                  <div className="space-y-2 pt-2">
                    <span className="text-xs font-semibold text-foreground">
                      Key Takeaways
                    </span>
                    <div className="space-y-1.5">
                      {exec.keyTakeaways.map((takeaway, idx) => (
                        <div
                          key={idx}
                          className="flex items-start gap-2 text-xs text-muted-foreground"
                        >
                          <span className="text-primary font-bold">›</span>
                          <span>{takeaway}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Recommendations */}
                {exec.recommendations.length > 0 && (
                  <div className="space-y-2 pt-2">
                    <span className="text-xs font-semibold text-foreground">
                      Recommended Action Items
                    </span>
                    <div className="space-y-1">
                      {exec.recommendations.map((rec, idx) => (
                        <div
                          key={idx}
                          className="flex items-center gap-2 rounded-md bg-muted/30 px-3 py-2 text-xs text-foreground"
                        >
                          <AlertTriangle className="h-3.5 w-3.5 text-amber-400 shrink-0" />
                          <span>{rec}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Embedded Charts Section */}
            {charts && (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* Pie Chart: Severity Distribution */}
                <div className="rounded-xl border border-border bg-card p-4 space-y-3">
                  <div className="flex items-center gap-2 text-xs font-semibold text-foreground">
                    <PieIcon className="h-4 w-4 text-primary" />
                    Severity Breakdown
                  </div>
                  <div className="h-[180px] w-full">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={charts.severityDistribution}
                          dataKey="count"
                          nameKey="severity"
                          cx="50%"
                          cy="50%"
                          outerRadius={60}
                          innerRadius={35}
                          paddingAngle={3}
                        >
                          {charts.severityDistribution.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={entry.fill} />
                          ))}
                        </Pie>
                        <Tooltip
                          contentStyle={{
                            backgroundColor: "var(--card)",
                            border: "1px solid var(--border)",
                            borderRadius: "8px",
                            fontSize: "12px",
                            color: "var(--foreground)",
                          }}
                        />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                </div>

                {/* Trend Chart */}
                <div className="rounded-xl border border-border bg-card p-4 space-y-3">
                  <div className="flex items-center gap-2 text-xs font-semibold text-foreground">
                    <TrendingUp className="h-4 w-4 text-emerald-400" />
                    Vulnerability Trend
                  </div>
                  <div className="h-[180px] w-full">
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart data={charts.trendData} margin={{ top: 5, right: 5, left: -25, bottom: 0 }}>
                        <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                        <XAxis dataKey="month" tick={{ fontSize: 10, fill: "var(--muted-foreground)" }} />
                        <YAxis tick={{ fontSize: 10, fill: "var(--muted-foreground)" }} />
                        <Tooltip
                          contentStyle={{
                            backgroundColor: "var(--card)",
                            border: "1px solid var(--border)",
                            borderRadius: "8px",
                            fontSize: "12px",
                          }}
                        />
                        <Area type="monotone" dataKey="critical" stroke="#ef4444" fill="#ef4444" fillOpacity={0.2} />
                        <Area type="monotone" dataKey="high" stroke="#f97316" fill="#f97316" fillOpacity={0.2} />
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>
                </div>
              </div>
            )}

            {/* Covered Targets */}
            <div className="rounded-xl border border-border bg-card p-4 space-y-2">
              <div className="flex items-center gap-2 text-xs font-semibold text-foreground">
                <Globe className="h-4 w-4 text-primary" />
                Covered Assessment Scope
              </div>
              <div className="space-y-1">
                {report.targetUrls.map((url) => (
                  <div
                    key={url}
                    className="flex items-center gap-2 rounded bg-muted/20 px-3 py-1.5 font-mono text-xs text-foreground"
                  >
                    <span className="text-primary">›</span>
                    <span>{url}</span>
                  </div>
                ))}
              </div>
            </div>
            </>
            )}
          </div>
        </ScrollArea>
      </SheetContent>
    </Sheet>
  )
}
