import { useState } from "react"
import {
  FileText,
  FileCode2,
  Code,
  FileSpreadsheet,
  Download,
  Check,
  Sparkles,
  Eye,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { toast } from "sonner"
import { cn } from "@/utils"
import { reportsService } from "@/services/reports.service"
import type { Report } from "@/types"

export interface ExportOptionsBarProps {
  onPreviewJson?: () => void
  latestReport?: Report | null
}

export function ExportOptionsBar({ onPreviewJson, latestReport }: ExportOptionsBarProps) {
  const [downloadingFmt, setDownloadingFmt] = useState<string | null>(null)
  const [successFmt, setSuccessFmt] = useState<string | null>(null)

  async function handleExport(fmt: "pdf" | "html" | "json" | "csv", filename: string) {
    if (!latestReport?.id) {
      toast.error("No generated reports available to download. Please generate a report first.")
      return
    }

    setDownloadingFmt(fmt)

    try {
      await reportsService.downloadReport(latestReport.id, filename, fmt)
      setSuccessFmt(fmt)
      toast.success(`${fmt.toUpperCase()} report downloaded successfully`)
    } catch (err: any) {
      toast.error(`Export failed: ${err.message || "Failed to download report from server"}`)
    } finally {
      setDownloadingFmt(null)
      setTimeout(() => setSuccessFmt(null), 2500)
    }
  }

  const exportCards = [
    {
      id: "pdf" as const,
      name: "PDF Executive Audit Report",
      fmt: "PDF",
      desc: "Full vector graphic PDF with charts, executive summary, and compliance badges.",
      icon: FileText,
      badge: "Print Ready",
      size: "~4.8 MB",
      filename: "Executive-Security-Audit-Q2.pdf",
      color: "border-red-500/30 bg-red-500/5 text-red-400",
    },
    {
      id: "html" as const,
      name: "HTML Standalone Web Report",
      fmt: "HTML",
      desc: "Interactive offline web report featuring dark mode theme and embedded charts.",
      icon: FileCode2,
      badge: "Interactive",
      size: "~1.2 MB",
      filename: "Security-Report-Interactive.html",
      color: "border-blue-500/30 bg-blue-500/5 text-blue-400",
    },
    {
      id: "json" as const,
      name: "JSON Machine API Schema",
      fmt: "JSON",
      desc: "Structured REST JSON payload for SIEM, Jira, or CI/CD automated ingestion.",
      icon: Code,
      badge: "API Schema",
      size: "~340 KB",
      filename: "Security-Report-Schema.json",
      color: "border-emerald-500/30 bg-emerald-500/5 text-emerald-400",
    },
    {
      id: "csv" as const,
      name: "CSV Raw Findings Data",
      fmt: "CSV",
      desc: "Tabular spreadsheet dataset containing all finding rows for Excel analysis.",
      icon: FileSpreadsheet,
      badge: "Spreadsheet",
      size: "~120 KB",
      filename: "Raw-Findings-Export.csv",
      color: "border-violet-500/30 bg-violet-500/5 text-violet-400",
    },
  ]

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Sparkles className="h-4 w-4 text-primary" />
          <h3 className="text-sm font-bold text-foreground">One-Click Multi-Format Export Center</h3>
        </div>
        <span className="text-xs text-muted-foreground">Select report export format</span>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        {exportCards.map((card) => {
          const Icon = card.icon
          const isDownloading = downloadingFmt === card.id
          const isSuccess = successFmt === card.id

          return (
            <div
              key={card.id}
              className={cn(
                "flex flex-col justify-between rounded-2xl border p-4 shadow-sm transition-all hover:border-primary/40 bg-card",
              )}
            >
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className={cn("flex h-8 w-8 items-center justify-center rounded-lg border", card.color)}>
                    <Icon className="h-4 w-4" />
                  </span>
                  <Badge variant="outline" className="text-[10px] font-mono uppercase">
                    {card.badge}
                  </Badge>
                </div>

                <div>
                  <h4 className="text-xs font-bold text-foreground">{card.name}</h4>
                  <p className="text-[11px] text-muted-foreground mt-1 line-clamp-2 leading-tight">
                    {card.desc}
                  </p>
                </div>
              </div>

              <div className="mt-4 pt-3 border-t border-border/40 flex items-center justify-between">
                <span className="font-mono text-[10px] text-muted-foreground">{card.size}</span>

                <div className="flex items-center gap-1.5">
                  {card.id === "json" && onPreviewJson && (
                    <Button
                      variant="ghost"
                      size="icon"
                      onClick={onPreviewJson}
                      title="Preview JSON"
                      className="h-7 w-7"
                    >
                      <Eye className="h-3.5 w-3.5 text-muted-foreground" />
                    </Button>
                  )}

                  <Button
                    size="sm"
                    disabled={isDownloading}
                    onClick={() => handleExport(card.id, card.filename)}
                    className="h-7 text-xs font-bold gap-1 uppercase"
                  >
                    {isSuccess ? (
                      <Check className="h-3.5 w-3.5 text-emerald-400" />
                    ) : (
                      <Download className={cn("h-3.5 w-3.5", isDownloading && "animate-bounce")} />
                    )}
                    {isDownloading ? "Generating..." : `Export ${card.fmt}`}
                  </Button>
                </div>
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
