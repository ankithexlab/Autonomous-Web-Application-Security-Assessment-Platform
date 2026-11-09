import { useState } from "react"
import { motion } from "framer-motion"
import {
  FileText,
  Download,
  Eye,
  MoreHorizontal,
  CheckCircle2,
  Clock,
  XCircle,
  Trash2,
} from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
  DropdownMenuSeparator,
} from "@/components/ui/dropdown-menu"
import { toast } from "sonner"
import { reportsService } from "@/services/reports.service"
import { cn, formatRelativeTime } from "@/utils"
import type { Report, ReportStatus, ReportType, ReportFormat } from "@/types"

const statusConfig: Record<ReportStatus, { label: string; color: string; icon: typeof CheckCircle2 }> = {
  completed: { label: "Completed", color: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20", icon: CheckCircle2 },
  generating: { label: "Generating", color: "bg-amber-500/10 text-amber-400 border-amber-500/20", icon: Clock },
  failed: { label: "Failed", color: "bg-red-500/10 text-red-400 border-red-500/20", icon: XCircle },
}

const typeLabels: Record<ReportType, string> = {
  executive: "Executive Summary",
  technical: "Technical Detail",
  compliance: "Compliance Audit",
  custom: "Custom Report",
}

interface ReportHistoryTableProps {
  reports: Report[]
  onPreview: (report: Report) => void
  onDeleteReport?: (id: string) => void
}

export function ReportHistoryTable({ reports, onPreview, onDeleteReport }: ReportHistoryTableProps) {
  const [downloadingId, setDownloadingId] = useState<string | null>(null)
  const [deletingId, setDeletingId] = useState<string | null>(null)

  async function handleDelete(reportId: string) {
    setDeletingId(reportId)
    try {
      await reportsService.deleteReport(reportId)
      toast.success("Report deleted successfully")
      onDeleteReport?.(reportId)
    } catch {
      toast.error("Failed to delete report")
    } finally {
      setDeletingId(null)
    }
  }

  async function handleDownload(reportId: string, fmt: ReportFormat) {
    setDownloadingId(`${reportId}-${fmt}`)
    try {
      await reportsService.downloadReport(reportId, `report_${reportId}.${fmt}`, fmt)
      toast.success(`Downloaded ${fmt.toUpperCase()} report`)
    } catch {
      toast.error("Failed to download report document")
    } finally {
      setDownloadingId(null)
    }
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35, delay: 0.15 }}
      className="overflow-hidden rounded-xl border border-border bg-card"
    >
      {/* Table Header */}
      <div className="grid grid-cols-[2fr_1fr_0.8fr_0.8fr_1fr_0.8fr] items-center gap-4 border-b border-border bg-muted/30 px-5 py-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
        <span>Report Document</span>
        <span>Type</span>
        <span>Status</span>
        <span>Formats</span>
        <span>Created</span>
        <span className="text-right">Actions</span>
      </div>

      {/* Rows */}
      {reports.map((report, index) => {
        const st = statusConfig[report.status]
        const StatusIcon = st.icon

        return (
          <motion.div
            key={report.id}
            initial={{ opacity: 0, x: -8 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.25, delay: 0.05 * index }}
            className="group grid grid-cols-[2fr_1fr_0.8fr_0.8fr_1fr_0.8fr] items-center gap-4 border-b border-border/50 px-5 py-3.5 transition-colors last:border-b-0 hover:bg-muted/20"
          >
            {/* Title & Project */}
            <div className="flex items-center gap-3 min-w-0">
              <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-primary/10">
                <FileText className="h-4 w-4 text-primary" />
              </div>
              <div className="min-w-0">
                <button
                  onClick={() => onPreview(report)}
                  className="flex items-center gap-1.5 text-sm font-semibold text-foreground transition-colors hover:text-primary text-left"
                >
                  <span className="truncate">{report.title}</span>
                </button>
                <p className="mt-0.5 truncate text-xs text-muted-foreground">
                  {report.projectName} · {report.author}
                </p>
              </div>
            </div>

            {/* Type */}
            <div>
              <Badge variant="outline" className="text-[11px] font-medium">
                {typeLabels[report.type]}
              </Badge>
            </div>

            {/* Status */}
            <div>
              <span
                className={cn(
                  "inline-flex items-center gap-1 rounded-full border px-2.5 py-0.5 text-[11px] font-medium",
                  st.color,
                )}
              >
                <StatusIcon className="h-3 w-3" />
                {st.label}
              </span>
            </div>

            {/* Formats Available */}
            <div className="flex items-center gap-1">
              {report.availableFormats.map((fmt) => (
                <Badge
                  key={fmt}
                  variant="secondary"
                  className="uppercase text-[9px] px-1.5 py-0 font-bold"
                >
                  {fmt}
                </Badge>
              ))}
            </div>

            {/* Created At */}
            <div className="text-xs text-muted-foreground">
              {formatRelativeTime(new Date(report.createdAt))}
            </div>

            {/* Actions */}
            <div className="flex justify-end gap-1">
              <Button
                variant="outline"
                size="sm"
                onClick={() => onPreview(report)}
                className="gap-1.5 text-xs"
              >
                <Eye className="h-3.5 w-3.5" />
                Preview
              </Button>

              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="ghost" size="icon-sm">
                    <MoreHorizontal className="h-4 w-4" />
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end" className="w-44">
                  <DropdownMenuItem onClick={() => onPreview(report)}>
                    <Eye className="mr-2 h-3.5 w-3.5" />
                    Preview Details
                  </DropdownMenuItem>
                  <DropdownMenuSeparator />
                  {report.availableFormats.map((fmt) => {
                    const isDownloading = downloadingId === `${report.id}-${fmt}`
                    return (
                      <DropdownMenuItem
                        key={fmt}
                        disabled={isDownloading}
                        onClick={() => handleDownload(report.id, fmt)}
                      >
                        <Download className={cn("mr-2 h-3.5 w-3.5", isDownloading && "animate-bounce")} />
                        {isDownloading ? `Preparing ${fmt.toUpperCase()}...` : `Download ${fmt.toUpperCase()}`}
                      </DropdownMenuItem>
                    )
                  })}
                  <DropdownMenuSeparator />
                  <DropdownMenuItem
                    disabled={deletingId === report.id}
                    onClick={() => handleDelete(report.id)}
                    className="text-destructive focus:text-destructive"
                  >
                    <Trash2 className="mr-2 h-3.5 w-3.5" />
                    {deletingId === report.id ? "Deleting..." : "Delete Report"}
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            </div>
          </motion.div>
        )
      })}
    </motion.div>
  )
}
