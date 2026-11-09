import { useState, useMemo } from "react"
import { motion, AnimatePresence } from "framer-motion"
import {
  ChevronDown,
  ChevronRight,
  MoreHorizontal,
  Eye,
  CheckCircle2,
  Trash2,
  ArrowUpDown,
  UserPlus,
  Download,
  ShieldAlert,
  AlertTriangle,
  RefreshCw,
} from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { SeverityBadge } from "@/features/dashboard/components/severity-badge"
import { FindingDetailView } from "./finding-detail-view"
import { cn } from "@/utils"
import { toast } from "sonner"
import { findingsService } from "@/services/findings.service"
import type { Finding, FindingStatus, Severity } from "@/types"

const statusLabels: Record<FindingStatus, { label: string; color: string }> = {
  open: { label: "Open", color: "bg-red-500/10 text-red-400 border-red-500/20" },
  confirmed: { label: "Confirmed", color: "bg-orange-500/10 text-orange-400 border-orange-500/20" },
  in_progress: { label: "In Progress", color: "bg-amber-500/10 text-amber-400 border-amber-500/20" },
  resolved: { label: "Resolved", color: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20" },
  reopened: { label: "Reopened", color: "bg-blue-500/10 text-blue-400 border-blue-500/20" },
  false_positive: { label: "False Positive", color: "bg-zinc-500/10 text-zinc-400 border-zinc-500/20" },
  accepted_risk: { label: "Risk Accepted", color: "bg-purple-500/10 text-purple-400 border-purple-500/20" },
}

const severityWeight: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
}

type SortField = "title" | "severity" | "cvssScore" | "status" | "category" | "createdAt"
type SortOrder = "asc" | "desc"

interface FindingTableProps {
  findings: Finding[]
}

export function FindingTable({ findings }: FindingTableProps) {
  const [expandedId, setExpandedId] = useState<string | null>(findings[0]?.id ?? null)
  const [selectedIds, setSelectedIds] = useState<string[]>([])
  const [sortField, setSortField] = useState<SortField>("severity")
  const [sortOrder, setSortOrder] = useState<SortOrder>("desc")
  const [currentPage, setCurrentPage] = useState(1)
  const [pageSize, setPageSize] = useState(10)
  const [statusOverrides, setStatusOverrides] = useState<Record<string, FindingStatus>>({})
  const [deletedIds, setDeletedIds] = useState<Set<string>>(new Set())

  async function handleUpdateStatus(findingId: string, nextStatus: FindingStatus) {
    try {
      await findingsService.updateStatus(findingId, nextStatus)
      setStatusOverrides((prev) => ({ ...prev, [findingId]: nextStatus }))
      const formatted = nextStatus.replace("_", " ")
      toast.success(`Finding status updated to ${formatted}`)
    } catch {
      toast.error("Failed to update finding status")
    }
  }

  async function handleDeleteFinding(findingId: string) {
    try {
      await findingsService.deleteFinding(findingId)
      setDeletedIds((prev) => new Set([...prev, findingId]))
      toast.success("Finding deleted successfully")
    } catch {
      toast.error("Failed to delete finding")
    }
  }

  // Toggle sorting
  function handleSort(field: SortField) {
    if (sortField === field) {
      setSortOrder((prev) => (prev === "asc" ? "desc" : "asc"))
    } else {
      setSortField(field)
      setSortOrder("desc")
    }
  }

  // Sorted findings list
  const sortedFindings = useMemo(() => {
    return [...findings].filter((f) => !deletedIds.has(f.id)).sort((a, b) => {
      let valA: any = a[sortField]
      let valB: any = b[sortField]

      if (sortField === "severity") {
        valA = severityWeight[a.severity]
        valB = severityWeight[b.severity]
      } else if (sortField === "cvssScore") {
        valA = a.cvssScore ?? 0
        valB = b.cvssScore ?? 0
      }

      if (valA < valB) return sortOrder === "asc" ? -1 : 1
      if (valA > valB) return sortOrder === "asc" ? 1 : -1
      return 0
    })
  }, [findings, sortField, sortOrder])

  // Pagination slice
  const paginatedFindings = useMemo(() => {
    const start = (currentPage - 1) * pageSize
    return sortedFindings.slice(start, start + pageSize)
  }, [sortedFindings, currentPage, pageSize])

  const totalPages = Math.ceil(sortedFindings.length / pageSize)

  // Select all logic
  const allSelected = paginatedFindings.length > 0 && paginatedFindings.every((f) => selectedIds.includes(f.id))

  function toggleSelectAll() {
    if (allSelected) {
      setSelectedIds((prev) => prev.filter((id) => !paginatedFindings.some((f) => f.id === id)))
    } else {
      const pageIds = paginatedFindings.map((f) => f.id)
      setSelectedIds((prev) => Array.from(new Set([...prev, ...pageIds])))
    }
  }

  function toggleSelectRow(id: string) {
    setSelectedIds((prev) =>
      prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id],
    )
  }

  function toggleRow(id: string) {
    setExpandedId((prev) => (prev === id ? null : id))
  }

  return (
    <div className="space-y-3">
      {/* Floating Bulk Actions Bar */}
      <AnimatePresence>
        {selectedIds.length > 0 && (
          <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            className="flex items-center justify-between rounded-xl border border-primary/30 bg-primary/10 px-4 py-2.5 shadow-sm"
          >
            <div className="flex items-center gap-2">
              <Badge variant="default" className="font-mono font-bold text-xs">
                {selectedIds.length} Selected
              </Badge>
              <span className="text-xs text-muted-foreground">Apply bulk security actions:</span>
            </div>

            <div className="flex items-center gap-2">
              <Button size="sm" variant="outline" className="h-7 text-xs gap-1.5">
                <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                Mark Resolved
              </Button>
              <Button size="sm" variant="outline" className="h-7 text-xs gap-1.5">
                <UserPlus className="h-3.5 w-3.5 text-blue-400" />
                Assign User
              </Button>
              <Button size="sm" variant="outline" className="h-7 text-xs gap-1.5">
                <Download className="h-3.5 w-3.5 text-violet-400" />
                Export CSV
              </Button>
              <Button
                size="sm"
                variant="ghost"
                onClick={() => setSelectedIds([])}
                className="h-7 text-xs text-muted-foreground hover:text-foreground"
              >
                Clear Selection
              </Button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Main Table Container */}
      <div className="overflow-hidden rounded-2xl border border-border/80 bg-card shadow-sm">
        {/* Table Header */}
        <div className="grid grid-cols-[36px_28px_2.5fr_1.1fr_1fr_1fr_1.2fr_44px] items-center gap-3 border-b border-border/70 bg-muted/40 px-4 py-3 text-xs font-bold uppercase tracking-wider text-muted-foreground select-none">
          {/* Select All Checkbox */}
          <input
            type="checkbox"
            checked={allSelected}
            onChange={toggleSelectAll}
            className="h-4 w-4 rounded border-border text-primary focus:ring-primary/40"
          />

          <span />

          {/* Title Sort */}
          <button
            type="button"
            onClick={() => handleSort("title")}
            className="flex items-center gap-1 hover:text-foreground transition-colors text-left"
          >
            Vulnerability Finding
            <ArrowUpDown className="h-3 w-3" />
          </button>

          {/* Severity Sort */}
          <button
            type="button"
            onClick={() => handleSort("severity")}
            className="flex items-center gap-1 hover:text-foreground transition-colors"
          >
            Severity
            <ArrowUpDown className="h-3 w-3" />
          </button>

          {/* CVSS Sort */}
          <button
            type="button"
            onClick={() => handleSort("cvssScore")}
            className="flex items-center gap-1 hover:text-foreground transition-colors"
          >
            CVSS v3.1
            <ArrowUpDown className="h-3 w-3" />
          </button>

          {/* Status Sort */}
          <button
            type="button"
            onClick={() => handleSort("status")}
            className="flex items-center gap-1 hover:text-foreground transition-colors"
          >
            Status
            <ArrowUpDown className="h-3 w-3" />
          </button>

          {/* Category Sort */}
          <button
            type="button"
            onClick={() => handleSort("category")}
            className="flex items-center gap-1 hover:text-foreground transition-colors"
          >
            Category
            <ArrowUpDown className="h-3 w-3" />
          </button>

          <span className="text-right">Actions</span>
        </div>

        {/* Table Rows */}
        <div className="divide-y divide-border/40">
          {paginatedFindings.map((finding) => {
            const isExpanded = expandedId === finding.id
            const isChecked = selectedIds.includes(finding.id)
            const currentStatus = statusOverrides[finding.id] || finding.status
            const st = statusLabels[currentStatus] || statusLabels.open

            return (
              <div
                key={finding.id}
                className={cn(
                  "transition-colors",
                  isChecked && "bg-primary/[0.03]",
                  isExpanded && "bg-muted/15",
                )}
              >
                {/* Primary Row */}
                <div
                  onClick={() => toggleRow(finding.id)}
                  className="grid cursor-pointer grid-cols-[36px_28px_2.5fr_1.1fr_1fr_1fr_1.2fr_44px] items-center gap-3 px-4 py-3.5 hover:bg-muted/20"
                >
                  {/* Select Checkbox */}
                  <div onClick={(e) => e.stopPropagation()}>
                    <input
                      type="checkbox"
                      checked={isChecked}
                      onChange={() => toggleSelectRow(finding.id)}
                      className="h-4 w-4 rounded border-border text-primary focus:ring-primary/40"
                    />
                  </div>

                  {/* Expand Chevron */}
                  <div className="text-muted-foreground">
                    {isExpanded ? (
                      <ChevronDown className="h-4 w-4 text-primary" />
                    ) : (
                      <ChevronRight className="h-4 w-4" />
                    )}
                  </div>

                  {/* Title & URL */}
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <p className="truncate font-bold text-foreground text-sm group-hover:text-primary transition-colors">
                        {finding.title}
                      </p>
                    </div>
                    <p className="truncate text-xs text-muted-foreground font-mono mt-0.5">
                      {finding.httpMethod && (
                        <span className="text-primary font-bold mr-1">{finding.httpMethod}</span>
                      )}
                      {finding.affectedUrl}
                    </p>
                  </div>

                  {/* Severity Badge */}
                  <div>
                    <SeverityBadge severity={finding.severity} />
                  </div>

                  {/* CVSS Score Gauge */}
                  <div>
                    <span
                      className={cn(
                        "inline-flex items-center rounded-md px-2 py-0.5 font-mono text-xs font-extrabold border",
                        finding.cvssScore && finding.cvssScore >= 9.0
                          ? "bg-red-500/15 text-red-400 border-red-500/30"
                          : finding.cvssScore && finding.cvssScore >= 7.0
                          ? "bg-orange-500/15 text-orange-400 border-orange-500/30"
                          : finding.cvssScore && finding.cvssScore >= 4.0
                          ? "bg-amber-500/15 text-amber-400 border-amber-500/30"
                          : "bg-blue-500/15 text-blue-400 border-blue-500/30",
                      )}
                    >
                      {finding.cvssScore !== undefined ? finding.cvssScore.toFixed(1) : "—"}
                    </span>
                  </div>

                  {/* Status Badge */}
                  <div>
                    <span
                      className={cn(
                        "inline-flex items-center rounded-full border px-2.5 py-0.5 text-[11px] font-semibold",
                        st.color,
                      )}
                    >
                      {st.label}
                    </span>
                  </div>

                  {/* Category */}
                  <div className="truncate">
                    <Badge variant="outline" className="text-[11px] font-medium truncate max-w-full">
                      {finding.category}
                    </Badge>
                  </div>

                  {/* Action Menu */}
                  <div className="flex justify-end" onClick={(e) => e.stopPropagation()}>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" size="icon" className="h-8 w-8">
                          <MoreHorizontal className="h-4 w-4" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end" className="w-44">
                        <DropdownMenuItem onClick={() => toggleRow(finding.id)}>
                          <Eye className="mr-2 h-3.5 w-3.5" />
                          {isExpanded ? "Collapse View" : "Expand Details"}
                        </DropdownMenuItem>
                        <DropdownMenuItem onClick={() => handleUpdateStatus(finding.id, "resolved")}>
                          <CheckCircle2 className="mr-2 h-3.5 w-3.5 text-emerald-400" />
                          Mark Resolved
                        </DropdownMenuItem>
                        <DropdownMenuItem onClick={() => handleUpdateStatus(finding.id, "false_positive")}>
                          <ShieldAlert className="mr-2 h-3.5 w-3.5 text-zinc-400" />
                          Mark False Positive
                        </DropdownMenuItem>
                        <DropdownMenuItem onClick={() => handleUpdateStatus(finding.id, "accepted_risk")}>
                          <AlertTriangle className="mr-2 h-3.5 w-3.5 text-amber-400" />
                          Accept Risk
                        </DropdownMenuItem>
                        {(currentStatus === "resolved" || currentStatus === "false_positive") && (
                          <DropdownMenuItem onClick={() => handleUpdateStatus(finding.id, "reopened")}>
                            <RefreshCw className="mr-2 h-3.5 w-3.5 text-blue-400" />
                            Reopen Finding
                          </DropdownMenuItem>
                        )}
                        <DropdownMenuSeparator />
                        <DropdownMenuItem
                          onClick={() => handleDeleteFinding(finding.id)}
                          className="text-destructive focus:text-destructive"
                        >
                          <Trash2 className="mr-2 h-3.5 w-3.5" />
                          Delete Finding
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </div>
                </div>

                {/* Expandable Detail View Drawer */}
                <AnimatePresence>
                  {isExpanded && (
                    <motion.div
                      initial={{ height: 0, opacity: 0 }}
                      animate={{ height: "auto", opacity: 1 }}
                      exit={{ height: 0, opacity: 0 }}
                      transition={{ duration: 0.25 }}
                      className="overflow-hidden bg-card/60 border-t border-border/50 px-6 py-5"
                    >
                      <FindingDetailView finding={finding} />
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            )
          })}
        </div>

        {/* Pagination Footer */}
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between border-t border-border/60 bg-muted/30 px-4 py-3 text-xs text-muted-foreground">
          <div>
            Showing{" "}
            <span className="font-mono font-bold text-foreground">
              {Math.min(1 + (currentPage - 1) * pageSize, sortedFindings.length)}
            </span>{" "}
            to{" "}
            <span className="font-mono font-bold text-foreground">
              {Math.min(currentPage * pageSize, sortedFindings.length)}
            </span>{" "}
            of <span className="font-mono font-bold text-foreground">{sortedFindings.length}</span> security findings
          </div>

          <div className="flex items-center gap-3">
            <div className="flex items-center gap-1.5">
              <span>Rows per page:</span>
              <select
                value={pageSize}
                onChange={(e) => {
                  setPageSize(Number(e.target.value))
                  setCurrentPage(1)
                }}
                className="rounded-md border border-border bg-card px-2 py-1 text-xs"
              >
                <option value={5}>5</option>
                <option value={10}>10</option>
                <option value={25}>25</option>
                <option value={50}>50</option>
              </select>
            </div>

            <div className="flex items-center gap-1">
              <Button
                variant="outline"
                size="sm"
                disabled={currentPage === 1}
                onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                className="h-7 text-xs"
              >
                Previous
              </Button>
              <span className="px-2 font-mono text-xs font-bold text-foreground">
                {currentPage} / {totalPages || 1}
              </span>
              <Button
                variant="outline"
                size="sm"
                disabled={currentPage >= totalPages}
                onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                className="h-7 text-xs"
              >
                Next
              </Button>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
