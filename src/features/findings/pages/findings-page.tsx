import { useEffect, useState, useMemo } from "react"
import { motion } from "framer-motion"
import { ShieldAlert, Download } from "lucide-react"
import { Button } from "@/components/ui/button"
import { EmptyState } from "@/components/feedback"
import { toast } from "sonner"
import { FindingStatsBar } from "../components/finding-stats-bar"
import { FindingTable } from "../components/finding-table"
import { FindingFilters } from "../components/finding-filters"
import { findingsService } from "@/services/findings.service"
import type { Finding, Severity, FindingStatus } from "@/types"

export function FindingsPage() {
  const [search, setSearch] = useState("")
  const [severityFilter, setSeverityFilter] = useState<Severity | "all">("all")
  const [statusFilter, setStatusFilter] = useState<FindingStatus | "all">("all")
  const [owaspFilter, setOwaspFilter] = useState<string>("all")
  const [realFindings, setRealFindings] = useState<Finding[]>([])

  useEffect(() => {
    let isMounted = true
    findingsService
      .getFindings({
        severity: severityFilter !== "all" ? severityFilter : undefined,
        status: statusFilter !== "all" ? statusFilter : undefined,
        owaspCategory: owaspFilter !== "all" ? owaspFilter : undefined,
      })
      .then((data) => {
        if (isMounted) {
          setRealFindings(data.items)
        }
      })
      .catch(() => {
        if (isMounted) {
          toast.error("Failed to load vulnerability findings from server")
        }
      })
    return () => {
      isMounted = false
    }
  }, [severityFilter, statusFilter, owaspFilter])

  /* ── Multi-Facet Filtering ── */
  const filteredFindings = useMemo(() => {
    return realFindings.filter((f) => {
      if (search) {
        const q = search.toLowerCase()
        const match =
          f.title.toLowerCase().includes(q) ||
          f.affectedUrl.toLowerCase().includes(q) ||
          f.category.toLowerCase().includes(q) ||
          f.cweId?.toLowerCase().includes(q) ||
          f.tags?.some((t) => t.toLowerCase().includes(q))
        if (!match) return false
      }

      if (severityFilter !== "all" && f.severity !== severityFilter) return false
      if (statusFilter !== "all" && f.status !== statusFilter) return false
      if (owaspFilter !== "all") {
        const matchOwasp = f.owasp?.some(
          (o) =>
            (o.id && o.id.toLowerCase().includes(owaspFilter.toLowerCase().split(":")[0] ?? "")) ||
            (o.name && o.name.toLowerCase().includes(owaspFilter.toLowerCase())),
        )
        if (!matchOwasp) return false
      }

      return true
    })
  }, [search, severityFilter, statusFilter, owaspFilter, realFindings])

  function handleExport() {
    const csvContent =
      "ID,Title,Severity,CVSS,Status,Category,URL\n" +
      filteredFindings
        .map(
          (f) =>
            `"${f.id}","${f.title}","${f.severity}","${f.cvssScore ?? 0}","${f.status}","${f.category}","${f.affectedUrl}"`,
        )
        .join("\n")

    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" })
    const url = URL.createObjectURL(blob)
    const link = document.createElement("a")
    link.href = url
    link.setAttribute("download", `findings-report-${new Date().toISOString().slice(0, 10)}.csv`)
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
    toast.success(`Exported ${filteredFindings.length} vulnerability findings to CSV`)
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
        className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between"
      >
        <div>
          <h1 className="text-2xl font-extrabold tracking-tight text-foreground">
            Vulnerability Findings
          </h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Enterprise vulnerability management, AI threat explanations, CVSS v3.1 metrics, and developer remediation guidance
          </p>
        </div>
        <Button onClick={handleExport} className="gap-2 self-start font-bold">
          <Download className="h-4 w-4" />
          Export Report CSV
        </Button>
      </motion.div>

      {/* Stats Summary Bar */}
      <FindingStatsBar findings={realFindings} />

      {/* Multi-Facet Filters Bar */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.3, delay: 0.1 }}
      >
        <FindingFilters
          search={search}
          onSearchChange={setSearch}
          severityFilter={severityFilter}
          onSeverityFilterChange={setSeverityFilter}
          statusFilter={statusFilter}
          onStatusFilterChange={setStatusFilter}
          owaspFilter={owaspFilter}
          onOwaspFilterChange={setOwaspFilter}
        />
      </motion.div>

      {/* Enterprise Data Table */}
      {filteredFindings.length > 0 ? (
        <FindingTable findings={filteredFindings} />
      ) : (
        <EmptyState
          icon={ShieldAlert}
          title="No vulnerability findings matched"
          description="Try adjusting your search criteria or resetting active filters."
        />
      )}
    </div>
  )
}
