import { useEffect, useState, useMemo } from "react"
import { motion } from "framer-motion"
import {
  Database,
  Search,
  Copy,
  Check,
  Filter,
  ShieldAlert,
  Terminal,
  Code2,
  ChevronLeft,
  ChevronRight,
  Info,
  AlertTriangle,
  RefreshCw,
  RotateCcw,
} from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Input } from "@/components/ui/input"
import { EmptyState } from "@/components/feedback"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { payloadsService } from "@/services/payloads.service"
import type { SecurityPayload, SecurityPayloadStats } from "@/types"

export function PayloadsPage() {
  const [payloads, setPayloads] = useState<SecurityPayload[]>([])
  const [stats, setStats] = useState<SecurityPayloadStats | null>(null)
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [pageSize] = useState(15)
  const [totalPages, setTotalPages] = useState(1)
  const [isLoading, setIsLoading] = useState(true)
  const [isError, setIsError] = useState(false)
  const [errorMessage, setErrorMessage] = useState<string | null>(null)

  // Filters
  const [search, setSearch] = useState("")
  const [selectedType, setSelectedType] = useState<string>("all")
  const [selectedSeverity, setSelectedSeverity] = useState<string>("all")

  // Selected payload for details modal
  const [activePayload, setActivePayload] = useState<SecurityPayload | null>(null)
  const [copied, setCopied] = useState(false)

  const loadStats = () => {
    payloadsService
      .getStats()
      .then((data) => setStats(data))
      .catch((err) => {
        console.error("Failed to fetch payload stats:", err)
      })
  }

  // Fetch stats once on mount
  useEffect(() => {
    loadStats()
  }, [])

  const fetchPayloads = () => {
    setIsLoading(true)
    setIsError(false)
    setErrorMessage(null)

    payloadsService
      .getPayloads({
        page,
        pageSize,
        type: selectedType !== "all" ? selectedType : undefined,
        severity: selectedSeverity !== "all" ? selectedSeverity : undefined,
        q: search.trim() ? search.trim() : undefined,
      })
      .then((res) => {
        setPayloads(res.items)
        setTotal(res.total)
        setTotalPages(res.total_pages)
        setIsLoading(false)
      })
      .catch((err) => {
        console.error("Failed to fetch payloads:", err)
        const msg = err?.message || "Failed to load security payloads from database."
        setErrorMessage(msg)
        setIsError(true)
        setIsLoading(false)
        toast.error(msg)
      })
  }

  // Fetch paginated payloads on filter/page change
  useEffect(() => {
    fetchPayloads()
  }, [page, pageSize, selectedType, selectedSeverity, search])

  const resetFilters = () => {
    setSearch("")
    setSelectedType("all")
    setSelectedSeverity("all")
    setPage(1)
  }

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true)
      toast.success("Payload copied to clipboard")
      setTimeout(() => setCopied(false), 2000)
    })
  }

  const getSeverityBadgeClass = (sev: string) => {
    switch (sev.toLowerCase()) {
      case "critical":
        return "bg-red-500/10 text-red-500 border-red-500/20"
      case "high":
        return "bg-orange-500/10 text-orange-500 border-orange-500/20"
      case "medium":
        return "bg-yellow-500/10 text-yellow-500 border-yellow-500/20"
      case "low":
        return "bg-blue-500/10 text-blue-500 border-blue-500/20"
      default:
        return "bg-zinc-500/10 text-zinc-400 border-zinc-500/20"
    }
  }

  const categoryOptions = useMemo(() => {
    if (!stats?.by_type) return []
    return Object.keys(stats.by_type).sort()
  }, [stats])

  return (
    <div className="space-y-6">
      {/* ── Page Header ── */}
      <motion.div
        initial={{ opacity: 0, y: -8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
        className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between"
      >
        <div>
          <h1 className="text-2xl font-extrabold tracking-tight text-foreground flex items-center gap-2.5">
            <Database className="h-6 w-6 text-primary" />
            Security Payloads Library
          </h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Curated web application security attack payloads stored in PostgreSQL for automated testing and detection validation.
          </p>
        </div>
      </motion.div>

      {/* ── Statistics Overview Cards ── */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <div className="rounded-xl border border-border/60 bg-card p-4 shadow-xs">
          <div className="flex items-center justify-between text-muted-foreground">
            <span className="text-xs font-medium uppercase tracking-wider">Total Payloads</span>
            <Terminal className="h-4 w-4 text-primary" />
          </div>
          <p className="mt-2 text-2xl font-bold text-foreground">
            {stats ? stats.total.toLocaleString() : "..."}
          </p>
          <span className="text-xs text-muted-foreground">Across all vulnerability vectors</span>
        </div>

        <div className="rounded-xl border border-border/60 bg-card p-4 shadow-xs">
          <div className="flex items-center justify-between text-muted-foreground">
            <span className="text-xs font-medium uppercase tracking-wider">Critical Severity</span>
            <ShieldAlert className="h-4 w-4 text-red-500" />
          </div>
          <p className="mt-2 text-2xl font-bold text-red-500">
            {stats?.by_severity?.critical ?? 0}
          </p>
          <span className="text-xs text-muted-foreground">Severe execution payloads</span>
        </div>

        <div className="rounded-xl border border-border/60 bg-card p-4 shadow-xs">
          <div className="flex items-center justify-between text-muted-foreground">
            <span className="text-xs font-medium uppercase tracking-wider">High Severity</span>
            <ShieldAlert className="h-4 w-4 text-orange-500" />
          </div>
          <p className="mt-2 text-2xl font-bold text-orange-500">
            {stats?.by_severity?.high ?? 0}
          </p>
          <span className="text-xs text-muted-foreground">Exploitation test cases</span>
        </div>

        <div className="rounded-xl border border-border/60 bg-card p-4 shadow-xs">
          <div className="flex items-center justify-between text-muted-foreground">
            <span className="text-xs font-medium uppercase tracking-wider">Categories</span>
            <Code2 className="h-4 w-4 text-blue-500" />
          </div>
          <p className="mt-2 text-2xl font-bold text-foreground">
            {categoryOptions.length || "..."}
          </p>
          <span className="text-xs text-muted-foreground">Distinct attack classifications</span>
        </div>
      </div>

      {/* ── Filters & Search ── */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            value={search}
            onChange={(e) => {
              setSearch(e.target.value)
              setPage(1)
            }}
            placeholder="Search payload ID, description, or content..."
            className="pl-9 h-9"
          />
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          {/* Category Filter */}
          <div className="flex items-center gap-1.5">
            <Filter className="h-3.5 w-3.5 text-muted-foreground" />
            <select
              value={selectedType}
              onChange={(e) => {
                setSelectedType(e.target.value)
                setPage(1)
              }}
              className="h-9 rounded-md border border-input bg-background px-3 py-1 text-xs text-foreground shadow-xs focus:outline-hidden focus:ring-1 focus:ring-ring"
            >
              <option value="all">All Categories</option>
              {categoryOptions.map((cat) => (
                <option key={cat} value={cat}>
                  {cat} ({stats?.by_type[cat]})
                </option>
              ))}
            </select>
          </div>

          {/* Severity Filter */}
          <select
            value={selectedSeverity}
            onChange={(e) => {
              setSelectedSeverity(e.target.value)
              setPage(1)
            }}
            className="h-9 rounded-md border border-input bg-background px-3 py-1 text-xs text-foreground shadow-xs focus:outline-hidden focus:ring-1 focus:ring-ring"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
        </div>
      </div>

      {/* ── Payloads Table ── */}
      <div className="rounded-xl border border-border/60 bg-card overflow-hidden shadow-xs">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="border-b border-border/60 bg-muted/40 text-xs font-semibold text-muted-foreground uppercase tracking-wider">
              <tr>
                <th className="px-4 py-3">ID</th>
                <th className="px-4 py-3">Type</th>
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3">Context</th>
                <th className="px-4 py-3">Description</th>
                <th className="px-4 py-3">Payload (Safe Text)</th>
                <th className="px-4 py-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/40">
              {isError ? (
                <tr>
                  <td colSpan={7} className="py-12 px-4">
                    <div className="flex flex-col items-center justify-center text-center">
                      <div className="rounded-full bg-destructive/10 p-3 text-destructive mb-3">
                        <AlertTriangle className="h-6 w-6" />
                      </div>
                      <h3 className="text-sm font-semibold text-foreground">Failed to Load Security Payloads</h3>
                      <p className="mt-1 max-w-md text-xs text-muted-foreground">
                        {errorMessage || "Unable to retrieve records from the security_payloads database."}
                      </p>
                      <Button
                        variant="outline"
                        size="sm"
                        className="mt-4 text-xs gap-1.5"
                        onClick={() => fetchPayloads()}
                      >
                        <RefreshCw className="h-3.5 w-3.5" /> Retry Connection
                      </Button>
                    </div>
                  </td>
                </tr>
              ) : isLoading ? (
                Array.from({ length: 6 }).map((_, i) => (
                  <tr key={i} className="animate-pulse">
                    <td className="px-4 py-3.5"><div className="h-4 w-16 bg-muted rounded" /></td>
                    <td className="px-4 py-3.5"><div className="h-4 w-20 bg-muted rounded" /></td>
                    <td className="px-4 py-3.5"><div className="h-4 w-14 bg-muted rounded" /></td>
                    <td className="px-4 py-3.5"><div className="h-4 w-24 bg-muted rounded" /></td>
                    <td className="px-4 py-3.5"><div className="h-4 w-48 bg-muted rounded" /></td>
                    <td className="px-4 py-3.5"><div className="h-4 w-40 bg-muted rounded" /></td>
                    <td className="px-4 py-3.5 text-right"><div className="h-4 w-12 bg-muted rounded ml-auto" /></td>
                  </tr>
                ))
              ) : payloads.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12">
                    <EmptyState
                      icon={Database}
                      title="No payloads found"
                      description="No records match your search criteria or filter configuration."
                      action={
                        (search || selectedType !== "all" || selectedSeverity !== "all") ? (
                          <Button variant="outline" size="sm" onClick={resetFilters} className="text-xs gap-1.5">
                            <RotateCcw className="h-3.5 w-3.5" /> Reset Filters
                          </Button>
                        ) : undefined
                      }
                    />
                  </td>
                </tr>
              ) : (
                payloads.map((p) => (
                  <tr key={p.id} className="hover:bg-muted/30 transition-colors">
                    <td className="px-4 py-3.5 font-mono text-xs font-semibold text-primary">
                      {p.id}
                    </td>
                    <td className="px-4 py-3.5">
                      <span className="inline-flex items-center rounded-md bg-secondary px-2 py-0.5 text-xs font-medium text-secondary-foreground">
                        {p.type}
                      </span>
                    </td>
                    <td className="px-4 py-3.5">
                      <Badge variant="outline" className={`text-[11px] font-semibold uppercase ${getSeverityBadgeClass(p.severity)}`}>
                        {p.severity}
                      </Badge>
                    </td>
                    <td className="px-4 py-3.5 text-xs text-muted-foreground max-w-[140px] truncate" title={p.context}>
                      {p.context}
                    </td>
                    <td className="px-4 py-3.5 text-xs text-foreground max-w-xs truncate" title={p.description}>
                      {p.description}
                    </td>
                    <td className="px-4 py-3.5 max-w-sm">
                      {/* Safely rendered text in code tag - Never executed */}
                      <div className="font-mono text-xs bg-muted/60 text-muted-foreground px-2 py-1 rounded border border-border/40 truncate select-all">
                        {p.payload}
                      </div>
                    </td>
                    <td className="px-4 py-3.5 text-right">
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-8 text-xs font-medium"
                        onClick={() => setActivePayload(p)}
                      >
                        Inspect
                      </Button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* ── Pagination Footer ── */}
        <div className="flex items-center justify-between border-t border-border/60 px-4 py-3 text-xs text-muted-foreground">
          <div>
            Showing <span className="font-semibold text-foreground">{payloads.length ? (page - 1) * pageSize + 1 : 0}</span> to{" "}
            <span className="font-semibold text-foreground">{Math.min(page * pageSize, total)}</span> of{" "}
            <span className="font-semibold text-foreground">{total}</span> records
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              disabled={page <= 1 || isLoading}
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              className="h-7 px-2.5"
            >
              <ChevronLeft className="h-3.5 w-3.5 mr-1" /> Previous
            </Button>
            <span className="text-xs px-2">
              Page {page} of {totalPages}
            </span>
            <Button
              variant="outline"
              size="sm"
              disabled={page >= totalPages || isLoading}
              onClick={() => setPage((p) => p + 1)}
              className="h-7 px-2.5"
            >
              Next <ChevronRight className="h-3.5 w-3.5 ml-1" />
            </Button>
          </div>
        </div>
      </div>

      {/* ── Payload Inspector Modal ── */}
      <Dialog open={!!activePayload} onOpenChange={(open) => !open && setActivePayload(null)}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <div className="flex items-center gap-2 mb-1">
              <span className="font-mono text-sm font-bold text-primary">{activePayload?.id}</span>
              {activePayload && (
                <Badge variant="outline" className={`text-xs ${getSeverityBadgeClass(activePayload.severity)}`}>
                  {activePayload.severity.toUpperCase()}
                </Badge>
              )}
              <span className="inline-flex items-center rounded-md bg-secondary px-2 py-0.5 text-xs text-secondary-foreground">
                {activePayload?.type}
              </span>
            </div>
            <DialogTitle className="text-lg font-bold text-foreground">
              {activePayload?.description}
            </DialogTitle>
            <DialogDescription className="text-xs text-muted-foreground">
              Context: {activePayload?.context}
            </DialogDescription>
          </DialogHeader>

          {activePayload && (
            <div className="space-y-4 py-2">
              {/* Payload Safe Box */}
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <span className="text-xs font-semibold text-foreground flex items-center gap-1.5">
                    <Terminal className="h-3.5 w-3.5 text-primary" />
                    Exact Payload String (Safely Escaped)
                  </span>
                  <Button
                    variant="outline"
                    size="sm"
                    className="h-7 text-xs gap-1.5"
                    onClick={() => handleCopy(activePayload.payload)}
                  >
                    {copied ? <Check className="h-3.5 w-3.5 text-emerald-500" /> : <Copy className="h-3.5 w-3.5" />}
                    {copied ? "Copied" : "Copy Payload"}
                  </Button>
                </div>
                {/* Preformatted Text block - safely renders string characters without executing */}
                <pre className="rounded-lg border border-border bg-muted/80 p-3 font-mono text-xs text-foreground overflow-x-auto whitespace-pre-wrap break-all select-all">
                  {activePayload.payload}
                </pre>
              </div>

              {/* Example Usage / Query if present */}
              {activePayload.example_usage && (
                <div>
                  <span className="text-xs font-semibold text-foreground flex items-center gap-1.5 mb-1.5">
                    <Code2 className="h-3.5 w-3.5 text-blue-500" />
                    Example Query / Usage
                  </span>
                  <pre className="rounded-lg border border-border bg-muted/50 p-3 font-mono text-xs text-muted-foreground overflow-x-auto whitespace-pre-wrap break-all select-all">
                    {activePayload.example_usage}
                  </pre>
                </div>
              )}

              {/* Safety Notice */}
              <div className="rounded-lg border border-blue-500/20 bg-blue-500/5 p-3 flex items-start gap-2.5 text-xs text-blue-500">
                <Info className="h-4 w-4 shrink-0 mt-0.5" />
                <p>
                  This attack payload is stored strictly as a test signature for authorized vulnerability detection.
                  It is safely escaped in the frontend UI and guarded against SSRF hazards in the scanner engine.
                </p>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  )
}
