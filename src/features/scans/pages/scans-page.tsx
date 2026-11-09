import { useState, useMemo } from "react"
import { motion } from "framer-motion"
import {
  Radar,
  History,
  Sliders,
  Plus,
  Search,
  SlidersHorizontal,
  ListOrdered,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import { EmptyState } from "@/components/feedback"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuCheckboxItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"

/* ── Scan Center Components ── */
import { useScanEngine } from "../hooks/use-scan-engine"
import { ScanConfigPanel } from "../components/scan-config-panel"
import { CurrentModuleCard } from "../components/current-module-card"
import { ScanCenterMetrics } from "../components/scan-center-metrics"
import { ScanCenterTimeline } from "../components/scan-center-timeline"
import { ScanCenterLogs } from "../components/scan-center-logs"

/* ── Scan History & Queue Components ── */
import { ScanStatsBar } from "../components/scan-stats-bar"
import { ScanStatusCards } from "../components/scan-status-cards"
import { ScanDetailView } from "../components/scan-detail-view"
import { ScanProgressLive } from "../components/scan-progress-live"
import { NewScanDialog } from "../components/new-scan-dialog"
import { ScanQueuePanel } from "../components/scan-queue-panel"
import { ScanPagination } from "../components/scan-pagination"
import type { Scan, ScanStatus, ScanType } from "@/types"

import { useEffect } from "react"
import { scansService } from "@/services/scans.service"
import { toast } from "sonner"

export function ScansPage() {
  const [activeTab, setActiveTab] = useState<"center" | "history" | "queue">("center")

  /* ── Scan Engine Hook ── */
  const engine = useScanEngine()

  /* ── Real API Scans State ── */
  const [realScans, setRealScans] = useState<Scan[]>([])

  /* ── Scan History State ── */
  const [search, setSearch] = useState("")
  const [statusFilter, setStatusFilter] = useState<ScanStatus | "all">("all")
  const [typeFilter, setTypeFilter] = useState<ScanType | "all">("all")
  const [selectedScan, setSelectedScan] = useState<Scan | null>(null)
  const [newScanOpen, setNewScanOpen] = useState(false)

  /* ── Fetch Real Scans ── */
  const fetchScans = async () => {
    try {
      const data = await scansService.getScans()
      setRealScans(data)
      if (data.length > 0 && !selectedScan) {
        setSelectedScan(data[0] ?? null)
      }
    } catch (err) {
      console.error("Failed to fetch scans:", err)
    }
  }

  const handleDeleteScan = async (scanId: string) => {
    try {
      await scansService.deleteScan(scanId)
      toast.success("Scan deleted successfully")
      setRealScans((prev) => prev.filter((s) => s.id !== scanId))
      setSelectedScan((prev) => {
        if (prev?.id === scanId) {
          const remaining = realScans.filter((s) => s.id !== scanId)
          return remaining[0] ?? null
        }
        return prev
      })
    } catch {
      toast.error("Failed to delete scan. Active running scans cannot be deleted.")
    }
  }

  useEffect(() => {
    fetchScans()
    const handleCreated = () => fetchScans()
    window.addEventListener("awsap:scan_created", handleCreated)
    return () => window.removeEventListener("awsap:scan_created", handleCreated)
  }, [])

  const allScans = useMemo(() => {
    return realScans
  }, [realScans])

  /* ── Pagination State ── */
  const [currentPage, setCurrentPage] = useState(1)
  const [pageSize, setPageSize] = useState(5)

  /* ── History Filtering ── */
  const filteredScans = useMemo(() => {
    return allScans.filter((scan) => {
      if (search) {
        const q = search.toLowerCase()
        const matchesSearch =
          scan.targetUrl.toLowerCase().includes(q) ||
          scan.id.toLowerCase().includes(q) ||
          scan.type.toLowerCase().includes(q)
        if (!matchesSearch) return false
      }
      if (statusFilter !== "all" && scan.status !== statusFilter) return false
      if (typeFilter !== "all" && scan.type !== typeFilter) return false
      return true
    })
  }, [allScans, search, statusFilter, typeFilter])

  /* ── Paginated Scans ── */
  const paginatedScans = useMemo(() => {
    const startIndex = (currentPage - 1) * pageSize
    return filteredScans.slice(startIndex, startIndex + pageSize)
  }, [filteredScans, currentPage, pageSize])

  const totalPages = Math.ceil(filteredScans.length / pageSize) || 1

  const activeFilterCount = [statusFilter, typeFilter].filter(
    (f) => f !== "all",
  ).length

  return (
    <div className="space-y-6 select-none pb-8">
      {/* Header & Mode Switcher */}
      <motion.div
        initial={{ opacity: 0, y: -8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
        className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between"
      >
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-2xl font-extrabold tracking-tight text-foreground">
              Security Scan Center
            </h1>
            {engine.status === "running" && (
              <Badge className="bg-emerald-500/15 text-emerald-400 border-emerald-500/30 font-bold uppercase tracking-wider text-[10px]">
                <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-400 mr-1.5" />
                Scan Active
              </Badge>
            )}
          </div>
          <p className="mt-0.5 text-xs sm:text-sm text-muted-foreground">
            Configure, launch, and inspect real-time security vulnerability audits
          </p>
        </div>

        {/* View Switcher Tabs */}
        <div className="flex items-center rounded-xl border border-border/80 bg-muted/40 p-1 overflow-x-auto">
          <button
            type="button"
            onClick={() => setActiveTab("center")}
            className={`flex items-center gap-2 rounded-lg px-3 py-1.5 text-xs font-bold transition-all whitespace-nowrap ${
              activeTab === "center"
                ? "bg-card text-primary shadow-xs"
                : "text-muted-foreground hover:text-foreground"
            }`}
          >
            <Sliders className="h-3.5 w-3.5" />
            Scan Studio (Live Engine)
          </button>
          <button
            type="button"
            onClick={() => setActiveTab("history")}
            className={`flex items-center gap-2 rounded-lg px-3 py-1.5 text-xs font-bold transition-all whitespace-nowrap ${
              activeTab === "history"
                ? "bg-card text-primary shadow-xs"
                : "text-muted-foreground hover:text-foreground"
            }`}
          >
            <History className="h-3.5 w-3.5" />
            Scan History ({allScans.length})
          </button>
          <button
            type="button"
            onClick={() => setActiveTab("queue")}
            className={`flex items-center gap-2 rounded-lg px-3 py-1.5 text-xs font-bold transition-all whitespace-nowrap ${
              activeTab === "queue"
                ? "bg-card text-primary shadow-xs"
                : "text-muted-foreground hover:text-foreground"
            }`}
          >
            <ListOrdered className="h-3.5 w-3.5" />
            Scan Queue
          </button>
        </div>
      </motion.div>

      {/* ── TAB 1: SCAN CENTER WORKSPACE ── */}
      {activeTab === "center" && (
        <motion.div
          initial={{ opacity: 0, y: 4 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3 }}
          className="grid grid-cols-1 gap-6 lg:grid-cols-12"
        >
          {/* Left Column: Scan Configuration Panel (5 cols) */}
          <div className="lg:col-span-5">
            <ScanConfigPanel engine={engine} />
          </div>

          {/* Right Column: Live Monitor & Logs (7 cols) */}
          <div className="space-y-5 lg:col-span-7">
            {/* Top Metrics & Countdown */}
            <ScanCenterMetrics engine={engine} />

            {/* Current Module Card */}
            <CurrentModuleCard engine={engine} />

            {/* Execution Timeline */}
            <ScanCenterTimeline engine={engine} />

            {/* Live Logs Terminal Console */}
            <ScanCenterLogs engine={engine} />
          </div>
        </motion.div>
      )}

      {/* ── TAB 2: SCAN HISTORY & DETAILS ── */}
      {activeTab === "history" && (
        <motion.div
          initial={{ opacity: 0, y: 4 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3 }}
          className="space-y-6"
        >
          {/* Stats */}
          <ScanStatsBar scans={allScans} />

          {/* Search + Filters */}
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex items-center gap-3 flex-1">
              <div className="relative max-w-sm flex-1">
                <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  placeholder="Search scans by URL or ID…"
                  value={search}
                  onChange={(e) => {
                    setSearch(e.target.value)
                    setCurrentPage(1)
                  }}
                  className="pl-9 text-xs"
                />
              </div>

              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="outline" size="sm" className="gap-2 text-xs">
                    <SlidersHorizontal className="h-3.5 w-3.5" />
                    Filters
                    {activeFilterCount > 0 && (
                      <Badge
                        variant="default"
                        className="h-5 min-w-5 rounded-full px-1.5 text-[10px] font-bold"
                      >
                        {activeFilterCount}
                      </Badge>
                    )}
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end" className="w-48">
                  <DropdownMenuLabel className="text-xs">Status</DropdownMenuLabel>
                  {(["all", "running", "queued", "completed", "failed", "cancelled"] as const).map(
                    (s) => (
                      <DropdownMenuCheckboxItem
                        key={s}
                        checked={statusFilter === s}
                        onCheckedChange={() => {
                          setStatusFilter(s)
                          setCurrentPage(1)
                        }}
                      >
                        {s === "all" ? "All Statuses" : s.charAt(0).toUpperCase() + s.slice(1)}
                      </DropdownMenuCheckboxItem>
                    ),
                  )}
                  <DropdownMenuSeparator />
                  <DropdownMenuLabel className="text-xs">Type</DropdownMenuLabel>
                  {(["all", "full", "quick", "targeted", "continuous"] as const).map(
                    (t) => (
                      <DropdownMenuCheckboxItem
                        key={t}
                        checked={typeFilter === t}
                        onCheckedChange={() => {
                          setTypeFilter(t)
                          setCurrentPage(1)
                        }}
                      >
                        {t === "all"
                          ? "All Types"
                          : t.charAt(0).toUpperCase() + t.slice(1)}
                      </DropdownMenuCheckboxItem>
                    ),
                  )}
                </DropdownMenuContent>
              </DropdownMenu>
            </div>

            <Button
              onClick={() => setNewScanOpen(true)}
              className="gap-2 text-xs font-semibold shadow-xs"
            >
              <Plus className="h-4 w-4" />
              New Scan Record
            </Button>
          </div>

          {/* Main split layout */}
          {filteredScans.length > 0 ? (
            <div className="space-y-4">
              <div className="grid grid-cols-1 gap-5 lg:grid-cols-[380px_1fr]">
                {/* Left: Scan cards */}
                <div className="max-h-[calc(100vh-340px)] overflow-y-auto pr-1">
                  <ScanStatusCards
                    scans={paginatedScans}
                    selectedScanId={selectedScan?.id ?? null}
                    onSelectScan={setSelectedScan}
                  />
                </div>

                {/* Right: Detail view */}
                <div className="max-h-[calc(100vh-340px)] overflow-y-auto pr-1">
                  {selectedScan ? (
                    <div className="space-y-4">
                      <ScanProgressLive scan={selectedScan} />
                      <ScanDetailView scan={selectedScan} onDeleteScan={handleDeleteScan} />
                    </div>
                  ) : (
                    <div className="flex h-full items-center justify-center rounded-xl border border-dashed border-border py-24">
                      <div className="text-center">
                        <Radar className="mx-auto h-10 w-10 text-muted-foreground/40" />
                        <p className="mt-3 text-sm text-muted-foreground">
                          Select a scan to view details
                        </p>
                      </div>
                    </div>
                  )}
                </div>
              </div>

              {/* Pagination controls */}
              <ScanPagination
                currentPage={currentPage}
                totalPages={totalPages}
                totalItems={filteredScans.length}
                pageSize={pageSize}
                onPageChange={setCurrentPage}
                onPageSizeChange={(size) => {
                  setPageSize(size)
                  setCurrentPage(1)
                }}
              />
            </div>
          ) : (
            <EmptyState
              icon={Radar}
              title="No scans found"
              description="Try adjusting your search or filters."
            />
          )}

          {/* New scan dialog */}
          <NewScanDialog
            open={newScanOpen}
            onClose={() => setNewScanOpen(false)}
          />
        </motion.div>
      )}

      {/* ── TAB 3: SCAN QUEUE ── */}
      {activeTab === "queue" && (
        <motion.div
          initial={{ opacity: 0, y: 4 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3 }}
        >
          <ScanQueuePanel />
        </motion.div>
      )}
    </div>
  )
}
