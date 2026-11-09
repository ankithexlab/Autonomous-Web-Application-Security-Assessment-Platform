import { useEffect, useState, useMemo } from "react"
import { motion } from "framer-motion"
import { Plus, Crosshair, RefreshCw } from "lucide-react"
import { Button } from "@/components/ui/button"
import { EmptyState } from "@/components/feedback"
import { toast } from "sonner"
import { TargetStatsBar } from "../components/target-stats-bar"
import { TargetTable } from "../components/target-table"
import { TargetCardGrid } from "../components/target-card-grid"
import { TargetDetailPanel } from "../components/target-detail-panel"
import { AddTargetDialog } from "../components/add-target-dialog"
import { TargetFilters } from "../components/target-filters"
import { targetsService } from "@/services/targets.service"
import type { Target, TargetType, TargetStatus, ValidationStatus } from "@/types"

export function TargetsPage() {
  /* ── State ── */
  const [targets, setTargets] = useState<Target[]>([])
  const [search, setSearch] = useState("")
  const [typeFilter, setTypeFilter] = useState<TargetType | "all">("all")
  const [statusFilter, setStatusFilter] = useState<TargetStatus | "all">("all")
  const [validationFilter, setValidationFilter] = useState<
    ValidationStatus | "all"
  >("all")
  const [viewMode, setViewMode] = useState<"cards" | "table">("cards")
  const [selectedTarget, setSelectedTarget] = useState<Target | null>(null)
  const [detailOpen, setDetailOpen] = useState(false)
  const [addDialogOpen, setAddDialogOpen] = useState(false)

  const loadTargets = () => {
    targetsService
      .getTargets()
      .then((data) => {
        setTargets(data)
      })
      .catch(() => {
        toast.error("Failed to load targets from server")
      })
  }

  useEffect(() => {
    loadTargets()
  }, [])

  /* ── Filtered targets ── */
  const filteredTargets = useMemo(() => {
    return targets.filter((target) => {
      // Search filter
      if (search) {
        const q = search.toLowerCase()
        const matchesSearch =
          target.url.toLowerCase().includes(q) ||
          target.description?.toLowerCase().includes(q) ||
          target.tags.some((t) => t.toLowerCase().includes(q)) ||
          target.technology?.some((t) => t.toLowerCase().includes(q))
        if (!matchesSearch) return false
      }

      // Type filter
      if (typeFilter !== "all" && target.type !== typeFilter) return false

      // Status filter
      if (statusFilter !== "all" && target.status !== statusFilter) return false

      // Validation filter
      if (
        validationFilter !== "all" &&
        target.validationStatus !== validationFilter
      )
        return false

      return true
    })
  }, [targets, search, typeFilter, statusFilter, validationFilter])

  /* ── Handlers ── */
  function handleViewDetails(target: Target) {
    setSelectedTarget(target)
    setDetailOpen(true)
    // Freshly query target details to verify and utilize GET /targets/{id}
    targetsService
      .getTargetById(target.id)
      .then((fresh) => {
        setSelectedTarget(fresh)
      })
      .catch((err) => {
        console.warn("Could not fetch fresh target details:", err)
      })
  }

  function handleCloseDetail() {
    setDetailOpen(false)
    setTimeout(() => setSelectedTarget(null), 300)
  }

  async function handleDeleteTarget(target: Target) {
    try {
      if (target.projectId) {
        await targetsService.deleteTarget(target.projectId, target.id)
      } else {
        await targetsService.deleteTargetById(target.id)
      }
      setTargets((prev) => prev.filter((t) => t.id !== target.id))
      if (selectedTarget?.id === target.id) {
        handleCloseDetail()
      }
      toast.success("Target removed successfully")
    } catch {
      toast.error("Failed to delete target")
    }
  }

  async function handleAddTarget(newTargetData: Partial<Target> & { projectId: string }) {
    if (!newTargetData.projectId) {
      toast.error("Project selection is required to register a target.")
      return
    }
    if (!newTargetData.url || !newTargetData.url.trim()) {
      toast.error("Target URL is required to register an assessment target.")
      return
    }
    try {
      const created = await targetsService.createTarget(newTargetData.projectId, {
        url: newTargetData.url.trim(),
        type: newTargetData.type || "web",
        tags: newTargetData.tags,
      })
      setTargets((prev) => [created, ...prev])
      toast.success("Target added successfully")
    } catch {
      toast.error("Failed to add target")
    }
  }

  return (
    <div className="space-y-6">
      {/* Page header */}
      <motion.div
        initial={{ opacity: 0, y: -8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
        className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between"
      >
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-foreground">
            Target Management
          </h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Add and manage authorized target URLs, scope rules, and validation statuses
          </p>
        </div>
        <Button
          onClick={() => setAddDialogOpen(true)}
          className="gap-2 self-start font-semibold"
        >
          <Plus className="h-4 w-4" />
          Add Target
        </Button>
      </motion.div>

      {/* Stats bar */}
      <TargetStatsBar targets={targets} />

      {/* Filters & View Toggle */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.3, delay: 0.1 }}
      >
        <TargetFilters
          search={search}
          onSearchChange={setSearch}
          typeFilter={typeFilter}
          onTypeFilterChange={setTypeFilter}
          statusFilter={statusFilter}
          onStatusFilterChange={setStatusFilter}
          validationFilter={validationFilter}
          onValidationFilterChange={setValidationFilter}
          viewMode={viewMode}
          onViewModeChange={setViewMode}
        />
      </motion.div>

      {/* Main Content Layout: Cards Grid vs Data Table */}
      {filteredTargets.length > 0 ? (
        viewMode === "cards" ? (
          <TargetCardGrid
            targets={filteredTargets}
            onSelectTarget={handleViewDetails}
            onDeleteTarget={handleDeleteTarget}
          />
        ) : (
          <TargetTable
            targets={filteredTargets}
            onViewDetails={handleViewDetails}
            onDeleteTarget={handleDeleteTarget}
          />
        )
      ) : (
        <EmptyState
          icon={Crosshair}
          title="No targets matched"
          description={
            search ||
            typeFilter !== "all" ||
            statusFilter !== "all" ||
            validationFilter !== "all"
              ? "Try adjusting your search terms or filters."
              : "Add your first authorized target URL to begin security assessment."
          }
          action={
            !search &&
            typeFilter === "all" &&
            statusFilter === "all" &&
            validationFilter === "all" ? (
              <div className="flex items-center gap-2">
                <Button
                  onClick={() => setAddDialogOpen(true)}
                  className="gap-2"
                >
                  <Plus className="h-4 w-4" />
                  Add Target
                </Button>
                <Button
                  variant="outline"
                  onClick={() => {
                    targetsService
                      .getTargets()
                      .then((items) => {
                        setTargets(items)
                        toast.success(`Loaded ${items.length} targets`)
                      })
                      .catch(() => toast.error("Failed to load targets"))
                  }}
                  className="gap-2"
                >
                  <RefreshCw className="h-4 w-4" />
                  Load Targets
                </Button>
              </div>
            ) : undefined
          }
        />
      )}

      {/* Slide-out detail sheet */}
      <TargetDetailPanel
        target={selectedTarget}
        open={detailOpen}
        onClose={handleCloseDetail}
        onDeleteTarget={handleDeleteTarget}
      />

      {/* Add Target modal */}
      <AddTargetDialog
        open={addDialogOpen}
        onClose={() => setAddDialogOpen(false)}
        onAddTarget={handleAddTarget}
      />
    </div>
  )
}
