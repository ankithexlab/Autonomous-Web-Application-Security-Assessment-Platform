import { useEffect, useState } from "react"
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  FileText,
  Cpu,
  ShieldCheck,
  SlidersHorizontal,
  Loader2,
  Check,
  FolderKanban,
  Crosshair,
  Radar,
} from "lucide-react"
import { toast } from "sonner"
import { projectsService } from "@/services/projects.service"
import { targetsService } from "@/services/targets.service"
import { scansService } from "@/services/scans.service"
import { reportsService } from "@/services/reports.service"
import { cn } from "@/utils"
import type { Project, Target, Scan, ReportType, ReportFormat } from "@/types"

const reportTypes: {
  value: ReportType
  label: string
  description: string
  icon: typeof FileText
}[] = [
  {
    value: "executive",
    label: "Executive Summary",
    description: "High-level risk rating & C-suite overview",
    icon: FileText,
  },
  {
    value: "technical",
    label: "Technical Details",
    description: "Full vulnerability proof of concepts & code remediation",
    icon: Cpu,
  },
  {
    value: "compliance",
    label: "Compliance Audit",
    description: "Mapped against OWASP Top 10, SOC 2 & PCI-DSS",
    icon: ShieldCheck,
  },
  {
    value: "custom",
    label: "Custom Assessment",
    description: "Select specific modules and target scopes",
    icon: SlidersHorizontal,
  },
]

interface GenerateReportDialogProps {
  open: boolean
  onClose: () => void
}

export function GenerateReportDialog({ open, onClose }: GenerateReportDialogProps) {
  const [projects, setProjects] = useState<Project[]>([])
  const [selectedProjectId, setSelectedProjectId] = useState<string>("")
  const [isLoadingProjects, setIsLoadingProjects] = useState(false)

  const [targets, setTargets] = useState<Target[]>([])
  const [scans, setScans] = useState<Scan[]>([])
  const [isLoadingScope, setIsLoadingScope] = useState(false)

  const [scopeMode, setScopeMode] = useState<"project" | "target" | "scan">("project")
  const [selectedTargetId, setSelectedTargetId] = useState<string>("")
  const [selectedScanId, setSelectedScanId] = useState<string>("")

  const [selectedType, setSelectedType] = useState<ReportType>("executive")
  const [title, setTitle] = useState("")
  const [formats, setFormats] = useState<ReportFormat[]>(["pdf", "html"])
  const [isSubmitting, setIsSubmitting] = useState(false)

  useEffect(() => {
    if (open) {
      setIsLoadingProjects(true)
      projectsService
        .getProjects()
        .then((items) => {
          setProjects(items)
          if (items.length > 0 && items[0] && !selectedProjectId) {
            setSelectedProjectId(items[0].id)
          }
        })
        .catch(() => {
          toast.error("Failed to load authorized projects")
        })
        .finally(() => {
          setIsLoadingProjects(false)
        })
    }
  }, [open])

  useEffect(() => {
    if (selectedProjectId) {
      setIsLoadingScope(true)
      Promise.all([
        targetsService.getTargets(selectedProjectId).catch(() => []),
        scansService.getScans().catch(() => []),
      ])
        .then(([targetList, allScans]) => {
          setTargets(targetList)
          const projectScans = allScans.filter((s) => s.projectId === selectedProjectId)
          setScans(projectScans)
          setSelectedTargetId("")
          setSelectedScanId("")
        })
        .finally(() => {
          setIsLoadingScope(false)
        })
    }
  }, [selectedProjectId])

  function toggleFormat(fmt: ReportFormat) {
    setFormats((prev) =>
      prev.includes(fmt) ? prev.filter((f) => f !== fmt) : [...prev, fmt],
    )
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!selectedProjectId) {
      toast.error("Please select a project for the security report.")
      return
    }

    if (scopeMode === "target" && !selectedTargetId) {
      toast.error("Please select a target for this scoped report.")
      return
    }

    if (scopeMode === "scan" && !selectedScanId) {
      toast.error("Please select a scan for this scoped report.")
      return
    }

    setIsSubmitting(true)
    try {
      const fmt = formats[0] || "pdf"
      await reportsService.createReport(selectedProjectId, {
        title: title.trim() || `${selectedType.toUpperCase()} Security Report`,
        report_type: selectedType,
        file_format: fmt,
        scan_id: scopeMode === "scan" && selectedScanId ? selectedScanId : undefined,
        target_id: scopeMode === "target" && selectedTargetId ? selectedTargetId : undefined,
      })
      toast.success("Security report generated successfully")
      handleReset()
      onClose()
      window.dispatchEvent(new CustomEvent("awsap:report_created"))
    } catch {
      toast.error("Failed to generate report")
    } finally {
      setIsSubmitting(false)
    }
  }

  function handleReset() {
    setSelectedType("executive")
    setTitle("")
    setFormats(["pdf", "html"])
    setScopeMode("project")
    setSelectedTargetId("")
    setSelectedScanId("")
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        if (!o) {
          handleReset()
          onClose()
        }
      }}
    >
      <DialogContent className="sm:max-w-[540px]">
        <DialogHeader>
          <DialogTitle>Generate Security Assessment Report</DialogTitle>
          <DialogDescription>
            Select report template and output formats to compile vulnerability intelligence.
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleSubmit} className="space-y-5">
          {/* Project Selector */}
          <div className="space-y-2">
            <Label htmlFor="report-project" className="flex items-center gap-1.5 font-semibold">
              <FolderKanban className="h-4 w-4 text-primary" />
              Target Project <span className="text-destructive">*</span>
            </Label>
            {isLoadingProjects ? (
              <div className="flex items-center gap-2 rounded-md border border-border p-2.5 text-xs text-muted-foreground">
                <Loader2 className="h-4 w-4 animate-spin text-primary" />
                Loading authorized projects...
              </div>
            ) : projects.length === 0 ? (
              <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-400">
                No active projects found. You must create a project before generating security reports.
              </div>
            ) : (
              <select
                id="report-project"
                value={selectedProjectId}
                onChange={(e) => setSelectedProjectId(e.target.value)}
                className="w-full rounded-md border border-input bg-card px-3 py-2 text-sm text-foreground ring-offset-background focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2"
                required
              >
                <option value="" disabled>Select project...</option>
                {projects.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name}
                  </option>
                ))}
              </select>
            )}
          </div>

          {/* Assessment Scope Selection */}
          <div className="space-y-2">
            <Label className="flex items-center gap-1.5 font-semibold">
              <Crosshair className="h-4 w-4 text-primary" />
              Report Scope
            </Label>
            <div className="grid grid-cols-3 gap-2">
              <button
                type="button"
                onClick={() => setScopeMode("project")}
                className={cn(
                  "flex items-center justify-center gap-1.5 rounded-lg border p-2 text-xs font-semibold transition-all",
                  scopeMode === "project"
                    ? "border-primary bg-primary/10 text-primary"
                    : "border-border bg-card text-muted-foreground hover:bg-muted/30",
                )}
              >
                <FolderKanban className="h-3.5 w-3.5" />
                Entire Project
              </button>
              <button
                type="button"
                onClick={() => setScopeMode("target")}
                className={cn(
                  "flex items-center justify-center gap-1.5 rounded-lg border p-2 text-xs font-semibold transition-all",
                  scopeMode === "target"
                    ? "border-primary bg-primary/10 text-primary"
                    : "border-border bg-card text-muted-foreground hover:bg-muted/30",
                )}
              >
                <Crosshair className="h-3.5 w-3.5" />
                Specific Target
              </button>
              <button
                type="button"
                onClick={() => setScopeMode("scan")}
                className={cn(
                  "flex items-center justify-center gap-1.5 rounded-lg border p-2 text-xs font-semibold transition-all",
                  scopeMode === "scan"
                    ? "border-primary bg-primary/10 text-primary"
                    : "border-border bg-card text-muted-foreground hover:bg-muted/30",
                )}
              >
                <Radar className="h-3.5 w-3.5" />
                Specific Scan
              </button>
            </div>

            {/* Sub-scope Dropdowns */}
            {isLoadingScope ? (
              <div className="flex items-center gap-2 py-1 text-xs text-muted-foreground">
                <Loader2 className="h-3.5 w-3.5 animate-spin text-primary" />
                Loading scoped assets...
              </div>
            ) : scopeMode === "target" ? (
              targets.length === 0 ? (
                <p className="text-xs text-amber-400 py-1">No targets registered under this project.</p>
              ) : (
                <select
                  value={selectedTargetId}
                  onChange={(e) => setSelectedTargetId(e.target.value)}
                  className="w-full rounded-md border border-input bg-card px-3 py-2 text-xs text-foreground mt-1.5 ring-offset-background focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2"
                >
                  <option value="">Select target...</option>
                  {targets.map((t) => (
                    <option key={t.id} value={t.id}>
                      {t.url} ({t.type})
                    </option>
                  ))}
                </select>
              )
            ) : scopeMode === "scan" ? (
              scans.length === 0 ? (
                <p className="text-xs text-amber-400 py-1">No executed scans found for this project.</p>
              ) : (
                <select
                  value={selectedScanId}
                  onChange={(e) => setSelectedScanId(e.target.value)}
                  className="w-full rounded-md border border-input bg-card px-3 py-2 text-xs text-foreground mt-1.5 ring-offset-background focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2"
                >
                  <option value="">Select scan run...</option>
                  {scans.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.targetUrl} - {(s.type || "full").toUpperCase()} ({s.status}) [{new Date(s.createdAt).toLocaleDateString()}]
                    </option>
                  ))}
                </select>
              )
            ) : null}
          </div>

          {/* Report Type */}
          <div className="space-y-2">
            <Label>Report Template</Label>
            <div className="grid grid-cols-2 gap-2">
              {reportTypes.map((rt) => (
                <button
                  key={rt.value}
                  type="button"
                  onClick={() => setSelectedType(rt.value)}
                  className={cn(
                    "flex items-start gap-3 rounded-lg border-2 p-3 text-left transition-all",
                    selectedType === rt.value
                      ? "border-primary bg-primary/5 text-primary"
                      : "border-border bg-card text-muted-foreground hover:border-muted-foreground/30",
                  )}
                >
                  <rt.icon className="h-5 w-5 shrink-0 mt-0.5" />
                  <div>
                    <span className="text-xs font-semibold text-foreground block">
                      {rt.label}
                    </span>
                    <span className="text-[10px] leading-tight text-muted-foreground block mt-0.5">
                      {rt.description}
                    </span>
                  </div>
                </button>
              ))}
            </div>
          </div>

          {/* Title */}
          <div className="space-y-2">
            <Label htmlFor="report-title">Report Title</Label>
            <Input
              id="report-title"
              placeholder="e.g. Q3 2026 Penetration Testing & Vulnerability Report"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              required
            />
          </div>

          {/* Formats Checklist */}
          <div className="space-y-2">
            <Label>Target Formats</Label>
            <div className="flex gap-3">
              {(["pdf", "html", "json", "csv"] as const).map((fmt) => {
                const checked = formats.includes(fmt)
                return (
                  <button
                    key={fmt}
                    type="button"
                    onClick={() => toggleFormat(fmt)}
                    className={cn(
                      "flex items-center gap-2 rounded-lg border px-3 py-2 uppercase font-bold text-xs transition-all",
                      checked
                        ? "border-primary bg-primary/10 text-primary"
                        : "border-border text-muted-foreground hover:bg-muted/30",
                    )}
                  >
                    <div
                      className={cn(
                        "flex h-4 w-4 items-center justify-center rounded border",
                        checked ? "border-primary bg-primary text-primary-foreground" : "border-muted-foreground/30",
                      )}
                    >
                      {checked && <Check className="h-3 w-3" />}
                    </div>
                    {fmt}
                  </button>
                )
              })}
            </div>
          </div>

          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>
              Cancel
            </Button>
            <Button
              type="submit"
              disabled={
                !title.trim() ||
                formats.length === 0 ||
                isSubmitting ||
                !selectedProjectId ||
                projects.length === 0 ||
                (scopeMode === "target" && !selectedTargetId) ||
                (scopeMode === "scan" && !selectedScanId)
              }
            >
              {isSubmitting ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin mr-1" />
                  Compiling Report...
                </>
              ) : (
                "Generate Report"
              )}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
