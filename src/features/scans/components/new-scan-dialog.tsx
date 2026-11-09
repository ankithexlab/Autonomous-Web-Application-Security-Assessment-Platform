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
import { Separator } from "@/components/ui/separator"
import {
  Radar,
  Zap,
  Crosshair,
  RefreshCw,
  Play,
  Loader2,
  ChevronDown,
  ChevronUp,
  Check,
  Link2,
  FlaskConical,
} from "lucide-react"
import { cn } from "@/utils"
import { AVAILABLE_MODULES } from "../data/scans-data"
import { scansService } from "@/services/scans.service"
import { targetsService } from "@/services/targets.service"
import type { ScanType, Target } from "@/types"
import { toast } from "sonner"

/* ── Scan type cards ── */
const scanTypes: {
  value: ScanType
  label: string
  description: string
  icon: typeof Radar
  modules: string
  estimatedTime: string
}[] = [
  {
    value: "full",
    label: "Full Scan",
    description: "Comprehensive security assessment with all modules",
    icon: Radar,
    modules: "All modules",
    estimatedTime: "30–60 min",
  },
  {
    value: "quick",
    label: "Quick Scan",
    description: "Fast surface-level check of common vulnerabilities",
    icon: Zap,
    modules: "3 modules",
    estimatedTime: "5–10 min",
  },
  {
    value: "targeted",
    label: "Targeted Scan",
    description: "Focus on specific vulnerability categories",
    icon: Crosshair,
    modules: "Custom",
    estimatedTime: "10–30 min",
  },
  {
    value: "continuous",
    label: "Continuous",
    description: "Ongoing monitoring with periodic re-scans",
    icon: RefreshCw,
    modules: "All modules",
    estimatedTime: "Recurring",
  },
]

interface NewScanDialogProps {
  open: boolean
  onClose: () => void
}

export function NewScanDialog({ open, onClose }: NewScanDialogProps) {
  const [selectedType, setSelectedType] = useState<ScanType>("full")
  const [targetMode, setTargetMode] = useState<"preconfigured" | "manual">("preconfigured")
  const [selectedTarget, setSelectedTarget] = useState("")
  const [manualUrl, setManualUrl] = useState("")
  const [authorizedConfirmation, setAuthorizedConfirmation] = useState(false)
  const [targetOptions, setTargetOptions] = useState<Target[]>([])
  const [selectedModules, setSelectedModules] = useState<string[]>(
    AVAILABLE_MODULES.map((m) => m.id),
  )
  const [maxDepth, setMaxDepth] = useState("10")
  const [maxConcurrency, setMaxConcurrency] = useState("5")
  const [showAdvanced, setShowAdvanced] = useState(false)
  const [isSubmitting, setIsSubmitting] = useState(false)

  useEffect(() => {
    if (open) {
      targetsService
        .getTargets()
        .then((items) => {
          setTargetOptions(items)
          // Intentionally do NOT auto-select the first target to require deliberate user selection
          setSelectedTarget("")
        })
        .catch(() => {})
    }
  }, [open])

  const isTargetValid =
    targetMode === "preconfigured"
      ? Boolean(selectedTarget)
      : Boolean(manualUrl.trim()) && authorizedConfirmation

  function toggleModule(moduleId: string) {
    setSelectedModules((prev) =>
      prev.includes(moduleId)
        ? prev.filter((m) => m !== moduleId)
        : [...prev, moduleId],
    )
  }

  function validateManualUrl(input: string): { valid: boolean; normalized: string; error?: string } {
    const raw = input.trim()
    if (!raw) {
      return { valid: false, normalized: "", error: "Target URL cannot be empty." }
    }
    let urlStr = raw
    if (!urlStr.startsWith("http://") && !urlStr.startsWith("https://")) {
      urlStr = `https://${urlStr}`
    }
    try {
      const parsed = new URL(urlStr)
      if (!parsed.hostname || !parsed.hostname.includes(".") && parsed.hostname !== "localhost") {
        return { valid: false, normalized: urlStr, error: "Please enter a valid domain or IP address." }
      }
      return { valid: true, normalized: urlStr }
    } catch {
      return { valid: false, normalized: urlStr, error: "Invalid URL syntax." }
    }
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setIsSubmitting(true)
    try {
      let targetObj: Target | undefined

      if (targetMode === "manual") {
        const urlValidation = validateManualUrl(manualUrl)
        if (!urlValidation.valid) {
          toast.error(urlValidation.error || "Please enter a valid HTTP/HTTPS URL.")
          setIsSubmitting(false)
          return
        }
        if (!authorizedConfirmation) {
          toast.error("Please confirm that you have authorization to scan this website.")
          setIsSubmitting(false)
          return
        }

        // Register custom target under the user's project or reuse existing
        const resolved = await scansService.getOrCreateTargetForUrl(urlValidation.normalized)
        targetObj = resolved.target
      } else {
        if (!selectedTarget) {
          toast.error("Please select a preconfigured target or switch to Manual URL.")
          setIsSubmitting(false)
          return
        }
        targetObj = targetOptions.find((t) => t.id === selectedTarget)
      }

      if (!targetObj) {
        toast.error("Unable to resolve assessment target.")
        setIsSubmitting(false)
        return
      }

      const newScan = await scansService.createScan(targetObj.projectId, targetObj.id, {
        scanType: selectedType,
        targetUrl: targetObj.url,
        targetId: targetObj.id,
        config: {
          targetUrl: targetObj.url,
          modules: selectedModules,
          maxDepth: parseInt(maxDepth, 10) || 10,
          maxConcurrency: parseInt(maxConcurrency, 10) || 5,
        },
      })

      // Trigger Scanner Engine execution against target
      await scansService.startScan(newScan.id)

      toast.success(`Assessment started on ${targetObj.url}`)
      handleReset()
      onClose()
      window.dispatchEvent(
        new CustomEvent("awsap:scan_created", { detail: { scanId: newScan.id } }),
      )
    } catch (err: any) {
      console.error("Failed to create scan:", err)
      toast.error(err?.message || "Failed to initiate scan on server")
    } finally {
      setIsSubmitting(false)
    }
  }

  function handleReset() {
    setSelectedType("full")
    setTargetMode("preconfigured")
    setSelectedTarget("")
    setManualUrl("")
    setAuthorizedConfirmation(false)
    setSelectedModules(AVAILABLE_MODULES.map((m) => m.id))
    setMaxDepth("10")
    setMaxConcurrency("5")
    setShowAdvanced(false)
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
      <DialogContent className="sm:max-w-[600px] max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Configure New Scan</DialogTitle>
          <DialogDescription>
            Set up scan parameters and select modules to execute against your target.
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleSubmit} className="space-y-5">
          {/* Scan Type */}
          <div className="space-y-2">
            <Label>Scan Type</Label>
            <div className="grid grid-cols-2 gap-2">
              {scanTypes.map((st) => (
                <button
                  key={st.value}
                  type="button"
                  onClick={() => setSelectedType(st.value)}
                  className={cn(
                    "flex items-start gap-3 rounded-lg border-2 p-3 text-left transition-all",
                    selectedType === st.value
                      ? "border-primary bg-primary/5"
                      : "border-border bg-card hover:border-muted-foreground/30",
                  )}
                >
                  <div
                    className={cn(
                      "flex h-9 w-9 shrink-0 items-center justify-center rounded-lg",
                      selectedType === st.value
                        ? "bg-primary/15"
                        : "bg-muted",
                    )}
                  >
                    <st.icon
                      className={cn(
                        "h-4 w-4",
                        selectedType === st.value
                          ? "text-primary"
                          : "text-muted-foreground",
                      )}
                    />
                  </div>
                  <div className="min-w-0">
                    <p
                      className={cn(
                        "text-sm font-semibold",
                        selectedType === st.value
                          ? "text-foreground"
                          : "text-foreground",
                      )}
                    >
                      {st.label}
                    </p>
                    <p className="mt-0.5 text-[11px] leading-tight text-muted-foreground">
                      {st.description}
                    </p>
                    <div className="mt-1 flex items-center gap-2 text-[10px] text-muted-foreground">
                      <span>{st.modules}</span>
                      <span>·</span>
                      <span>~{st.estimatedTime}</span>
                    </div>
                  </div>
                </button>
              ))}
            </div>
          </div>

          {/* Target Selection Mode Toggle & Inputs */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <Label className="text-xs font-semibold">Assessment Target</Label>
              <div className="flex rounded-lg border border-border bg-muted/40 p-0.5 text-xs">
                <button
                  type="button"
                  onClick={() => setTargetMode("preconfigured")}
                  className={cn(
                    "flex items-center gap-1.5 rounded-md px-2.5 py-1 font-medium transition-colors",
                    targetMode === "preconfigured"
                      ? "bg-card text-foreground shadow-xs"
                      : "text-muted-foreground hover:text-foreground",
                  )}
                >
                  <FlaskConical className="h-3.5 w-3.5" />
                  Preconfigured Labs
                </button>
                <button
                  type="button"
                  onClick={() => setTargetMode("manual")}
                  className={cn(
                    "flex items-center gap-1.5 rounded-md px-2.5 py-1 font-medium transition-colors",
                    targetMode === "manual"
                      ? "bg-card text-foreground shadow-xs"
                      : "text-muted-foreground hover:text-foreground",
                  )}
                >
                  <Link2 className="h-3.5 w-3.5" />
                  Manual URL
                </button>
              </div>
            </div>

            {targetMode === "preconfigured" ? (
              <div className="space-y-2">
                {targetOptions.length === 0 ? (
                  <p className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-2.5 text-xs text-amber-300">
                    No registered targets available. Switch to <strong>Manual URL</strong> to scan an authorized website.
                  </p>
                ) : (
                  <>
                    <select
                      id="scan-target"
                      value={selectedTarget}
                      onChange={(e) => setSelectedTarget(e.target.value)}
                      className="flex h-9 w-full rounded-md border border-input bg-card px-3 py-1 font-mono text-xs shadow-xs transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                      required={targetMode === "preconfigured"}
                    >
                      <option value="">Choose an assessment target from library…</option>
                      <optgroup label="── Vulnerable Labs & Security Benchmarks ──">
                        {targetOptions
                          .filter((t) =>
                            t.url.includes("vulnweb.com") ||
                            t.url.includes("testfire.net") ||
                            t.url.includes("juice-shop"),
                          )
                          .map((t) => (
                            <option key={t.id} value={t.id}>
                              {t.url} [BENCHMARK LAB]
                            </option>
                          ))}
                      </optgroup>
                      <optgroup label="── Registered Project Targets ──">
                        {targetOptions
                          .filter(
                            (t) =>
                              !t.url.includes("vulnweb.com") &&
                              !t.url.includes("testfire.net") &&
                              !t.url.includes("juice-shop"),
                          )
                          .map((t) => (
                            <option key={t.id} value={t.id}>
                              {t.url} ({t.type.toUpperCase()})
                            </option>
                          ))}
                      </optgroup>
                    </select>

                    {selectedTarget && (
                      <div className="flex items-center justify-between rounded-lg bg-muted/40 px-3 py-1.5 text-[11px] font-mono text-muted-foreground">
                        <span className="truncate">
                          Target URL:{" "}
                          <strong className="text-foreground">
                            {targetOptions.find((t) => t.id === selectedTarget)?.url}
                          </strong>
                        </span>
                        <span className="flex items-center gap-1 text-emerald-400 shrink-0 font-sans text-[10px] font-medium">
                          <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
                          Ready
                        </span>
                      </div>
                    )}
                  </>
                )}
              </div>
            ) : (
              <div className="space-y-2.5">
                <div className="space-y-1">
                  <Input
                    type="url"
                    placeholder="https://example.com or http://target-app.local"
                    value={manualUrl}
                    onChange={(e) => setManualUrl(e.target.value)}
                    className="font-mono text-xs h-9 bg-card"
                    required={targetMode === "manual"}
                  />
                  <p className="text-[11px] text-muted-foreground">
                    Paste the exact HTTP or HTTPS URL of the application you are authorized to assess.
                  </p>
                </div>

                {manualUrl.trim() && (
                  <div className="rounded-lg border border-border/80 bg-muted/30 p-2.5 space-y-1.5 text-xs">
                    <div className="flex items-center justify-between font-mono text-[11px]">
                      <span className="text-muted-foreground">Normalized Target:</span>
                      <span className="font-bold text-foreground">
                        {validateManualUrl(manualUrl).normalized || manualUrl}
                      </span>
                    </div>
                    {validateManualUrl(manualUrl).error && (
                      <p className="text-[11px] text-red-400">
                        {validateManualUrl(manualUrl).error}
                      </p>
                    )}
                  </div>
                )}

                <label className="flex items-start gap-2 pt-1 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={authorizedConfirmation}
                    onChange={(e) => setAuthorizedConfirmation(e.target.checked)}
                    className="mt-0.5 rounded border-border text-primary focus:ring-primary"
                    required={targetMode === "manual"}
                  />
                  <span className="text-[11px] leading-tight text-muted-foreground">
                    I confirm that I own this website or have explicit authorization to perform security testing.
                    Non-destructive passive and controlled active probes will be conducted.
                  </span>
                </label>
              </div>
            )}
          </div>

          <Separator />

          {/* Module selection (for targeted scans) */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <Label>Scan Modules</Label>
              <span className="text-[11px] text-muted-foreground">
                {selectedModules.length}/{AVAILABLE_MODULES.length} selected
              </span>
            </div>
            <div className="grid grid-cols-2 gap-1.5">
              {AVAILABLE_MODULES.map((mod) => {
                const isSelected = selectedModules.includes(mod.id)
                return (
                  <button
                    key={mod.id}
                    type="button"
                    onClick={() => toggleModule(mod.id)}
                    className={cn(
                      "flex items-center gap-2 rounded-lg border px-3 py-2 text-left transition-all",
                      isSelected
                        ? "border-primary/30 bg-primary/5"
                        : "border-border bg-card hover:bg-muted/30",
                    )}
                  >
                    <div
                      className={cn(
                        "flex h-5 w-5 shrink-0 items-center justify-center rounded border transition-colors",
                        isSelected
                          ? "border-primary bg-primary"
                          : "border-muted-foreground/30",
                      )}
                    >
                      {isSelected && (
                        <Check className="h-3 w-3 text-primary-foreground" />
                      )}
                    </div>
                    <div className="min-w-0">
                      <p className="truncate text-xs font-medium text-foreground">
                        {mod.name}
                      </p>
                      <p className="truncate text-[10px] text-muted-foreground">
                        {mod.description}
                      </p>
                    </div>
                  </button>
                )
              })}
            </div>
          </div>

          {/* Advanced settings */}
          <div>
            <button
              type="button"
              onClick={() => setShowAdvanced(!showAdvanced)}
              className="flex items-center gap-1.5 text-xs font-medium text-muted-foreground transition-colors hover:text-foreground"
            >
              {showAdvanced ? (
                <ChevronUp className="h-3.5 w-3.5" />
              ) : (
                <ChevronDown className="h-3.5 w-3.5" />
              )}
              Advanced Settings
            </button>

            {showAdvanced && (
              <div className="mt-3 grid grid-cols-2 gap-3">
                <div className="space-y-1.5">
                  <Label htmlFor="max-depth" className="text-xs">
                    Max Crawl Depth
                  </Label>
                  <Input
                    id="max-depth"
                    type="number"
                    min={1}
                    max={50}
                    value={maxDepth}
                    onChange={(e) => setMaxDepth(e.target.value)}
                  />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="max-concurrency" className="text-xs">
                    Max Concurrency
                  </Label>
                  <Input
                    id="max-concurrency"
                    type="number"
                    min={1}
                    max={20}
                    value={maxConcurrency}
                    onChange={(e) => setMaxConcurrency(e.target.value)}
                  />
                </div>
              </div>
            )}
          </div>

          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>
              Cancel
            </Button>
            <Button
              type="submit"
              disabled={!isTargetValid || selectedModules.length === 0 || isSubmitting}
            >
              {isSubmitting ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Launching…
                </>
              ) : (
                <>
                  <Play className="h-4 w-4" />
                  Start Scan
                </>
              )}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
