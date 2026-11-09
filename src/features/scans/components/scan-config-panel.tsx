import { useState } from "react"
import { motion, AnimatePresence } from "framer-motion"
import {
  Radar,
  Zap,
  Crosshair,
  RefreshCw,
  Play,
  StopCircle,
  RotateCcw,
  Sliders,
  Check,
  ChevronDown,
  ChevronUp,
  Globe,
  Sparkles,
  Shield,
  Layers,
  Key,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Badge } from "@/components/ui/badge"
import { Separator } from "@/components/ui/separator"
import { cn } from "@/utils"
import type { ScanEngineReturn } from "../hooks/use-scan-engine"
import type { ScanType } from "@/types"

interface ScanConfigPanelProps {
  engine: ScanEngineReturn
}

const SCAN_TYPES: {
  value: ScanType
  label: string
  desc: string
  icon: typeof Radar
  badge: string
}[] = [
  {
    value: "full",
    label: "Full Scan",
    desc: "Exhaustive audit across all vulnerability vectors",
    icon: Radar,
    badge: "Recommended",
  },
  {
    value: "quick",
    label: "Quick Audit",
    desc: "Fast check for surface vulnerabilities & headers",
    icon: Zap,
    badge: "5 mins",
  },
  {
    value: "targeted",
    label: "Targeted",
    desc: "Focus on specific selected security modules",
    icon: Crosshair,
    badge: "Custom",
  },
  {
    value: "continuous",
    label: "Continuous",
    desc: "Ongoing monitoring with periodic re-scanning",
    icon: RefreshCw,
    badge: "Recurring",
  },
]

export function ScanConfigPanel({ engine }: ScanConfigPanelProps) {
  const [showAdvanced, setShowAdvanced] = useState(false)
  const isRunning = engine.status === "running"
  const isPaused = engine.status === "paused"
  const isExecuting = isRunning || isPaused || engine.status === "queued"

  return (
    <div className="flex flex-col gap-5 rounded-2xl border border-border/80 bg-card p-5 shadow-sm">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-primary/10 text-primary">
            <Sliders className="h-4 w-4" />
          </div>
          <div>
            <h3 className="text-base font-bold tracking-tight text-foreground">
              Scan Configurator
            </h3>
            <p className="text-xs text-muted-foreground">
              Configure parameters, modules, and target profile
            </p>
          </div>
        </div>
        <Badge
          variant={isExecuting ? "default" : "outline"}
          className={cn(
            "text-[10px] font-semibold uppercase tracking-wider",
            isExecuting && "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
          )}
        >
          {engine.status}
        </Badge>
      </div>

      {/* Target URL Selector & Input */}
      <div className="space-y-2.5">
        <div className="flex items-center justify-between">
          <Label className="flex items-center gap-1.5 text-xs font-semibold">
            <Globe className="h-3.5 w-3.5 text-primary" />
            Assessment Target
          </Label>
          <span className="text-[10px] text-muted-foreground font-mono">
            {engine.selectedTargetUrl ? "Target Configured" : "Select or Enter Target"}
          </span>
        </div>

        {/* Target input & dropdown row */}
        <div className="space-y-2">
          <div className="flex flex-col sm:flex-row gap-2">
            <div className="relative flex-1">
              <Input
                type="text"
                placeholder="Enter URL (e.g. https://example.com) or pick below..."
                value={engine.selectedTargetUrl}
                onChange={(e) => {
                  engine.setSelectedTargetUrl(e.target.value)
                }}
                disabled={isExecuting}
                className="font-mono text-xs h-9 bg-card"
              />
            </div>
            {engine.targets.length > 0 && (
              <select
                value={engine.selectedTargetId}
                onChange={(e) => {
                  const targetId = e.target.value
                  if (targetId) {
                    engine.setSelectedTargetId(targetId)
                  } else {
                    engine.setSelectedTargetId("")
                  }
                }}
                disabled={isExecuting}
                className="h-9 rounded-md border border-input bg-card px-3 py-1 font-mono text-xs shadow-xs transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring sm:max-w-[210px]"
              >
                <option value="">
                  {engine.selectedTargetId ? "Custom manual URL…" : `Registered targets (${engine.targets.length})…`}
                </option>
                {engine.targets.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.url.replace(/^https?:\/\//, "")}
                  </option>
                ))}
              </select>
            )}
          </div>

          {engine.selectedTargetUrl && (
            <div className="flex items-center justify-between rounded-lg bg-muted/40 px-3 py-1.5 text-[11px] font-mono text-muted-foreground">
              <span className="truncate">{engine.selectedTargetUrl}</span>
              <span className="flex items-center gap-1 text-emerald-400 shrink-0 font-sans text-[10px] font-medium">
                <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
                {engine.selectedTargetId ? "Registered Target" : "Manual Custom Target"}
              </span>
            </div>
          )}
        </div>

        {/* Quick Vulnerable Benchmark Targets */}
        <div className="space-y-1.5 pt-0.5">
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-semibold text-muted-foreground">
              Quick Test Targets:
            </span>
            {engine.targets.length === 0 && (
              <button
                type="button"
                onClick={() => engine.loadDefaultTargets()}
                className="text-[10px] text-primary hover:underline flex items-center gap-1"
              >
                <RefreshCw className="h-2.5 w-2.5" /> Reload Targets
              </button>
            )}
          </div>
          <div className="flex flex-wrap items-center gap-1.5">
            {[
              { label: "testphp.vulnweb (PHP Lab)", url: "http://testphp.vulnweb.com" },
              { label: "testhtml5.vulnweb (HTML5 Lab)", url: "http://testhtml5.vulnweb.com" },
              { label: "demo.testfire (Banking Lab)", url: "http://demo.testfire.net" },
            ].map((item) => (
              <button
                key={item.url}
                type="button"
                disabled={isExecuting}
                onClick={() => {
                  engine.setSelectedTargetUrl(item.url)
                }}
                className={cn(
                  "rounded-md border px-2 py-0.5 font-mono text-[10px] transition-all",
                  engine.selectedTargetUrl === item.url
                    ? "border-primary bg-primary/15 text-primary font-bold shadow-xs"
                    : "border-border/60 bg-muted/40 text-muted-foreground hover:border-border hover:text-foreground",
                )}
              >
                ⚡ {item.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Quick Scan Presets */}
      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <Label className="flex items-center gap-1.5 text-xs font-semibold">
            <Sparkles className="h-3.5 w-3.5 text-amber-400" />
            Audit Presets
          </Label>
          <span className="text-[10px] text-muted-foreground">One-click templates</span>
        </div>
        <div className="grid grid-cols-2 gap-2">
          {engine.SCAN_PRESETS.map((preset) => (
            <button
              key={preset.id}
              type="button"
              disabled={isExecuting}
              onClick={() => engine.applyPreset(preset)}
              className="group flex flex-col items-start rounded-xl border border-border/70 bg-card/60 p-2.5 text-left transition-all hover:border-primary/40 hover:bg-primary/[0.03] disabled:opacity-50"
            >
              <div className="flex w-full items-center justify-between">
                <span className="text-xs font-bold text-foreground group-hover:text-primary transition-colors">
                  {preset.name}
                </span>
                <span className="rounded bg-muted px-1.5 py-0.5 text-[9px] font-mono text-muted-foreground">
                  ~{preset.estimatedMinutes}m
                </span>
              </div>
              <span className="mt-1 line-clamp-1 text-[10px] text-muted-foreground">
                {preset.description}
              </span>
            </button>
          ))}
        </div>
      </div>

      {/* Scan Type Cards */}
      <div className="space-y-2">
        <Label className="text-xs font-semibold">Scan Profile</Label>
        <div className="grid grid-cols-2 gap-2">
          {SCAN_TYPES.map((st) => {
            const Icon = st.icon
            const isSelected = engine.scanType === st.value
            return (
              <button
                key={st.value}
                type="button"
                disabled={isExecuting}
                onClick={() => engine.setScanType(st.value)}
                className={cn(
                  "flex items-start gap-2.5 rounded-xl border-2 p-3 text-left transition-all",
                  isSelected
                    ? "border-primary bg-primary/5 shadow-xs"
                    : "border-border/60 bg-card hover:border-muted-foreground/30",
                )}
              >
                <div
                  className={cn(
                    "flex h-8 w-8 shrink-0 items-center justify-center rounded-lg transition-colors",
                    isSelected ? "bg-primary text-primary-foreground" : "bg-muted text-muted-foreground",
                  )}
                >
                  <Icon className="h-4 w-4" />
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-foreground">{st.label}</span>
                  </div>
                  <p className="mt-0.5 text-[10px] leading-tight text-muted-foreground line-clamp-2">
                    {st.desc}
                  </p>
                </div>
              </button>
            )
          })}
        </div>
      </div>

      <Separator />

      {/* Module Selection Checklist */}
      <div className="space-y-2.5">
        <div className="flex items-center justify-between">
          <Label className="flex items-center gap-1.5 text-xs font-semibold">
            <Layers className="h-3.5 w-3.5 text-primary" />
            Security Modules
          </Label>
          <div className="flex items-center gap-2">
            <button
              type="button"
              disabled={isExecuting}
              onClick={engine.selectAllModules}
              className="text-[10px] font-semibold text-primary hover:underline disabled:opacity-50"
            >
              Select All
            </button>
            <span className="text-[10px] text-muted-foreground">·</span>
            <button
              type="button"
              disabled={isExecuting}
              onClick={engine.deselectAllModules}
              className="text-[10px] font-semibold text-muted-foreground hover:text-foreground disabled:opacity-50"
            >
              Clear
            </button>
            <Badge variant="secondary" className="ml-1 text-[10px] font-bold">
              {engine.selectedModuleIds.length}/{engine.AVAILABLE_MODULES.length}
            </Badge>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-1.5 max-h-56 overflow-y-auto pr-1">
          {engine.AVAILABLE_MODULES.map((mod) => {
            const isSelected = engine.selectedModuleIds.includes(mod.id)
            return (
              <button
                key={mod.id}
                type="button"
                disabled={isExecuting}
                onClick={() => engine.toggleModule(mod.id)}
                className={cn(
                  "flex items-center gap-2 rounded-lg border p-2 text-left transition-all",
                  isSelected
                    ? "border-primary/40 bg-primary/5 text-foreground"
                    : "border-border/50 bg-card/50 opacity-60 hover:opacity-100",
                )}
              >
                <div
                  className={cn(
                    "flex h-4 w-4 shrink-0 items-center justify-center rounded border text-xs transition-colors",
                    isSelected
                      ? "border-primary bg-primary text-primary-foreground"
                      : "border-muted-foreground/30",
                  )}
                >
                  {isSelected && <Check className="h-3 w-3" />}
                </div>
                <div className="min-w-0 flex-1">
                  <p className="truncate text-xs font-medium">{mod.name}</p>
                </div>
              </button>
            )
          })}
        </div>
      </div>

      {/* Advanced Parameters Collapsible */}
      <div className="rounded-xl border border-border/60 bg-muted/20 p-3">
        <button
          type="button"
          onClick={() => setShowAdvanced(!showAdvanced)}
          className="flex w-full items-center justify-between text-xs font-semibold text-foreground"
        >
          <span className="flex items-center gap-1.5">
            <Shield className="h-3.5 w-3.5 text-primary" />
            Advanced Engine Parameters
          </span>
          {showAdvanced ? (
            <ChevronUp className="h-3.5 w-3.5 text-muted-foreground" />
          ) : (
            <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" />
          )}
        </button>

        <AnimatePresence>
          {showAdvanced && (
            <motion.div
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: "auto", opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              transition={{ duration: 0.2 }}
              className="mt-3 space-y-3 pt-2 border-t border-border/40"
            >
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <Label className="text-[11px] text-muted-foreground">Max Crawl Depth</Label>
                  <Input
                    type="number"
                    min={1}
                    max={50}
                    value={engine.maxDepth}
                    onChange={(e) => engine.setMaxDepth(Number(e.target.value))}
                    disabled={isExecuting}
                    className="h-8 text-xs font-mono"
                  />
                </div>
                <div className="space-y-1">
                  <Label className="text-[11px] text-muted-foreground">Concurrency Threads</Label>
                  <Input
                    type="number"
                    min={1}
                    max={20}
                    value={engine.maxConcurrency}
                    onChange={(e) => engine.setMaxConcurrency(Number(e.target.value))}
                    disabled={isExecuting}
                    className="h-8 text-xs font-mono"
                  />
                </div>
              </div>

              <div className="space-y-1">
                <Label className="text-[11px] text-muted-foreground flex items-center gap-1">
                  <Key className="h-3 w-3" />
                  Custom Auth Header (Optional)
                </Label>
                <Input
                  value={engine.authHeader}
                  onChange={(e) => engine.setAuthHeader(e.target.value)}
                  placeholder="Bearer eyJhbGci..."
                  disabled={isExecuting}
                  className="h-8 text-xs font-mono"
                />
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* Main Start / Control Action Bar */}
      <div className="pt-2">
        {!isExecuting && (
          <Button
            size="lg"
            onClick={engine.startScan}
            disabled={engine.selectedModuleIds.length === 0 || !engine.selectedTargetUrl?.trim()}
            className="w-full gap-2 rounded-xl bg-gradient-to-r from-blue-600 via-indigo-600 to-violet-600 py-6 text-sm font-bold shadow-md hover:from-blue-500 hover:to-violet-500 active:scale-[0.99] disabled:opacity-50"
          >
            <Play className="h-4 w-4 fill-current" />
            Start Security Scan
          </Button>
        )}

        {isExecuting && (
          <div className="flex gap-2">
            <Button
              variant="destructive"
              size="lg"
              onClick={engine.stopScan}
              className="w-full gap-2 rounded-xl py-6 font-bold shadow-md"
            >
              <StopCircle className="h-4 w-4" />
              Stop / Cancel Active Scan
            </Button>
          </div>
        )}

        {(engine.status === "completed" || engine.status === "cancelled" || engine.status === "failed") && (
          <Button
            variant="outline"
            size="lg"
            onClick={engine.resetScan}
            className="w-full mt-2 gap-2"
          >
            <RotateCcw className="h-4 w-4" />
            Reset & Reconfigure
          </Button>
        )}
      </div>
    </div>
  )
}
