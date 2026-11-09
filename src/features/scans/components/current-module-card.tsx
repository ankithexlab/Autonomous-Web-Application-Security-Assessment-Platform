import { motion } from "framer-motion"
import { Radar, Loader2, CheckCircle2, AlertCircle, ShieldAlert, Cpu } from "lucide-react"
import { cn } from "@/utils"
import type { ScanEngineReturn } from "../hooks/use-scan-engine"

interface CurrentModuleCardProps {
  engine: ScanEngineReturn
}

export function CurrentModuleCard({ engine }: CurrentModuleCardProps) {
  const isRunning = engine.status === "running"
  const isPaused = engine.status === "paused"
  const isQueued = engine.status === "queued"
  const isCompleted = engine.status === "completed"
  const isCancelled = engine.status === "cancelled"
  const isFailed = engine.status === "failed"

  const activeModule = engine.activeModules.find((m) => m.status === "running") ||
    (isCompleted ? engine.activeModules[engine.activeModules.length - 1] : null)

  const activeIdx = activeModule
    ? engine.activeModules.findIndex((m) => m.id === activeModule.id)
    : 0

  return (
    <div className="relative overflow-hidden rounded-2xl border border-primary/20 bg-gradient-to-br from-card via-card to-primary/[0.04] p-5 shadow-md">
      {/* Background Cyber Glow / Radar Effect */}
      <div className="pointer-events-none absolute -right-12 -top-12 h-48 w-48 rounded-full bg-primary/10 blur-3xl" />
      {isRunning && (
        <div className="pointer-events-none absolute right-6 top-6 h-20 w-20 opacity-20">
          <motion.div
            className="h-full w-full rounded-full border-2 border-primary border-t-transparent"
            animate={{ rotate: 360 }}
            transition={{ duration: 3, repeat: Infinity, ease: "linear" }}
          />
        </div>
      )}

      {/* Header Badge & Counter */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="flex h-7 w-7 items-center justify-center rounded-lg bg-primary/15 text-primary">
            <Cpu className="h-4 w-4" />
          </span>
          <span className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
            Current Scanning Module
          </span>
        </div>

        {engine.activeModules.length > 0 && (
          <span className="rounded-full bg-muted/60 px-2.5 py-0.5 font-mono text-[11px] font-semibold text-foreground">
            Module {Math.min(activeIdx + 1, engine.activeModules.length)} of {engine.activeModules.length}
          </span>
        )}
      </div>

      {/* Active Module Content */}
      <div className="mt-4">
        {isQueued && (
          <div className="flex items-center gap-3 py-2 text-muted-foreground">
            <Loader2 className="h-5 w-5 animate-spin text-primary" />
            <div>
              <p className="text-sm font-semibold text-foreground">Initializing Scan Engine</p>
              <p className="text-xs">Preparing sandbox and allocation scanner slots...</p>
            </div>
          </div>
        )}

        {isCompleted && (
          <div className="flex items-center gap-3 py-2 text-emerald-400">
            <CheckCircle2 className="h-6 w-6 shrink-0" />
            <div>
              <p className="text-base font-bold text-foreground">Scan Pipeline Completed</p>
              <p className="text-xs text-muted-foreground">
                All {engine.activeModules.length} modules executed successfully with {engine.totalFindingsCount} vulnerability finding(s).
              </p>
            </div>
          </div>
        )}

        {isCancelled && (
          <div className="flex items-center gap-3 py-2 text-red-400">
            <AlertCircle className="h-6 w-6 shrink-0" />
            <div>
              <p className="text-base font-bold text-foreground">Scan Terminated</p>
              <p className="text-xs text-muted-foreground">Execution was stopped prior to pipeline completion.</p>
            </div>
          </div>
        )}

        {isFailed && (
          <div className="flex items-center gap-3 py-2 text-red-400">
            <AlertCircle className="h-6 w-6 shrink-0" />
            <div>
              <p className="text-base font-bold text-foreground">Scan Execution Failed</p>
              <p className="text-xs text-muted-foreground">The scanner engine encountered an unhandled error or target reachability issue.</p>
            </div>
          </div>
        )}

        {engine.status === "idle" && (
          <div className="flex items-center gap-3 py-4 text-muted-foreground">
            <Radar className="h-7 w-7 opacity-50" />
            <div>
              <p className="text-sm font-semibold text-foreground">Engine Ready</p>
              <p className="text-xs text-muted-foreground">Select scan configuration and click "Start Security Scan".</p>
            </div>
          </div>
        )}

        {activeModule && (isRunning || isPaused) && (
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <h4 className="text-lg font-bold tracking-tight text-foreground flex items-center gap-2">
                  {activeModule.name}
                  {isRunning && (
                    <span className="flex h-2 w-2 rounded-full bg-blue-400 animate-ping" />
                  )}
                </h4>
                <p className="text-xs text-muted-foreground">{activeModule.description}</p>
              </div>
              <div className="text-right">
                <span className="text-2xl font-extrabold tabular-nums text-primary">
                  {activeModule.progress}%
                </span>
              </div>
            </div>

            {/* Active Subtask & Endpoint */}
            <div className="rounded-xl border border-border/60 bg-muted/30 p-3 space-y-1.5 font-mono text-xs">
              <div className="flex items-center gap-2 text-primary font-medium">
                <Loader2 className={cn("h-3.5 w-3.5", isRunning && "animate-spin")} />
                <span className="truncate">{engine.activeSubtask || "Executing vulnerability suite..."}</span>
              </div>
              {engine.currentEndpoint && (
                <div className="flex items-center gap-2 text-[11px] text-muted-foreground">
                  <span className="text-muted-foreground/60">Target:</span>
                  <span className="truncate text-foreground/80">{engine.currentEndpoint}</span>
                </div>
              )}
            </div>

            {/* Progress Bar */}
            <div className="space-y-1">
              <div className="h-2.5 w-full overflow-hidden rounded-full bg-muted/60">
                <motion.div
                  className="h-full rounded-full bg-gradient-to-r from-blue-500 via-indigo-500 to-violet-500"
                  initial={{ width: 0 }}
                  animate={{ width: `${activeModule.progress}%` }}
                  transition={{ duration: 0.5, ease: "easeOut" }}
                />
              </div>
              <div className="flex items-center justify-between text-[10px] text-muted-foreground">
                <span>Active concurrency: {engine.activeThreads} threads</span>
                {activeModule.findingsCount > 0 && (
                  <span className="flex items-center gap-1 text-amber-400 font-semibold">
                    <ShieldAlert className="h-3 w-3" />
                    {activeModule.findingsCount} issue(s) found in this module
                  </span>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
