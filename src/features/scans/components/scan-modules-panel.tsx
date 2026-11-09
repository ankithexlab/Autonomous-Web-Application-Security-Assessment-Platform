/**
 * Scan Modules Panel — displays all scanner modules organized by category
 * with status indicators, finding counts, and timing information.
 */

import { useState } from "react"
import { motion, AnimatePresence } from "framer-motion"
import {
  Globe, Search, Server, Cpu, FolderSearch, Shield, Key, ShieldCheck,
  Lock, ShieldAlert, KeyRound, Syringe, AlertTriangle, Settings, Package,
  UserX, FileCheck, FileWarning, Unlink, Database, Code, ShieldOff, Hash,
  ExternalLink, Terminal, Plug, Upload, Gauge, ChevronDown, ChevronRight,
  CheckCircle2, XCircle, Clock, Loader2, SkipForward, type LucideIcon,
} from "lucide-react"
import type { ScanModule } from "@/types"
import { MODULE_CATEGORIES } from "../data/scanner-modules-data"

/* ── Icon Map ── */
const ICON_MAP: Record<string, LucideIcon> = {
  Globe, Search, Server, Cpu, FolderSearch, Shield, Key, ShieldCheck,
  Lock, ShieldAlert, KeyRound, Syringe, AlertTriangle, Settings, Package,
  UserX, FileCheck, FileWarning, Unlink, Database, Code, ShieldOff, Hash,
  ExternalLink, Terminal, Plug, Upload, Gauge, Cookie: Key, KeySquare: Key,
}

/* ── Module Category Colors ── */
const CATEGORY_COLORS: Record<string, { bg: string; text: string; border: string }> = {
  "Information Gathering": { bg: "bg-blue-500/10", text: "text-blue-400", border: "border-blue-500/20" },
  "Security Analysis": { bg: "bg-emerald-500/10", text: "text-emerald-400", border: "border-emerald-500/20" },
  "OWASP Top 10": { bg: "bg-amber-500/10", text: "text-amber-400", border: "border-amber-500/20" },
  "Vulnerability Detection": { bg: "bg-rose-500/10", text: "text-rose-400", border: "border-rose-500/20" },
}

/* ── Status Badge ── */
function StatusBadge({ status }: { status: ScanModule["status"] }) {
  const config = {
    completed: { icon: CheckCircle2, text: "Completed", className: "text-emerald-400 bg-emerald-400/10" },
    running: { icon: Loader2, text: "Running", className: "text-blue-400 bg-blue-400/10" },
    pending: { icon: Clock, text: "Pending", className: "text-zinc-400 bg-zinc-400/10" },
    failed: { icon: XCircle, text: "Failed", className: "text-rose-400 bg-rose-400/10" },
    skipped: { icon: SkipForward, text: "Skipped", className: "text-zinc-500 bg-zinc-500/10" },
  }
  const { icon: Icon, text, className } = config[status]
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium ${className}`}>
      <Icon className={`h-3 w-3 ${status === "running" ? "animate-spin" : ""}`} />
      {text}
    </span>
  )
}

/* ── Module Card ── */
function ModuleCard({ module, categoryColor }: { module: ScanModule; categoryColor: string }) {
  const [expanded, setExpanded] = useState(false)
  const ModIcon = ICON_MAP[module.name] || Cpu

  return (
    <motion.div
      layout
      className={`rounded-xl border border-zinc-800 bg-zinc-900/50 backdrop-blur-sm overflow-hidden transition-colors hover:border-zinc-700`}
    >
      <button
        onClick={() => setExpanded(!expanded)}
        className="flex w-full items-center justify-between gap-3 p-4 text-left"
      >
        <div className="flex items-center gap-3 min-w-0">
          <div className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-lg ${categoryColor}`}>
            <ModIcon className="h-4 w-4" />
          </div>
          <div className="min-w-0">
            <p className="text-sm font-medium text-zinc-100 truncate">{module.name}</p>
            <p className="text-xs text-zinc-500 truncate">{module.description}</p>
          </div>
        </div>
        <div className="flex items-center gap-3 shrink-0">
          {module.findingsCount > 0 && (
            <span className="flex h-6 min-w-6 items-center justify-center rounded-full bg-rose-500/15 px-2 text-xs font-semibold text-rose-400">
              {module.findingsCount}
            </span>
          )}
          <StatusBadge status={module.status} />
          {expanded ? (
            <ChevronDown className="h-4 w-4 text-zinc-500" />
          ) : (
            <ChevronRight className="h-4 w-4 text-zinc-500" />
          )}
        </div>
      </button>

      <AnimatePresence>
        {expanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="border-t border-zinc-800"
          >
            <div className="grid grid-cols-2 gap-4 p-4 sm:grid-cols-4">
              <div>
                <p className="text-[11px] font-medium uppercase tracking-wider text-zinc-500">Progress</p>
                <div className="mt-1.5 flex items-center gap-2">
                  <div className="h-1.5 flex-1 rounded-full bg-zinc-800">
                    <div
                      className="h-full rounded-full bg-gradient-to-r from-blue-500 to-cyan-400 transition-all"
                      style={{ width: `${module.progress}%` }}
                    />
                  </div>
                  <span className="text-xs font-medium text-zinc-300">{module.progress}%</span>
                </div>
              </div>
              <div>
                <p className="text-[11px] font-medium uppercase tracking-wider text-zinc-500">Duration</p>
                <p className="mt-1 text-sm font-medium text-zinc-200">{module.duration || "—"}</p>
              </div>
              <div>
                <p className="text-[11px] font-medium uppercase tracking-wider text-zinc-500">Started</p>
                <p className="mt-1 text-sm text-zinc-300">
                  {module.startedAt ? new Date(module.startedAt).toLocaleTimeString() : "—"}
                </p>
              </div>
              <div>
                <p className="text-[11px] font-medium uppercase tracking-wider text-zinc-500">Findings</p>
                <p className="mt-1 text-sm font-semibold text-zinc-200">{module.findingsCount}</p>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  )
}

/* ── Main Component ── */
export function ScanModulesPanel({ modules }: { modules: ScanModule[] }) {
  const [expandedCategories, setExpandedCategories] = useState<Set<string>>(
    new Set(MODULE_CATEGORIES)
  )

  // Group modules by category heuristic
  const groupedModules: Record<string, ScanModule[]> = {
    "Information Gathering": [],
    "Security Analysis": [],
    "OWASP Top 10": [],
    "Vulnerability Detection": [],
  }

  const infoNames = new Set(["DNS Lookup", "WHOIS Lookup", "IP Detection", "Technology Detection", "Directory Discovery"])
  const secNames = new Set(["Security Headers", "Cookie Security", "CORS Analysis", "Session Management", "SSL/TLS Analysis"])
  const owaspNames = new Set(["OWASP Top 10"])

  for (const mod of modules) {
    if (infoNames.has(mod.name)) groupedModules["Information Gathering"]?.push(mod)
    else if (secNames.has(mod.name)) groupedModules["Security Analysis"]?.push(mod)
    else if (owaspNames.has(mod.name)) groupedModules["OWASP Top 10"]?.push(mod)
    else groupedModules["Vulnerability Detection"]?.push(mod)
  }

  const toggleCategory = (cat: string) => {
    setExpandedCategories((prev) => {
      const next = new Set(prev)
      if (next.has(cat)) next.delete(cat)
      else next.add(cat)
      return next
    })
  }

  const totalFindings = modules.reduce((s, m) => s + m.findingsCount, 0)
  const completedCount = modules.filter((m) => m.status === "completed").length
  const failedCount = modules.filter((m) => m.status === "failed").length

  return (
    <div className="space-y-6">
      {/* Summary Bar */}
      <div className="flex flex-wrap gap-4 rounded-xl border border-zinc-800 bg-zinc-900/50 p-4">
        <div className="flex items-center gap-2">
          <div className="h-2 w-2 rounded-full bg-emerald-400" />
          <span className="text-sm text-zinc-300">{completedCount} completed</span>
        </div>
        {failedCount > 0 && (
          <div className="flex items-center gap-2">
            <div className="h-2 w-2 rounded-full bg-rose-400" />
            <span className="text-sm text-zinc-300">{failedCount} failed</span>
          </div>
        )}
        <div className="flex items-center gap-2">
          <div className="h-2 w-2 rounded-full bg-blue-400" />
          <span className="text-sm text-zinc-300">{modules.length} total modules</span>
        </div>
        <div className="ml-auto flex items-center gap-2">
          <span className="text-sm font-medium text-zinc-100">{totalFindings} findings</span>
        </div>
      </div>

      {/* Category Groups */}
      {MODULE_CATEGORIES.map((category) => {
        const catModules = groupedModules[category]
        if (!catModules || catModules.length === 0) return null
        const colors = CATEGORY_COLORS[category] ?? {
          bg: "bg-zinc-500/10",
          text: "text-zinc-400",
          border: "border-zinc-500/20",
        }
        const isOpen = expandedCategories.has(category)
        const catFindings = catModules.reduce((s, m) => s + m.findingsCount, 0)

        return (
          <div key={category} className={`rounded-xl border ${colors.border} overflow-hidden`}>
            <button
              onClick={() => toggleCategory(category)}
              className={`flex w-full items-center justify-between px-5 py-3.5 ${colors.bg}`}
            >
              <div className="flex items-center gap-3">
                {isOpen ? (
                  <ChevronDown className={`h-4 w-4 ${colors.text}`} />
                ) : (
                  <ChevronRight className={`h-4 w-4 ${colors.text}`} />
                )}
                <span className={`text-sm font-semibold ${colors.text}`}>{category}</span>
                <span className="text-xs text-zinc-500">{catModules.length} modules</span>
              </div>
              {catFindings > 0 && (
                <span className={`rounded-full px-2.5 py-0.5 text-xs font-semibold ${colors.bg} ${colors.text}`}>
                  {catFindings} findings
                </span>
              )}
            </button>

            <AnimatePresence>
              {isOpen && (
                <motion.div
                  initial={{ height: 0 }}
                  animate={{ height: "auto" }}
                  exit={{ height: 0 }}
                  transition={{ duration: 0.2 }}
                  className="overflow-hidden"
                >
                  <div className="space-y-2 p-3">
                    {catModules.map((mod) => (
                      <ModuleCard key={mod.id} module={mod} categoryColor={colors.bg} />
                    ))}
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        )
      })}
    </div>
  )
}


