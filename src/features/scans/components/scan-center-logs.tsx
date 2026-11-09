import { useState, useRef, useEffect } from "react"
import { motion } from "framer-motion"
import {
  Terminal,
  Filter,
  Search,
  Copy,
  ChevronDown,
  Info,
  AlertTriangle,
  XCircle,
  Bug,
  CheckCircle2,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { toast } from "sonner"
import { cn } from "@/utils"
import type { ScanEngineReturn } from "../hooks/use-scan-engine"
import type { ScanLogEntry } from "@/types"

const levelConfig: Record<
  ScanLogEntry["level"],
  { icon: typeof Info; color: string; bg: string; label: string }
> = {
  info: { icon: Info, color: "text-blue-400", bg: "bg-blue-500/10", label: "INF" },
  warning: { icon: AlertTriangle, color: "text-amber-400", bg: "bg-amber-500/10", label: "WRN" },
  error: { icon: XCircle, color: "text-red-400", bg: "bg-red-500/10", label: "ERR" },
  debug: { icon: Bug, color: "text-zinc-400", bg: "bg-zinc-500/10", label: "DBG" },
  success: { icon: CheckCircle2, color: "text-emerald-400", bg: "bg-emerald-500/10", label: "OK" },
}

type LogLevelFilter = ScanLogEntry["level"] | "all"

interface ScanCenterLogsProps {
  engine: ScanEngineReturn
}

export function ScanCenterLogs({ engine }: ScanCenterLogsProps) {
  const [levelFilter, setLevelFilter] = useState<LogLevelFilter>("all")
  const [search, setSearch] = useState("")
  const [autoScroll, setAutoScroll] = useState(true)
  const scrollRef = useRef<HTMLDivElement>(null)

  const isLive = engine.status === "running"

  const filteredLogs = engine.logs.filter((log) => {
    if (levelFilter !== "all" && log.level !== levelFilter) return false
    if (search) {
      const q = search.toLowerCase()
      const matches =
        log.message.toLowerCase().includes(q) ||
        log.module.toLowerCase().includes(q) ||
        log.level.toLowerCase().includes(q)
      if (!matches) return false
    }
    return true
  })

  // Auto scroll to bottom
  useEffect(() => {
    if (autoScroll && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight
    }
  }, [filteredLogs.length, autoScroll])

  function formatTime(ts: string): string {
    const d = new Date(ts)
    return d.toLocaleTimeString("en-US", {
      hour12: false,
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    })
  }

  function handleCopy() {
    const text = filteredLogs.map((l) => `[${formatTime(l.timestamp)}] [${l.module}] ${l.level.toUpperCase()}: ${l.message}`).join("\n")
    navigator.clipboard.writeText(text)
    toast.success("Logs copied to clipboard")
  }

  const filterOptions: { level: LogLevelFilter; label: string }[] = [
    { level: "all", label: "ALL" },
    { level: "error", label: "ERR" },
    { level: "warning", label: "WRN" },
    { level: "info", label: "INF" },
    { level: "success", label: "OK" },
  ]

  return (
    <div className="flex flex-col overflow-hidden rounded-2xl border border-border/80 bg-card shadow-sm">
      {/* Console Header */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border/60 bg-muted/40 px-4 py-2.5">
        <div className="flex items-center gap-2">
          <Terminal className="h-4 w-4 text-primary" />
          <h3 className="text-sm font-bold text-foreground">Live Security Execution Console</h3>
          {isLive && (
            <span className="flex items-center gap-1 rounded-full bg-emerald-500/10 px-2 py-0.5 text-[10px] font-semibold text-emerald-400">
              <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-400" />
              STREAMING
            </span>
          )}
        </div>

        {/* Console Controls */}
        <div className="flex items-center gap-2">
          {/* Search bar */}
          <div className="relative max-w-[160px]">
            <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
            <Input
              placeholder="Search console..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="h-7 pl-8 text-xs"
            />
          </div>

          {/* Level Filter */}
          <div className="flex items-center gap-1">
            <Filter className="h-3 w-3 text-muted-foreground mr-0.5" />
            {filterOptions.map((opt) => (
              <button
                key={opt.level}
                type="button"
                onClick={() => setLevelFilter(opt.level)}
                className={cn(
                  "rounded px-1.5 py-0.5 text-[10px] font-bold transition-colors font-mono",
                  levelFilter === opt.level
                    ? "bg-primary text-primary-foreground"
                    : "text-muted-foreground hover:bg-muted hover:text-foreground",
                )}
              >
                {opt.label}
              </button>
            ))}
          </div>

          {/* Actions */}
          <Button variant="ghost" size="icon" onClick={handleCopy} title="Copy Logs" className="h-7 w-7">
            <Copy className="h-3.5 w-3.5 text-muted-foreground" />
          </Button>
        </div>
      </div>

      {/* Terminal View Body */}
      <div
        ref={scrollRef}
        className="max-h-80 min-h-60 overflow-y-auto bg-[oklch(0.12_0.005_285.82)] p-3 font-mono text-xs text-foreground/90 selection:bg-primary/30"
        onScroll={(e) => {
          const el = e.currentTarget
          const isAtBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 30
          setAutoScroll(isAtBottom)
        }}
      >
        {filteredLogs.length === 0 ? (
          <div className="flex h-48 items-center justify-center text-muted-foreground/60">
            {engine.status === "idle"
              ? "Console waiting for scan start signal..."
              : "No log entries match selected filters"}
          </div>
        ) : (
          filteredLogs.map((log) => {
            const cfg = levelConfig[log.level]
            const LogIcon = cfg.icon

            return (
              <motion.div
                key={log.id}
                initial={{ opacity: 0, y: 2 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.15 }}
                className={cn(
                  "flex items-start gap-2 py-1 px-1.5 rounded transition-colors hover:bg-white/[0.03]",
                  log.level === "error" && "bg-red-500/10 text-red-300",
                  log.level === "warning" && "bg-amber-500/5 text-amber-200",
                )}
              >
                <span className="shrink-0 text-muted-foreground/60 tabular-nums">
                  [{formatTime(log.timestamp)}]
                </span>

                <span
                  className={cn(
                    "flex shrink-0 items-center gap-0.5 rounded px-1 text-[9px] font-bold uppercase",
                    cfg.bg,
                    cfg.color,
                  )}
                >
                  <LogIcon className="h-2.5 w-2.5" />
                  {cfg.label}
                </span>

                <span className="shrink-0 font-semibold text-primary/80">
                  [{log.module}]
                </span>

                <span className="flex-1 break-all leading-relaxed">{log.message}</span>
              </motion.div>
            )
          })
        )}
      </div>

      {/* Scroll indicator when user scrolled up */}
      {!autoScroll && isLive && (
        <div className="border-t border-border/40 bg-muted/40">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              setAutoScroll(true)
              if (scrollRef.current) {
                scrollRef.current.scrollTop = scrollRef.current.scrollHeight
              }
            }}
            className="w-full h-7 gap-1.5 rounded-none text-[11px] text-muted-foreground"
          >
            <ChevronDown className="h-3 w-3" />
            Resume auto-scroll to bottom
          </Button>
        </div>
      )}
    </div>
  )
}
