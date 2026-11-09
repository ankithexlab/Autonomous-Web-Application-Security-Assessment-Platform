import { useState, useRef, useEffect } from "react"
import { motion } from "framer-motion"
import {
  Info,
  AlertTriangle,
  XCircle,
  Bug,
  CheckCircle2,
  Filter,
  ChevronDown,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { cn } from "@/utils"
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

type LogLevel = ScanLogEntry["level"] | "all"

interface ScanLogsPanelProps {
  logs: ScanLogEntry[]
  isLive?: boolean
}

export function ScanLogsPanel({ logs, isLive = false }: ScanLogsPanelProps) {
  const [filter, setFilter] = useState<LogLevel>("all")
  const [autoScroll, setAutoScroll] = useState(true)
  const scrollRef = useRef<HTMLDivElement>(null)

  const filteredLogs = filter === "all" ? logs : logs.filter((l) => l.level === filter)

  // Auto-scroll to bottom for live scans
  useEffect(() => {
    if (autoScroll && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight
    }
  }, [filteredLogs.length, autoScroll])

  function formatTimestamp(ts: string): string {
    const d = new Date(ts)
    return d.toLocaleTimeString("en-US", {
      hour12: false,
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    })
  }

  const filterButtons: { level: LogLevel; label: string; count: number }[] = [
    { level: "all", label: "All", count: logs.length },
    { level: "error", label: "Errors", count: logs.filter((l) => l.level === "error").length },
    { level: "warning", label: "Warnings", count: logs.filter((l) => l.level === "warning").length },
    { level: "info", label: "Info", count: logs.filter((l) => l.level === "info").length },
    { level: "success", label: "Success", count: logs.filter((l) => l.level === "success").length },
    { level: "debug", label: "Debug", count: logs.filter((l) => l.level === "debug").length },
  ]

  return (
    <div className="flex flex-col overflow-hidden rounded-xl border border-border bg-card">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-border px-4 py-2.5">
        <div className="flex items-center gap-2">
          <h4 className="text-sm font-semibold text-foreground">Scan Logs</h4>
          {isLive && (
            <span className="flex items-center gap-1 rounded-full bg-emerald-500/10 px-2 py-0.5 text-[10px] font-semibold text-emerald-400">
              <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-400" />
              LIVE
            </span>
          )}
        </div>
        <div className="flex items-center gap-1">
          <Filter className="h-3.5 w-3.5 text-muted-foreground mr-1" />
          {filterButtons.map((fb) =>
            fb.count > 0 ? (
              <button
                key={fb.level}
                onClick={() => setFilter(fb.level)}
                className={cn(
                  "rounded-md px-2 py-1 text-[10px] font-semibold transition-colors",
                  filter === fb.level
                    ? "bg-primary/15 text-primary"
                    : "text-muted-foreground hover:bg-muted/50 hover:text-foreground",
                )}
              >
                {fb.label}
                <span className="ml-1 opacity-60">{fb.count}</span>
              </button>
            ) : null,
          )}
        </div>
      </div>

      {/* Log entries */}
      <div
        ref={scrollRef}
        className="max-h-72 overflow-y-auto bg-[oklch(0.12_0.005_285.82)] font-mono text-xs"
        onScroll={(e) => {
          const el = e.currentTarget
          const isAtBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 40
          setAutoScroll(isAtBottom)
        }}
      >
        {filteredLogs.length === 0 ? (
          <div className="flex items-center justify-center py-12 text-muted-foreground">
            No log entries matching filter
          </div>
        ) : (
          filteredLogs.map((log, i) => {
            const cfg = levelConfig[log.level]
            const LogIcon = cfg.icon

            return (
              <motion.div
                key={log.id}
                initial={isLive && i === filteredLogs.length - 1 ? { opacity: 0, y: 4 } : false}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.2 }}
                className={cn(
                  "flex items-start gap-2 border-b border-white/5 px-4 py-1.5 transition-colors hover:bg-white/[0.02]",
                  log.level === "error" && "bg-red-500/[0.03]",
                )}
              >
                {/* Timestamp */}
                <span className="shrink-0 text-muted-foreground/70 tabular-nums">
                  {formatTimestamp(log.timestamp)}
                </span>

                {/* Level badge */}
                <span
                  className={cn(
                    "flex h-4.5 shrink-0 items-center gap-1 rounded px-1",
                    cfg.bg,
                  )}
                >
                  <LogIcon className={cn("h-2.5 w-2.5", cfg.color)} />
                  <span className={cn("text-[9px] font-bold", cfg.color)}>
                    {cfg.label}
                  </span>
                </span>

                {/* Module */}
                <span className="shrink-0 font-semibold text-primary/70">
                  [{log.module}]
                </span>

                {/* Message */}
                <span
                  className={cn(
                    "flex-1",
                    log.level === "error"
                      ? "text-red-300"
                      : log.level === "warning"
                        ? "text-amber-300"
                        : "text-foreground/80",
                  )}
                >
                  {log.message}
                </span>
              </motion.div>
            )
          })
        )}
      </div>

      {/* Auto-scroll indicator */}
      {!autoScroll && isLive && (
        <div className="border-t border-border">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              setAutoScroll(true)
              if (scrollRef.current) {
                scrollRef.current.scrollTop = scrollRef.current.scrollHeight
              }
            }}
            className="w-full gap-2 rounded-none text-xs text-muted-foreground"
          >
            <ChevronDown className="h-3 w-3" />
            Scroll to latest
          </Button>
        </div>
      )}
    </div>
  )
}
