import { useState } from "react"
import {
  Shield,
  Search,
  FileText,
  CheckCircle2,
  AlertCircle,
  XCircle,
  StopCircle,
  Clock,
  Radar,
  Globe,
  FolderPlus,
  Activity,
  type LucideIcon,
} from "lucide-react"
import { motion } from "framer-motion"
import { cn } from "@/utils"
import { SeverityBadge } from "./severity-badge"
import type { ActivityItem } from "../data/dashboard-data"

const TYPE_CONFIG: Record<
  string,
  { icon: LucideIcon; color: string; bg: string; label: string }
> = {
  finding_discovered: {
    icon: AlertCircle,
    color: "text-red-400",
    bg: "bg-red-500/10",
    label: "Finding Discovered",
  },
  finding_resolved: {
    icon: Shield,
    color: "text-emerald-400",
    bg: "bg-emerald-500/10",
    label: "Finding Resolved",
  },
  scan_completed: {
    icon: CheckCircle2,
    color: "text-emerald-400",
    bg: "bg-emerald-500/10",
    label: "Scan Completed",
  },
  scan_started: {
    icon: Search,
    color: "text-blue-400",
    bg: "bg-blue-500/10",
    label: "Scan Started",
  },
  scan_failed: {
    icon: XCircle,
    color: "text-red-400",
    bg: "bg-red-500/10",
    label: "Scan Failed",
  },
  scan_cancelled: {
    icon: StopCircle,
    color: "text-amber-400",
    bg: "bg-amber-500/10",
    label: "Scan Cancelled",
  },
  scan_running: {
    icon: Radar,
    color: "text-cyan-400",
    bg: "bg-cyan-500/10",
    label: "Scan Running",
  },
  scan_queued: {
    icon: Clock,
    color: "text-zinc-400",
    bg: "bg-zinc-500/10",
    label: "Scan Queued",
  },
  report_generated: {
    icon: FileText,
    color: "text-violet-400",
    bg: "bg-violet-500/10",
    label: "Report Generated",
  },
  target_created: {
    icon: Globe,
    color: "text-indigo-400",
    bg: "bg-indigo-500/10",
    label: "Target Created",
  },
  project_created: {
    icon: FolderPlus,
    color: "text-teal-400",
    bg: "bg-teal-500/10",
    label: "Project Created",
  },
}

const DEFAULT_CONFIG = {
  icon: Activity,
  color: "text-primary",
  bg: "bg-primary/10",
  label: "Security Event",
}

function formatTimestamp(timestamp?: string | null): string {
  if (!timestamp) return "Just now"
  try {
    const d = new Date(timestamp)
    if (!isNaN(d.getTime()) && timestamp.includes("T")) {
      return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
    }
    return String(timestamp)
  } catch {
    return String(timestamp)
  }
}

interface RecentActivityProps {
  activities?: ActivityItem[]
}

export function RecentActivity({ activities }: RecentActivityProps) {
  const [filter, setFilter] = useState<"all" | "scans" | "findings" | "reports">("all")

  const sourceItems = Array.isArray(activities) ? activities : []

  const filteredItems = sourceItems.filter((item) => {
    if (!item) return false
    const itemType = (item.type || "").toLowerCase()
    if (filter === "scans") return itemType.startsWith("scan_")
    if (filter === "findings") return itemType.startsWith("finding_")
    if (filter === "reports") return itemType.startsWith("report_")
    return true
  })

  return (
    <div className="rounded-xl border border-border bg-card p-5 space-y-4 shadow-sm">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h3 className="text-sm font-semibold text-foreground flex items-center gap-2">
            <Activity className="h-4 w-4 text-primary" />
            Live Security Timeline
          </h3>
          <p className="text-xs text-muted-foreground">
            Audit events across active environments
          </p>
        </div>

        {/* Filter buttons */}
        <div className="flex items-center gap-1 overflow-x-auto rounded-lg border border-border bg-muted/30 p-1 text-[11px]">
          {(["all", "scans", "findings", "reports"] as const).map((cat) => (
            <button
              key={cat}
              onClick={() => setFilter(cat)}
              className={cn(
                "rounded-md px-2 py-1 font-medium capitalize transition-colors whitespace-nowrap",
                filter === cat
                  ? "bg-background text-foreground shadow-xs"
                  : "text-muted-foreground hover:text-foreground",
              )}
            >
              {cat}
            </button>
          ))}
        </div>
      </div>

      <div className="space-y-1">
        {filteredItems.length === 0 ? (
          <div className="p-6 text-center text-xs text-muted-foreground">
            No events match the selected category.
          </div>
        ) : (
          filteredItems.map((item, index) => {
            const itemType = (item?.type || "").toLowerCase()
            const config = TYPE_CONFIG[itemType] || DEFAULT_CONFIG
            const Icon = config.icon || Activity
            const itemId = item?.id || `activity-${index}`

            return (
              <motion.div
                key={itemId}
                initial={{ opacity: 0, x: -8 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{
                  duration: 0.25,
                  delay: index * 0.05,
                  ease: "easeOut",
                }}
                className="group relative flex gap-3 py-3"
              >
                {/* Timeline connector */}
                {index < filteredItems.length - 1 && (
                  <div className="absolute left-[15px] top-[42px] h-[calc(100%-26px)] w-px bg-border" />
                )}

                {/* Icon */}
                <div
                  className={cn(
                    "relative z-10 flex h-8 w-8 shrink-0 items-center justify-center rounded-full border border-border/40",
                    config.bg,
                  )}
                >
                  <Icon className={cn("h-4 w-4", config.color)} />
                </div>

                {/* Content */}
                <div className="min-w-0 flex-1">
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-xs font-bold text-foreground">
                        {item?.title || config.label}
                      </p>
                      <p className="mt-0.5 text-xs text-muted-foreground line-clamp-1">
                        {item?.description || "Security event recorded"}
                      </p>
                    </div>

                    {item?.severity && (
                      <SeverityBadge
                        severity={item.severity}
                        className="shrink-0"
                      />
                    )}
                  </div>

                  <p className="mt-1 text-[10px] text-muted-foreground/70 font-mono">
                    {formatTimestamp(item?.timestamp)}
                  </p>
                </div>
              </motion.div>
            )
          })
        )}
      </div>
    </div>
  )
}
