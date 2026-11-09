import { motion } from "framer-motion"
import {
  Play,
  Clock,
  CheckCircle2,
  XCircle,
  Ban,
  ChevronRight,
  Radar,
  Zap,
  Crosshair,
  RefreshCw,
  AlertTriangle,
  Timer,
  Shield,
  Target,
} from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { cn, formatRelativeTime } from "@/utils"
import type { Scan, ScanStatus, ScanType } from "@/types"

/* ── Status config ── */
const statusConfig: Record<
  ScanStatus,
  { label: string; icon: typeof Play; className: string; dotClass: string }
> = {
  idle: {
    label: "Idle",
    icon: Clock,
    className: "bg-zinc-500/10 text-zinc-400 border-zinc-500/20",
    dotClass: "bg-zinc-400",
  },
  running: {
    label: "Running",
    icon: Play,
    className: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
    dotClass: "bg-emerald-400 animate-pulse",
  },
  paused: {
    label: "Paused",
    icon: Clock,
    className: "bg-amber-500/10 text-amber-400 border-amber-500/20",
    dotClass: "bg-amber-400",
  },
  queued: {
    label: "Queued",
    icon: Clock,
    className: "bg-amber-500/10 text-amber-400 border-amber-500/20",
    dotClass: "bg-amber-400",
  },
  completed: {
    label: "Completed",
    icon: CheckCircle2,
    className: "bg-blue-500/10 text-blue-400 border-blue-500/20",
    dotClass: "bg-blue-400",
  },
  failed: {
    label: "Failed",
    icon: XCircle,
    className: "bg-red-500/10 text-red-400 border-red-500/20",
    dotClass: "bg-red-400",
  },
  cancelled: {
    label: "Cancelled",
    icon: Ban,
    className: "bg-zinc-500/10 text-zinc-400 border-zinc-500/20",
    dotClass: "bg-zinc-400",
  },
}

const typeConfig: Record<ScanType, { label: string; icon: typeof Radar }> = {
  full: { label: "Full Scan", icon: Radar },
  quick: { label: "Quick Scan", icon: Zap },
  targeted: { label: "Targeted", icon: Crosshair },
  continuous: { label: "Continuous", icon: RefreshCw },
  active: { label: "Active Vulnerability", icon: Target },
  passive: { label: "Passive Security", icon: Shield },
}

interface ScanStatusCardsProps {
  scans: Scan[]
  selectedScanId: string | null
  onSelectScan: (scan: Scan) => void
}

export function ScanStatusCards({ scans, selectedScanId, onSelectScan }: ScanStatusCardsProps) {
  return (
    <div className="space-y-2">
      {scans.map((scan, i) => {
        const st = statusConfig[scan.status]
        const tp = typeConfig[scan.type]
        const TypeIcon = tp.icon
        const isSelected = scan.id === selectedScanId

        return (
          <motion.button
            key={scan.id}
            initial={{ opacity: 0, x: -10 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.25, delay: i * 0.04 }}
            onClick={() => onSelectScan(scan)}
            className={cn(
              "group flex w-full items-center gap-3 rounded-xl border px-4 py-3.5 text-left transition-all",
              isSelected
                ? "border-primary/40 bg-primary/5 ring-1 ring-primary/20"
                : "border-border bg-card hover:border-muted-foreground/20 hover:bg-muted/20",
            )}
          >
            {/* Icon */}
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-primary/10">
              <TypeIcon className="h-4.5 w-4.5 text-primary" />
            </div>

            {/* Info */}
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <span className="truncate text-sm font-semibold text-foreground">
                  {scan.targetUrl}
                </span>
                <Badge variant="outline" className="shrink-0 text-[10px] px-1.5 py-0">
                  {tp.label}
                </Badge>
              </div>

              <div className="mt-1 flex items-center gap-3 text-[11px] text-muted-foreground">
                {/* Status badge */}
                <span className={cn("inline-flex items-center gap-1 rounded-full border px-2 py-0.5 font-medium", st.className)}>
                  <span className={cn("h-1.5 w-1.5 rounded-full", st.dotClass)} />
                  {st.label}
                </span>

                {/* Progress or duration */}
                {scan.status === "running" && (
                  <span className="flex items-center gap-1 font-medium text-emerald-400">
                    <Timer className="h-3 w-3" />
                    {scan.progress}%
                  </span>
                )}
                {scan.duration && (
                  <span>{scan.duration}</span>
                )}

                {/* Findings */}
                {scan.findingsCount > 0 && (
                  <span className="flex items-center gap-1">
                    {scan.criticalCount > 0 && (
                      <span className="flex items-center gap-0.5 font-semibold text-red-400">
                        <AlertTriangle className="h-3 w-3" />
                        {scan.criticalCount}
                      </span>
                    )}
                    <span>{scan.findingsCount} findings</span>
                  </span>
                )}

                {/* Timestamp */}
                <span className="ml-auto shrink-0">
                  {scan.startedAt
                    ? formatRelativeTime(new Date(scan.startedAt))
                    : formatRelativeTime(new Date(scan.createdAt))}
                </span>
              </div>

              {/* Progress bar for running scans */}
              {scan.status === "running" && (
                <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-muted">
                  <motion.div
                    className="h-full rounded-full bg-gradient-to-r from-emerald-500 to-emerald-400"
                    initial={{ width: 0 }}
                    animate={{ width: `${scan.progress}%` }}
                    transition={{ duration: 1, ease: "easeOut" }}
                  />
                </div>
              )}
            </div>

            <ChevronRight className="h-4 w-4 shrink-0 text-muted-foreground transition-transform group-hover:translate-x-0.5" />
          </motion.button>
        )
      })}
    </div>
  )
}
