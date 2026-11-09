import { motion } from "framer-motion"
import {
  Globe,
  Server,
  Network,
  ExternalLink,
  MoreHorizontal,
  ScanSearch,
  Eye,
  Trash2,
  CheckCircle2,
  Clock,
  XCircle,
  HelpCircle,
} from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
  DropdownMenuSeparator,
} from "@/components/ui/dropdown-menu"
import { cn, formatRelativeTime } from "@/utils"
import type { Target, TargetType, TargetStatus, ValidationStatus } from "@/types"

/* ── Icon mapping ── */
const typeIcons: Record<TargetType, typeof Globe> = {
  web: Globe,
  api: Server,
  network: Network,
}

const typeLabels: Record<TargetType, string> = {
  web: "Web App",
  api: "API",
  network: "Network",
}

/* ── Status styles ── */
const statusConfig: Record<
  TargetStatus,
  { label: string; className: string; dot: string }
> = {
  active: {
    label: "Active",
    className: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
    dot: "bg-emerald-400",
  },
  scanning: {
    label: "Scanning",
    className: "bg-blue-500/10 text-blue-400 border-blue-500/20",
    dot: "bg-blue-400",
  },
  inactive: {
    label: "Inactive",
    className: "bg-zinc-500/10 text-zinc-400 border-zinc-500/20",
    dot: "bg-zinc-400",
  },
}

/* ── Validation status config ── */
const validationConfig: Record<
  ValidationStatus,
  { label: string; icon: typeof CheckCircle2; className: string }
> = {
  verified: {
    label: "Verified",
    icon: CheckCircle2,
    className: "text-emerald-400",
  },
  pending: {
    label: "Pending",
    icon: Clock,
    className: "text-amber-400",
  },
  failed: {
    label: "Failed",
    icon: XCircle,
    className: "text-red-400",
  },
  unverified: {
    label: "Unverified",
    icon: HelpCircle,
    className: "text-zinc-400",
  },
}

interface TargetTableProps {
  targets: Target[]
  onViewDetails: (target: Target) => void
  onDeleteTarget?: (target: Target) => void
}

export function TargetTable({ targets, onViewDetails, onDeleteTarget }: TargetTableProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35, delay: 0.15 }}
      className="overflow-hidden rounded-xl border border-border bg-card"
    >
      {/* Table header */}
      <div className="grid grid-cols-[2fr_0.8fr_0.8fr_0.8fr_1fr_0.7fr_0.5fr] items-center gap-4 border-b border-border bg-muted/30 px-5 py-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
        <span>Target</span>
        <span>Type</span>
        <span>Status</span>
        <span>Validation</span>
        <span>Last Scanned</span>
        <span className="text-center">Findings</span>
        <span className="text-right">Actions</span>
      </div>

      {/* Table rows */}
      {targets.map((target, index) => {
        const TypeIcon = typeIcons[target.type]
        const stCfg = statusConfig[target.status]
        const valCfg = validationConfig[target.validationStatus]
        const ValIcon = valCfg.icon

        return (
          <motion.div
            key={target.id}
            initial={{ opacity: 0, x: -8 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.25, delay: 0.05 * index }}
            className="group grid grid-cols-[2fr_0.8fr_0.8fr_0.8fr_1fr_0.7fr_0.5fr] items-center gap-4 border-b border-border/50 px-5 py-3.5 transition-colors last:border-b-0 hover:bg-muted/20"
          >
            {/* Target URL + description */}
            <div className="flex items-center gap-3 min-w-0">
              <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-primary/10">
                <TypeIcon className="h-4 w-4 text-primary" />
              </div>
              <div className="min-w-0">
                <button
                  onClick={() => onViewDetails(target)}
                  className="flex items-center gap-1.5 text-sm font-medium text-foreground transition-colors hover:text-primary"
                >
                  <span className="truncate">{target.url}</span>
                  <ExternalLink className="h-3 w-3 shrink-0 opacity-0 transition-opacity group-hover:opacity-100" />
                </button>
                {target.description && (
                  <p className="mt-0.5 truncate text-xs text-muted-foreground">
                    {target.description.slice(0, 70)}
                    {target.description.length > 70 ? "…" : ""}
                  </p>
                )}
              </div>
            </div>

            {/* Type */}
            <div>
              <Badge
                variant="outline"
                className="gap-1 text-[11px] font-medium"
              >
                <TypeIcon className="h-3 w-3" />
                {typeLabels[target.type]}
              </Badge>
            </div>

            {/* Status */}
            <div>
              <span
                className={cn(
                  "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-[11px] font-medium",
                  stCfg.className,
                )}
              >
                <span
                  className={cn(
                    "h-1.5 w-1.5 rounded-full",
                    stCfg.dot,
                    target.status === "scanning" && "animate-pulse",
                  )}
                />
                {stCfg.label}
              </span>
            </div>

            {/* Validation */}
            <div className="flex items-center gap-1.5">
              <ValIcon className={cn("h-3.5 w-3.5", valCfg.className)} />
              <span className={cn("text-xs font-medium", valCfg.className)}>
                {valCfg.label}
              </span>
            </div>

            {/* Last scanned */}
            <div className="text-xs text-muted-foreground">
              {target.lastScannedAt
                ? formatRelativeTime(new Date(target.lastScannedAt))
                : "Never"}
            </div>

            {/* Findings */}
            <div className="flex items-center justify-center gap-2">
              <span className="text-sm font-semibold text-foreground">
                {target.totalFindings}
              </span>
              {target.criticalFindings > 0 && (
                <Badge
                  variant="destructive"
                  className="h-5 min-w-5 rounded-full px-1.5 text-[10px] font-bold"
                >
                  {target.criticalFindings}
                </Badge>
              )}
            </div>

            {/* Actions */}
            <div className="flex justify-end">
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button
                    variant="ghost"
                    size="icon-xs"
                    className="opacity-0 transition-opacity group-hover:opacity-100"
                  >
                    <MoreHorizontal className="h-4 w-4" />
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end" className="w-44">
                  <DropdownMenuItem onClick={() => onViewDetails(target)}>
                    <Eye className="mr-2 h-3.5 w-3.5" />
                    View Details
                  </DropdownMenuItem>
                  <DropdownMenuItem>
                    <ScanSearch className="mr-2 h-3.5 w-3.5" />
                    Start Scan
                  </DropdownMenuItem>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem
                    onClick={() => onDeleteTarget?.(target)}
                    className="text-destructive focus:text-destructive"
                  >
                    <Trash2 className="mr-2 h-3.5 w-3.5" />
                    Remove Target
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            </div>
          </motion.div>
        )
      })}
    </motion.div>
  )
}
