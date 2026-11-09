import { motion } from "framer-motion"
import {
  Globe,
  Server,
  Activity,
  CheckCircle2,
  Clock,
  XCircle,
  AlertTriangle,
  Radar,
  MoreHorizontal,
  Eye,
  ExternalLink,
  Trash2,
} from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { cn, formatRelativeTime } from "@/utils"
import type { Target, TargetType, TargetStatus, ValidationStatus, TargetRiskLevel } from "@/types"

const typeConfig: Record<TargetType, { label: string; icon: typeof Globe }> = {
  web: { label: "Web Application", icon: Globe },
  api: { label: "REST / GraphQL API", icon: Server },
  network: { label: "Network Range", icon: Activity },
}

const statusConfig: Record<
  TargetStatus,
  { label: string; className: string; dotClass: string }
> = {
  active: {
    label: "Active",
    className: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
    dotClass: "bg-emerald-400 animate-pulse",
  },
  scanning: {
    label: "Scanning",
    className: "bg-blue-500/10 text-blue-400 border-blue-500/20",
    dotClass: "bg-blue-400 animate-ping",
  },
  inactive: {
    label: "Inactive",
    className: "bg-zinc-500/10 text-zinc-400 border-zinc-500/20",
    dotClass: "bg-zinc-400",
  },
}

const validationConfig: Record<
  ValidationStatus,
  { label: string; className: string; icon: typeof CheckCircle2 }
> = {
  verified: {
    label: "Verified Owner",
    className: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
    icon: CheckCircle2,
  },
  pending: {
    label: "Verification Pending",
    className: "bg-amber-500/10 text-amber-400 border-amber-500/20",
    icon: Clock,
  },
  failed: {
    label: "Validation Failed",
    className: "bg-red-500/10 text-red-400 border-red-500/20",
    icon: XCircle,
  },
  unverified: {
    label: "Unverified",
    className: "bg-zinc-500/10 text-zinc-400 border-zinc-500/20",
    icon: Clock,
  },
}

const riskConfig: Record<TargetRiskLevel, { label: string; className: string }> = {
  critical: { label: "Critical Risk", className: "bg-red-500/15 text-red-400 border-red-500/30" },
  high: { label: "High Risk", className: "bg-orange-500/15 text-orange-400 border-orange-500/30" },
  medium: { label: "Medium Risk", className: "bg-amber-500/15 text-amber-400 border-amber-500/30" },
  low: { label: "Low Risk", className: "bg-blue-500/15 text-blue-400 border-blue-500/30" },
}

interface TargetCardGridProps {
  targets: Target[]
  onSelectTarget: (target: Target) => void
  onDeleteTarget?: (target: Target) => void
}

export function TargetCardGrid({ targets, onSelectTarget, onDeleteTarget }: TargetCardGridProps) {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
      {targets.map((target, index) => {
        const tp = typeConfig[target.type]
        const st = statusConfig[target.status]
        const val = validationConfig[target.validationStatus]
        const rk = target.riskLevel ? riskConfig[target.riskLevel] : riskConfig.medium
        const TypeIcon = tp.icon
        const ValIcon = val.icon

        return (
          <motion.div
            key={target.id}
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.3, delay: index * 0.05 }}
            className="group flex flex-col justify-between rounded-xl border border-border bg-card p-5 transition-all hover:border-primary/40 hover:shadow-md"
          >
            <div>
              {/* Top Header */}
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-center gap-3 min-w-0">
                  <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-primary/10 text-primary">
                    <TypeIcon className="h-5 w-5" />
                  </div>
                  <div className="min-w-0">
                    <div className="flex items-center gap-1.5">
                      <h3
                        onClick={() => onSelectTarget(target)}
                        className="truncate font-bold text-base text-foreground group-hover:text-primary transition-colors cursor-pointer"
                      >
                        {target.url}
                      </h3>
                      <a
                        href={target.url.startsWith("http") ? target.url : `https://${target.url}`}
                        target="_blank"
                        rel="noreferrer"
                        className="text-muted-foreground hover:text-foreground shrink-0"
                      >
                        <ExternalLink className="h-3 w-3" />
                      </a>
                    </div>

                    <div className="mt-1 flex items-center gap-1.5 flex-wrap">
                      <span
                        className={cn(
                          "inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-semibold",
                          st.className,
                        )}
                      >
                        <span className={cn("h-1.5 w-1.5 rounded-full", st.dotClass)} />
                        {st.label}
                      </span>

                      <span
                        className={cn(
                          "inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-semibold",
                          val.className,
                        )}
                      >
                        <ValIcon className="h-3 w-3" />
                        {val.label}
                      </span>

                      <span
                        className={cn(
                          "inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide",
                          rk.className,
                        )}
                      >
                        {rk.label}
                      </span>
                    </div>
                  </div>
                </div>

                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button variant="ghost" size="icon-xs" className="shrink-0">
                      <MoreHorizontal className="h-4 w-4" />
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="end" className="w-44">
                    <DropdownMenuItem onClick={() => onSelectTarget(target)}>
                      <Eye className="mr-2 h-3.5 w-3.5" />
                      View Details
                    </DropdownMenuItem>
                    <DropdownMenuItem>
                      <Radar className="mr-2 h-3.5 w-3.5 text-primary" />
                      Launch Scan
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

              {/* Description */}
              {target.description && (
                <p className="mt-3 text-xs text-muted-foreground line-clamp-2 leading-relaxed">
                  {target.description}
                </p>
              )}

              {/* Scope Paths */}
              {target.scope && target.scope.length > 0 && (
                <div className="mt-3 space-y-1">
                  <span className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                    In-Scope Routes
                  </span>
                  <div className="flex flex-wrap gap-1">
                    {target.scope.slice(0, 3).map((path) => (
                      <span
                        key={path}
                        className="rounded bg-muted/40 px-1.5 py-0.5 font-mono text-[10px] text-primary"
                      >
                        {path}
                      </span>
                    ))}
                    {target.scope.length > 3 && (
                      <span className="rounded bg-muted/20 px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground">
                        +{target.scope.length - 3} more
                      </span>
                    )}
                  </div>
                </div>
              )}

              {/* Tags & Tech */}
              {target.tags.length > 0 && (
                <div className="mt-3 flex flex-wrap gap-1">
                  {target.tags.map((tag) => (
                    <Badge key={tag} variant="secondary" className="text-[10px] px-1.5 py-0 font-mono">
                      #{tag}
                    </Badge>
                  ))}
                </div>
              )}
            </div>

            {/* Last Scan Info Footer */}
            <div className="mt-4 pt-3 border-t border-border/40 space-y-2">
              <div className="flex items-center justify-between text-xs">
                <span className="text-muted-foreground">Last Scanned</span>
                <span className="font-medium text-foreground">
                  {target.lastScannedAt
                    ? formatRelativeTime(new Date(target.lastScannedAt))
                    : "Never"}
                </span>
              </div>

              <div className="flex items-center justify-between text-xs">
                <span className="text-muted-foreground">Total Scans: {target.totalScans}</span>
                {target.criticalFindings > 0 ? (
                  <span className="flex items-center gap-1 font-bold text-red-400 text-[11px]">
                    <AlertTriangle className="h-3 w-3" />
                    {target.criticalFindings} Critical
                  </span>
                ) : (
                  <span className="text-emerald-400 font-semibold text-[11px]">
                    0 Critical
                  </span>
                )}
              </div>
            </div>
          </motion.div>
        )
      })}
    </div>
  )
}
