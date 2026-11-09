import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
} from "@/components/ui/sheet"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Separator } from "@/components/ui/separator"
import { ScrollArea } from "@/components/ui/scroll-area"
import { cn, formatRelativeTime } from "@/utils"
import { useNavigate } from "react-router"
import {
  Globe,
  Server,
  Network,
  MapPin,
  Tag,
  Layers,
  Shield,
  Clock,
  CheckCircle2,
  XCircle,
  HelpCircle,
  ScanSearch,
  ChevronRight,
  Cpu,
  Calendar,
  Trash2,
} from "lucide-react"
import type { Target, TargetType, ValidationStatus, TargetScanHistory } from "@/types"

/* ── Icon maps ── */
const typeIcons: Record<TargetType, typeof Globe> = {
  web: Globe,
  api: Server,
  network: Network,
}

const typeLabels: Record<TargetType, string> = {
  web: "Web Application",
  api: "REST / GraphQL API",
  network: "Network Segment",
}

const validationConfig: Record<
  ValidationStatus,
  { label: string; icon: typeof CheckCircle2; className: string; bgClass: string }
> = {
  verified: {
    label: "Verified",
    icon: CheckCircle2,
    className: "text-emerald-400",
    bgClass: "bg-emerald-500/10 border-emerald-500/20",
  },
  pending: {
    label: "Pending Verification",
    icon: Clock,
    className: "text-amber-400",
    bgClass: "bg-amber-500/10 border-amber-500/20",
  },
  failed: {
    label: "Verification Failed",
    icon: XCircle,
    className: "text-red-400",
    bgClass: "bg-red-500/10 border-red-500/20",
  },
  unverified: {
    label: "Not Yet Verified",
    icon: HelpCircle,
    className: "text-zinc-400",
    bgClass: "bg-zinc-500/10 border-zinc-500/20",
  },
}

/* ── Scan history row ── */
function ScanHistoryRow({ scan }: { scan: TargetScanHistory }) {
  const statusColor =
    scan.status === "completed"
      ? "text-emerald-400"
      : scan.status === "running"
        ? "text-blue-400"
        : "text-red-400"
  const statusDot =
    scan.status === "completed"
      ? "bg-emerald-400"
      : scan.status === "running"
        ? "bg-blue-400"
        : "bg-red-400"

  return (
    <div className="flex items-center gap-3 rounded-lg border border-border/50 bg-muted/20 px-3.5 py-2.5 transition-colors hover:bg-muted/40">
      <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-primary/10">
        <ScanSearch className="h-3.5 w-3.5 text-primary" />
      </div>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium text-foreground">
            {scan.scanType}
          </span>
          <span
            className={cn(
              "inline-flex items-center gap-1 text-[10px] font-semibold uppercase",
              statusColor,
            )}
          >
            <span
              className={cn(
                "h-1.5 w-1.5 rounded-full",
                statusDot,
                scan.status === "running" && "animate-pulse",
              )}
            />
            {scan.status}
          </span>
        </div>
        <div className="mt-0.5 flex items-center gap-3 text-[11px] text-muted-foreground">
          <span>{formatRelativeTime(new Date(scan.startedAt))}</span>
          <span>·</span>
          <span>{scan.duration}</span>
          {scan.findingsCount > 0 && (
            <>
              <span>·</span>
              <span className="font-medium text-amber-400">
                {scan.findingsCount} findings
              </span>
            </>
          )}
        </div>
      </div>
      <ChevronRight className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
    </div>
  )
}

/* ── Detail section helper ── */
function DetailSection({
  icon: Icon,
  title,
  children,
}: {
  icon: typeof Globe
  title: string
  children: React.ReactNode
}) {
  return (
    <div className="space-y-2.5">
      <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
        <Icon className="h-3.5 w-3.5" />
        {title}
      </div>
      {children}
    </div>
  )
}

interface TargetDetailPanelProps {
  target: Target | null
  open: boolean
  onClose: () => void
  onDeleteTarget?: (target: Target) => void
}

export function TargetDetailPanel({
  target,
  open,
  onClose,
  onDeleteTarget,
}: TargetDetailPanelProps) {
  const navigate = useNavigate()
  if (!target) return null

  function handleStartScan() {
    onClose()
    navigate("/scans")
  }

  const TypeIcon = typeIcons[target.type]
  const valCfg = validationConfig[target.validationStatus]
  const ValIcon = valCfg.icon

  return (
    <Sheet open={open} onOpenChange={(o) => !o && onClose()}>
      <SheetContent className="w-full sm:max-w-lg p-0 border-l border-border bg-background">
        <ScrollArea className="h-full">
          <div className="p-6 space-y-6">
            {/* Header */}
            <SheetHeader className="space-y-3">
              <div className="flex items-center gap-3">
                <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl bg-primary/10">
                  <TypeIcon className="h-5 w-5 text-primary" />
                </div>
                <div className="min-w-0 flex-1">
                  <SheetTitle className="truncate text-base font-semibold text-foreground">
                    {target.url}
                  </SheetTitle>
                  <SheetDescription className="text-xs text-muted-foreground">
                    {typeLabels[target.type]} · Added{" "}
                    {formatRelativeTime(new Date(target.createdAt))}
                  </SheetDescription>
                </div>
              </div>
            </SheetHeader>

            {/* Validation status banner */}
            <div
              className={cn(
                "flex items-center gap-3 rounded-lg border px-4 py-3",
                valCfg.bgClass,
              )}
            >
              <ValIcon className={cn("h-5 w-5", valCfg.className)} />
              <div>
                <p className={cn("text-sm font-semibold", valCfg.className)}>
                  {valCfg.label}
                </p>
                <p className="text-xs text-muted-foreground">
                  {target.validationStatus === "verified"
                    ? "Target ownership has been confirmed"
                    : target.validationStatus === "pending"
                      ? "Ownership verification is in progress"
                      : target.validationStatus === "failed"
                        ? "Could not verify target ownership"
                        : "Target has not been verified yet"}
                </p>
              </div>
            </div>

            {/* Quick stats */}
            <div className="grid grid-cols-3 gap-3">
              {[
                {
                  label: "Total Scans",
                  value: target.totalScans,
                  color: "text-blue-400",
                },
                {
                  label: "Findings",
                  value: target.totalFindings,
                  color: "text-amber-400",
                },
                {
                  label: "Critical",
                  value: target.criticalFindings,
                  color: "text-red-400",
                },
              ].map((s) => (
                <div
                  key={s.label}
                  className="rounded-lg border border-border bg-muted/20 p-3 text-center"
                >
                  <p className={cn("text-lg font-bold", s.color)}>
                    {s.value}
                  </p>
                  <p className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
                    {s.label}
                  </p>
                </div>
              ))}
            </div>

            <Separator />

            {/* Description */}
            {target.description && (
              <DetailSection icon={Layers} title="Description">
                <p className="text-sm leading-relaxed text-muted-foreground">
                  {target.description}
                </p>
              </DetailSection>
            )}

            {/* Tags */}
            {target.tags.length > 0 && (
              <DetailSection icon={Tag} title="Tags">
                <div className="flex flex-wrap gap-1.5">
                  {target.tags.map((tag) => (
                    <Badge
                      key={tag}
                      variant="secondary"
                      className="rounded-md px-2 py-0.5 text-[11px] font-medium"
                    >
                      {tag}
                    </Badge>
                  ))}
                </div>
              </DetailSection>
            )}

            {/* Scope */}
            {target.scope.length > 0 && (
              <DetailSection icon={Shield} title="Scope">
                <div className="space-y-1">
                  {target.scope.map((s) => (
                    <div
                      key={s}
                      className="flex items-center gap-2 rounded-md bg-muted/30 px-3 py-1.5 font-mono text-xs text-foreground"
                    >
                      <span className="text-primary">›</span>
                      {s}
                    </div>
                  ))}
                </div>
              </DetailSection>
            )}

            {/* Technology Stack */}
            {target.technology && target.technology.length > 0 && (
              <DetailSection icon={Cpu} title="Technology Stack">
                <div className="flex flex-wrap gap-1.5">
                  {target.technology.map((tech) => (
                    <Badge
                      key={tech}
                      variant="outline"
                      className="rounded-md px-2 py-0.5 text-[11px]"
                    >
                      {tech}
                    </Badge>
                  ))}
                </div>
              </DetailSection>
            )}

            {/* Network Info */}
            {target.ipAddress && (
              <DetailSection icon={MapPin} title="Network Information">
                <div className="grid grid-cols-2 gap-3 text-xs">
                  <div className="rounded-md bg-muted/30 px-3 py-2">
                    <span className="text-muted-foreground">IP Address</span>
                    <p className="mt-0.5 font-mono font-medium text-foreground">
                      {target.ipAddress}
                    </p>
                  </div>
                  <div className="rounded-md bg-muted/30 px-3 py-2">
                    <span className="text-muted-foreground">Last Updated</span>
                    <p className="mt-0.5 font-medium text-foreground">
                      {formatRelativeTime(new Date(target.updatedAt))}
                    </p>
                  </div>
                </div>
              </DetailSection>
            )}

            <Separator />

            {/* Scan History */}
            <DetailSection icon={Calendar} title="Scan History">
              {target.scanHistory.length > 0 ? (
                <div className="space-y-2">
                  {target.scanHistory.map((scan) => (
                    <ScanHistoryRow key={scan.id} scan={scan} />
                  ))}
                </div>
              ) : (
                <div className="rounded-lg border border-dashed border-border py-8 text-center">
                  <ScanSearch className="mx-auto h-8 w-8 text-muted-foreground/50" />
                  <p className="mt-2 text-sm text-muted-foreground">
                    No scans yet
                  </p>
                  <p className="text-xs text-muted-foreground/70">
                    Start a scan to see results here
                  </p>
                </div>
              )}
            </DetailSection>

            {/* Actions */}
            <div className="flex flex-col gap-2 pt-2">
              <div className="flex gap-2">
                <Button onClick={handleStartScan} className="flex-1 gap-2" size="sm">
                  <ScanSearch className="h-4 w-4" />
                  Start Scan
                </Button>
              </div>
              {onDeleteTarget && (
                <Button
                  variant="destructive"
                  size="sm"
                  className="w-full gap-2 font-semibold"
                  onClick={() => {
                    onDeleteTarget(target)
                    onClose()
                  }}
                >
                  <Trash2 className="h-4 w-4" />
                  Delete Target
                </Button>
              )}
            </div>
          </div>
        </ScrollArea>
      </SheetContent>
    </Sheet>
  )
}
