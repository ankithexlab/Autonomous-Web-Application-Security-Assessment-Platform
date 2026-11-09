import { useNavigate } from "react-router"
import {
  Radar,
  CheckCircle2,
  Clock,
  Globe,
  ArrowRight,
  Play,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { ROUTES } from "@/constants"
import { cn } from "@/utils"

interface RecentScanCardProps {
  scan?: {
    id: string
    target_name: string
    target_url: string
    scan_type: string
    status: string
    created_at: string | null
    completed_at: string | null
    findings_count?: number
    critical_count?: number
    high_count?: number
    medium_count?: number
    low_count?: number
  } | null
}

export function RecentScanCard({ scan: scanProp }: RecentScanCardProps) {
  const navigate = useNavigate()

  if (!scanProp) {
    return (
      <div className="rounded-xl border border-border bg-card p-5 space-y-4 shadow-sm relative overflow-hidden flex flex-col justify-center items-center text-center min-h-[260px]">
        <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10 text-primary border border-primary/20 mb-2">
          <Radar className="h-5 w-5" />
        </div>
        <h3 className="text-sm font-bold text-foreground">No Scans Executed Yet</h3>
        <p className="text-xs text-muted-foreground max-w-[240px]">
          Launch your first automated vulnerability scan to analyze target security posture.
        </p>
        <Button
          size="sm"
          onClick={() => navigate(ROUTES.SCANS)}
          className="gap-1.5 text-xs font-semibold mt-2"
        >
          <Play className="h-3.5 w-3.5" />
          Start New Scan
        </Button>
      </div>
    )
  }

  const activeScan = {
    id: scanProp?.id ? String(scanProp.id).substring(0, 8) : "N/A",
    targetName: scanProp?.target_name || scanProp?.target_url || "Target",
    targetUrl: scanProp?.target_url || "N/A",
    status: scanProp?.status || "Unknown",
    startedAt: scanProp?.created_at ? new Date(scanProp.created_at).toLocaleString() : "Recently",
    findingsCount: {
      critical: scanProp?.critical_count ?? 0,
      high: scanProp?.high_count ?? 0,
      medium: scanProp?.medium_count ?? 0,
      low: scanProp?.low_count ?? 0,
    },
  }

  const totalFindings =
    activeScan.findingsCount.critical +
    activeScan.findingsCount.high +
    activeScan.findingsCount.medium +
    activeScan.findingsCount.low

  const statusLower = activeScan.status.toLowerCase()
  const isCompleted = statusLower === "completed"

  return (
    <div className="rounded-xl border border-border bg-card p-5 space-y-4 shadow-sm relative overflow-hidden">
      {/* Top Header */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border/50 pb-3.5">
        <div className="flex items-center gap-2.5">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary/10 text-primary border border-primary/20">
            <Radar className="h-5 w-5 animate-spin-slow" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-bold text-foreground">Recent Security Scan</h3>
              <Badge
                variant="outline"
                className={cn(
                  "text-[10px]",
                  isCompleted
                    ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"
                    : "bg-blue-500/10 text-blue-400 border-blue-500/30"
                )}
              >
                <CheckCircle2 className="h-3 w-3 mr-1" />
                {activeScan.status}
              </Badge>
            </div>
            <p className="text-xs text-muted-foreground font-mono mt-0.5">ID: {activeScan.id}</p>
          </div>
        </div>

        <Button
          size="sm"
          onClick={() => navigate(ROUTES.SCANS)}
          className="gap-1.5 text-xs font-semibold shadow-xs"
        >
          <Play className="h-3.5 w-3.5" />
          New Scan
        </Button>
      </div>

      {/* Target Info */}
      <div className="rounded-lg border border-border/60 bg-muted/20 p-3.5 space-y-2">
        <div className="flex items-center justify-between">
          <span className="text-xs font-bold text-foreground truncate">{activeScan.targetName}</span>
          <span className="text-[11px] text-muted-foreground flex items-center gap-1">
            <Clock className="h-3 w-3" />
            {activeScan.startedAt}
          </span>
        </div>
        <div className="flex items-center gap-1.5 text-xs text-muted-foreground font-mono truncate">
          <Globe className="h-3.5 w-3.5 text-primary shrink-0" />
          <span>{activeScan.targetUrl}</span>
        </div>
      </div>

      {/* Findings Breakdown Pills */}
      <div className="space-y-2 pt-1">
        <div className="flex items-center justify-between text-xs">
          <span className="font-semibold text-foreground">Findings Discovered ({totalFindings})</span>
          <Button
            variant="link"
            size="sm"
            onClick={() => navigate(ROUTES.SCANS)}
            className="h-auto p-0 text-xs text-primary gap-1"
          >
            View details
            <ArrowRight className="h-3 w-3" />
          </Button>
        </div>

        <div className="grid grid-cols-4 gap-2 text-center text-xs">
          <div className="rounded-md border border-red-500/30 bg-red-500/10 p-1.5 text-red-400">
            <span className="text-[10px] block font-medium">Critical</span>
            <span className="font-bold">{activeScan.findingsCount.critical}</span>
          </div>
          <div className="rounded-md border border-orange-500/30 bg-orange-500/10 p-1.5 text-orange-400">
            <span className="text-[10px] block font-medium">High</span>
            <span className="font-bold">{activeScan.findingsCount.high}</span>
          </div>
          <div className="rounded-md border border-amber-500/30 bg-amber-500/10 p-1.5 text-amber-400">
            <span className="text-[10px] block font-medium">Medium</span>
            <span className="font-bold">{activeScan.findingsCount.medium}</span>
          </div>
          <div className="rounded-md border border-blue-500/30 bg-blue-500/10 p-1.5 text-blue-400">
            <span className="text-[10px] block font-medium">Low</span>
            <span className="font-bold">{activeScan.findingsCount.low}</span>
          </div>
        </div>
      </div>
    </div>
  )
}
