import { useState, useEffect, useMemo } from "react"
import { motion } from "framer-motion"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@radix-ui/react-tabs"
import {
  Radar,
  Zap,
  Crosshair,
  RefreshCw,
  Play,
  Pause,
  StopCircle,
  Timer,
  Target,
  AlertTriangle,
  Shield,
  Settings2,
  Trash2,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Separator } from "@/components/ui/separator"
import { cn, formatRelativeTime } from "@/utils"
import { toast } from "sonner"
import { scansService } from "@/services/scans.service"
import { findingsService } from "@/services/findings.service"
import { ModuleTimeline } from "./module-timeline"
import { ScanLogsPanel } from "./scan-logs-panel"
import { ScanRiskCards } from "./scan-risk-cards"
import { VulnerabilityFindingsPanel } from "./vulnerability-findings-panel"
import { InfoGatheringResults } from "./info-gathering-results"
import type { ModuleResults, DNSRecord } from "../data/scanner-modules-data"
import type { Scan, ScanType, Finding } from "@/types"

function extractReconResults(modulesJson?: string | null): ModuleResults | undefined {
  if (!modulesJson) return undefined
  try {
    const raw = typeof modulesJson === "string" ? JSON.parse(modulesJson) : modulesJson
    if (!raw || typeof raw !== "object") return undefined

    const results: ModuleResults = {}

    // 1. DNS records
    if (raw.dns_lookup && typeof raw.dns_lookup === "object") {
      const d = raw.dns_lookup
      const records: DNSRecord[] = []
      if (d.records && typeof d.records === "object") {
        for (const [rtype, vals] of Object.entries(d.records)) {
          if (Array.isArray(vals)) {
            for (const item of vals) {
              if (typeof item === "object" && item !== null && "host" in item) {
                records.push({ type: rtype, value: (item as any).host, priority: (item as any).priority })
              } else if (typeof item === "string") {
                records.push({ type: rtype, value: item })
              }
            }
          }
        }
      }
      results.dns = {
        hostname: d.hostname || "",
        records,
      }
    }

    // 2. WHOIS
    if (raw.whois_lookup && typeof raw.whois_lookup === "object") {
      const w = raw.whois_lookup
      results.whois = {
        registrar: w.registrar || "Unknown",
        creationDate: w.creation_date ? String(w.creation_date).slice(0, 10) : "N/A",
        expirationDate: w.expiration_date ? String(w.expiration_date).slice(0, 10) : "N/A",
        nameServers: Array.isArray(w.name_servers) ? w.name_servers : [],
        registrantCountry: w.country || "Unknown",
        daysUntilExpiry: w.days_until_expiry ?? 365,
      }
    }

    // 3. IP detection
    if (raw.ip_detection && typeof raw.ip_detection === "object") {
      const ip = raw.ip_detection
      results.ip = {
        ipv4: Array.isArray(ip.ipv4) ? ip.ipv4 : [],
        ipv6: Array.isArray(ip.ipv6) ? ip.ipv6 : [],
        reverseDns: Array.isArray(ip.reverse_dns) ? ip.reverse_dns : [],
        cdnDetected: ip.cdn_detected || null,
        hostingProvider: ip.hosting_provider || null,
      }
    }

    // 4. Technology detection
    if (raw.tech_detection && typeof raw.tech_detection === "object") {
      const t = raw.tech_detection
      results.technologies = Array.isArray(t.technologies) ? t.technologies : []
    }

    // 5. Directory discovery
    if (raw.directory_discovery && typeof raw.directory_discovery === "object") {
      const dir = raw.directory_discovery
      results.directories = {
        pathsChecked: dir.paths_checked || 0,
        discovered: Array.isArray(dir.discovered)
          ? dir.discovered.map((item: any) => ({
              path: item.path || "",
              name: item.name || item.path || "",
              statusCode: item.status_code || 200,
              severity: item.severity || "info",
            }))
          : [],
      }
    }

    const hasAny = results.dns || results.whois || results.ip || results.technologies || results.directories
    return hasAny ? results : undefined
  } catch {
    return undefined
  }
}

const typeConfig: Record<ScanType, { label: string; icon: typeof Radar }> = {
  full: { label: "Full Scan", icon: Radar },
  quick: { label: "Quick Scan", icon: Zap },
  targeted: { label: "Targeted Scan", icon: Crosshair },
  continuous: { label: "Continuous Scan", icon: RefreshCw },
  active: { label: "Active Vulnerability Scan", icon: Target },
  passive: { label: "Passive Security Scan", icon: Shield },
}

interface ScanDetailViewProps {
  scan: Scan
  onDeleteScan?: (scanId: string) => void
}

export function ScanDetailView({ scan, onDeleteScan }: ScanDetailViewProps) {
  const [scanFindings, setScanFindings] = useState<Finding[]>([])
  const [isLoadingFindings, setIsLoadingFindings] = useState(false)
  const reconData = useMemo(() => extractReconResults(scan.modulesJson), [scan.modulesJson])

  useEffect(() => {
    let isMounted = true
    setIsLoadingFindings(true)
    findingsService
      .getFindings({ scanId: scan.id })
      .then((res) => {
        if (isMounted) setScanFindings(res.items)
      })
      .catch(() => {
        if (isMounted) setScanFindings([])
      })
      .finally(() => {
        if (isMounted) setIsLoadingFindings(false)
      })

    return () => {
      isMounted = false
    }
  }, [scan.id])

  const tp = typeConfig[scan.type]
  const TypeIcon = tp.icon
  const isLive = scan.status === "running"

  async function handleRerunScan() {
    try {
      const newScan = await scansService.createScan(scan.projectId, scan.targetId, {
        scanType: scan.type,
        config: scan.config as any,
      })
      await scansService.startScan(newScan.id)
      toast.success("Scan execution started")
      window.dispatchEvent(
        new CustomEvent("awsap:scan_created", { detail: { scanId: newScan.id } }),
      )
    } catch {
      toast.error("Failed to start scan execution")
    }
  }

  return (
    <motion.div
      key={scan.id}
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-5"
    >
      {/* Header */}
      <div className="rounded-xl border border-border bg-card p-5">
        <div className="flex items-start justify-between">
          <div className="flex items-center gap-3">
            <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl bg-primary/10">
              <TypeIcon className="h-5 w-5 text-primary" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-lg font-bold text-foreground">
                  {tp.label}
                </h2>
                <Badge variant="outline" className="text-[10px]">
                  {scan.id}
                </Badge>
              </div>
              <div className="mt-0.5 flex items-center gap-2 text-xs text-muted-foreground">
                <Target className="h-3 w-3" />
                <span>{scan.targetUrl}</span>
                {scan.startedAt && (
                  <>
                    <span>·</span>
                    <span>
                      Started {formatRelativeTime(new Date(scan.startedAt))}
                    </span>
                  </>
                )}
              </div>
            </div>
          </div>

          {/* Action buttons */}
          <div className="flex gap-2">
            {(isLive || scan.status === "queued" || scan.status === "idle") && (
              <>
                {isLive && (
                  <Button variant="outline" size="sm" className="gap-1.5">
                    <Pause className="h-3.5 w-3.5" />
                    Pause
                  </Button>
                )}
                <Button
                  variant="destructive"
                  size="sm"
                  className="gap-1.5"
                  onClick={async () => {
                    try {
                      await scansService.cancelScan(scan.id)
                      window.dispatchEvent(new CustomEvent("awsap:scan_created"))
                    } catch (e) {
                      console.error("Failed to cancel scan:", e)
                    }
                  }}
                >
                  <StopCircle className="h-3.5 w-3.5" />
                  Cancel Scan
                </Button>
              </>
            )}
            {scan.status === "completed" && (
              <Button onClick={handleRerunScan} variant="outline" size="sm" className="gap-1.5">
                <Play className="h-3.5 w-3.5" />
                Re-run
              </Button>
            )}
            {scan.status === "failed" && (
              <Button onClick={handleRerunScan} size="sm" className="gap-1.5">
                <RefreshCw className="h-3.5 w-3.5" />
                Retry
              </Button>
            )}
            {!isLive && onDeleteScan && (
              <Button
                variant="outline"
                size="sm"
                className="gap-1.5 text-destructive hover:text-destructive hover:bg-destructive/10"
                onClick={() => onDeleteScan(scan.id)}
              >
                <Trash2 className="h-3.5 w-3.5" />
                Delete
              </Button>
            )}
          </div>
        </div>

        {/* Progress section */}
        {isLive && (
          <div className="mt-4 space-y-2">
            <div className="flex items-center justify-between text-xs">
              <span className="flex items-center gap-1.5 font-medium text-emerald-400">
                <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-400" />
                Scan in progress
              </span>
              <span className="text-muted-foreground">
                {scan.estimatedTimeRemaining && (
                  <span className="flex items-center gap-1">
                    <Timer className="h-3 w-3" />
                    ETA: {scan.estimatedTimeRemaining}
                  </span>
                )}
              </span>
            </div>
            <div className="h-2 w-full overflow-hidden rounded-full bg-muted">
              <motion.div
                className="h-full rounded-full bg-gradient-to-r from-emerald-500 via-emerald-400 to-teal-400"
                initial={{ width: 0 }}
                animate={{ width: `${scan.progress}%` }}
                transition={{ duration: 1.5, ease: "easeOut" }}
              />
            </div>
            <div className="flex items-center justify-between text-[11px] text-muted-foreground">
              <span>{scan.progress}% complete</span>
              <span>
                {scan.modules.filter((m) => m.status === "completed").length}/
                {scan.modules.length} modules
              </span>
            </div>
          </div>
        )}

        {/* Completed/failed banner */}
        {scan.status === "completed" && scan.duration && (
          <div className="mt-4 flex items-center gap-2 rounded-lg bg-blue-500/10 px-3 py-2 text-xs text-blue-400">
            <Shield className="h-4 w-4" />
            <span>Scan completed in {scan.duration}</span>
          </div>
        )}
        {scan.status === "failed" && (
          <div className="mt-4 flex items-center gap-2 rounded-lg bg-red-500/10 px-3 py-2 text-xs text-red-400">
            <AlertTriangle className="h-4 w-4" />
            <span>
              Scan failed{scan.duration ? ` after ${scan.duration}` : ""}
            </span>
          </div>
        )}

        <Separator className="mt-4" />

        {/* Finding severity breakdown */}
        <div className="mt-4 grid grid-cols-5 gap-2">
          {[
            { label: "Critical", count: scan.criticalCount, color: "text-red-400 bg-red-500/10" },
            { label: "High", count: scan.highCount, color: "text-orange-400 bg-orange-500/10" },
            { label: "Medium", count: scan.mediumCount, color: "text-amber-400 bg-amber-500/10" },
            { label: "Low", count: scan.lowCount, color: "text-blue-400 bg-blue-500/10" },
            { label: "Info", count: scan.infoCount, color: "text-zinc-400 bg-zinc-500/10" },
          ].map((s) => (
            <div
              key={s.label}
              className={cn(
                "rounded-lg px-2.5 py-2 text-center",
                s.color.split(" ")[1],
              )}
            >
              <p className={cn("text-lg font-bold", s.color.split(" ")[0])}>
                {s.count}
              </p>
              <p className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
                {s.label}
              </p>
            </div>
          ))}
        </div>
      </div>

      {/* Risk Summary Cards */}
      <ScanRiskCards scan={scan} />

      {/* Tabs: Modules / Findings / Reconnaissance / Logs / Config */}
      <Tabs defaultValue="modules" className="space-y-3">
        <TabsList className="flex gap-1 rounded-lg border border-border bg-muted/30 p-1 flex-wrap">
          {[
            { value: "modules", label: "Modules", count: scan.modules.length },
            { value: "findings", label: "Findings", count: scanFindings.length },
            { value: "recon", label: "Reconnaissance" },
            { value: "logs", label: "Logs", count: scan.logs.length },
            { value: "config", label: "Configuration" },
          ].map((tab) => (
            <TabsTrigger
              key={tab.value}
              value={tab.value}
              className="flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium text-muted-foreground transition-colors data-[state=active]:bg-background data-[state=active]:text-foreground data-[state=active]:shadow-sm"
            >
              {tab.label}
              {"count" in tab && (
                <span className="rounded-full bg-muted px-1.5 text-[10px]">
                  {tab.count}
                </span>
              )}
            </TabsTrigger>
          ))}
        </TabsList>

        {/* Modules tab */}
        <TabsContent value="modules">
          <div className="rounded-xl border border-border bg-card p-5">
            <ModuleTimeline modules={scan.modules} />
          </div>
        </TabsContent>

        {/* Findings tab */}
        <TabsContent value="findings">
          <div className="rounded-xl border border-border bg-card p-5">
            {isLoadingFindings ? (
              <div className="py-12 text-center text-xs text-muted-foreground">
                Loading scan findings...
              </div>
            ) : (
              <VulnerabilityFindingsPanel findings={scanFindings} />
            )}
          </div>
        </TabsContent>

        {/* Reconnaissance tab */}
        <TabsContent value="recon">
          <div className="rounded-xl border border-border bg-card p-5">
            <InfoGatheringResults results={reconData} />
          </div>
        </TabsContent>

        {/* Logs tab */}
        <TabsContent value="logs">
          <ScanLogsPanel logs={scan.logs} isLive={isLive} />
        </TabsContent>

        {/* Config tab */}
        <TabsContent value="config">
          <div className="rounded-xl border border-border bg-card p-5">
            <div className="flex items-center gap-2 mb-4">
              <Settings2 className="h-4 w-4 text-muted-foreground" />
              <h4 className="text-sm font-semibold text-foreground">
                Scan Configuration
              </h4>
            </div>
            <div className="grid grid-cols-2 gap-3 text-xs">
              {[
                { label: "Scan Type", value: tp.label },
                { label: "Max Depth", value: String(scan.config.maxDepth) },
                { label: "Concurrency", value: String(scan.config.maxConcurrency) },
                { label: "Follow Redirects", value: scan.config.followRedirects ? "Yes" : "No" },
                { label: "Authentication", value: scan.config.authentication ? "Enabled" : "Disabled" },
                { label: "Modules", value: String(scan.config.modules.length) },
              ].map((item) => (
                <div
                  key={item.label}
                  className="rounded-md bg-muted/30 px-3 py-2"
                >
                  <span className="text-muted-foreground">{item.label}</span>
                  <p className="mt-0.5 font-medium text-foreground">
                    {item.value}
                  </p>
                </div>
              ))}
            </div>

            {/* Scope */}
            {scan.config.includePaths.length > 0 && (
              <div className="mt-4">
                <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                  Include Paths
                </span>
                <div className="mt-1.5 space-y-1">
                  {scan.config.includePaths.map((p) => (
                    <div
                      key={p}
                      className="flex items-center gap-2 rounded-md bg-emerald-500/5 px-3 py-1.5 font-mono text-xs text-emerald-400"
                    >
                      <span className="text-emerald-500">+</span> {p}
                    </div>
                  ))}
                </div>
              </div>
            )}
            {scan.config.excludePaths.length > 0 && (
              <div className="mt-3">
                <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                  Exclude Paths
                </span>
                <div className="mt-1.5 space-y-1">
                  {scan.config.excludePaths.map((p) => (
                    <div
                      key={p}
                      className="flex items-center gap-2 rounded-md bg-red-500/5 px-3 py-1.5 font-mono text-xs text-red-400"
                    >
                      <span className="text-red-500">−</span> {p}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </TabsContent>
      </Tabs>
    </motion.div>
  )
}
