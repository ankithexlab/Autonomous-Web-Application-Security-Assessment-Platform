import { useState, useEffect, useCallback, useMemo } from "react"
import { AVAILABLE_MODULES } from "../data/scans-data"
import { scansService } from "@/services/scans.service"
import { targetsService } from "@/services/targets.service"
import { toast } from "sonner"
import type {
  Scan,
  ScanStatus,
  ScanType,
  ScanModule,
  ScanModuleStatus,
  ScanLogEntry,
  Target,
} from "@/types"

export interface ScanPreset {
  id: string
  name: string
  description: string
  scanType: ScanType
  modules: string[]
  maxDepth: number
  maxConcurrency: number
  estimatedMinutes: number
}

export const SCAN_PRESETS: ScanPreset[] = [
  {
    id: "owasp-top-10",
    name: "OWASP Top 10",
    description: "Standard web security audit covering top web vulnerabilities",
    scanType: "full",
    modules: ["recon", "crawler", "sqli", "xss", "csrf", "headers", "auth"],
    maxDepth: 10,
    maxConcurrency: 5,
    estimatedMinutes: 5,
  },
  {
    id: "fast-surface",
    name: "Fast Surface Recon",
    description: "Quick check for subdomains, headers, and SSL certificates",
    scanType: "quick",
    modules: ["recon", "headers", "ssl", "ports"],
    maxDepth: 3,
    maxConcurrency: 5,
    estimatedMinutes: 2,
  },
  {
    id: "api-security",
    name: "API Vulnerability Audit",
    description: "Focus on API endpoints, BOLA, authentication, and schema",
    scanType: "targeted",
    modules: ["recon", "crawler", "api", "auth", "headers"],
    maxDepth: 8,
    maxConcurrency: 4,
    estimatedMinutes: 3,
  },
  {
    id: "deep-pentest",
    name: "Deep Security Pentest",
    description: "Exhaustive crawl and vulnerability scanning across all modules",
    scanType: "full",
    modules: AVAILABLE_MODULES.map((m) => m.id),
    maxDepth: 15,
    maxConcurrency: 5,
    estimatedMinutes: 10,
  },
]

const STAGE_SUBTASKS: Record<number, string> = {
  0: "Scan queued — awaiting scanner engine allocation...",
  5: "Validating destination host against SSRF security guardrails...",
  15: "Resolving DNS records, WHOIS data, and IP allocation...",
  30: "Testing endpoint reachability and measuring response latency...",
  45: "Auditing HSTS, CSP, X-Frame-Options, and Set-Cookie flags...",
  55: "Validating TLS protocol versions and redirect chains...",
  65: "Probing robots.txt, sitemap.xml, and server banner disclosure...",
  75: "Evaluating OWASP Top 10 compliance rules A01–A10...",
  85: "Auditing CORS access policies and session management...",
  95: "Executing vulnerability heuristics and security test probes...",
  100: "Scan completed — final vulnerability metrics compiled",
}

function getSubtaskForProgress(progress: number): string {
  const steps = [100, 95, 85, 75, 65, 55, 45, 30, 15, 5, 0]
  for (const step of steps) {
    if (progress >= step) {
      return STAGE_SUBTASKS[step] ?? "Executing security assessment..."
    }
  }
  return "Executing security assessment..."
}

function computeModuleStates(
  selectedIds: string[],
  progress: number,
  scanStatus: ScanStatus,
): ScanModule[] {
  return selectedIds.map((id, index) => {
    const template = AVAILABLE_MODULES.find((m) => m.id === id)
    const name = template?.name ?? id
    const description = template?.description ?? ""

    let modStatus: ScanModuleStatus = "pending"
    let modProgress = 0

    if (scanStatus === "completed") {
      modStatus = "completed"
      modProgress = 100
    } else if (scanStatus === "idle") {
      modStatus = "pending"
      modProgress = 0
    } else if (scanStatus === "failed") {
      const targetPct = (index + 1) * (100 / Math.max(selectedIds.length, 1))
      const prevPct = index * (100 / Math.max(selectedIds.length, 1))
      if (progress >= targetPct) {
        modStatus = "completed"
        modProgress = 100
      } else if (progress > prevPct) {
        modStatus = "failed"
        modProgress = Math.min(100, Math.round(((progress - prevPct) / (targetPct - prevPct)) * 100))
      } else {
        modStatus = "pending"
        modProgress = 0
      }
    } else if (scanStatus === "cancelled") {
      const targetPct = (index + 1) * (100 / Math.max(selectedIds.length, 1))
      const prevPct = index * (100 / Math.max(selectedIds.length, 1))
      if (progress >= targetPct) {
        modStatus = "completed"
        modProgress = 100
      } else if (progress > prevPct) {
        modStatus = "failed"
        modProgress = Math.min(100, Math.round(((progress - prevPct) / (targetPct - prevPct)) * 100))
      } else {
        modStatus = "skipped"
        modProgress = 0
      }
    } else {
      // running or queued
      const targetPct = (index + 1) * (100 / Math.max(selectedIds.length, 1))
      const startPct = index * (100 / Math.max(selectedIds.length, 1))
      if (progress >= targetPct) {
        modStatus = "completed"
        modProgress = 100
      } else if (progress > startPct) {
        modStatus = "running"
        const span = targetPct - startPct
        modProgress = Math.min(99, Math.max(5, Math.round(((progress - startPct) / span) * 100)))
      } else {
        modStatus = "pending"
        modProgress = 0
      }
    }

    return {
      id,
      name,
      description,
      status: modStatus,
      progress: modProgress,
      findingsCount: 0,
    }
  })
}

function computeRealLogs(
  scan: Scan | null,
  findings: any[],
  status: ScanStatus,
  targetUrl: string,
  scanType: ScanType,
): ScanLogEntry[] {
  if (!scan && status === "idle") {
    return []
  }

  const entries: ScanLogEntry[] = []
  const timestamp = scan?.startedAt || scan?.createdAt || new Date().toISOString()
  const url = scan?.targetUrl || targetUrl

  entries.push({
    id: `log-init-${scan?.id || "live"}`,
    timestamp,
    level: "info",
    module: "Core Engine",
    message: `Scan initialized for ${url} (${(scan?.type || scanType).toUpperCase()})`,
  })

  const prog = scan?.progress ?? 0

  if (prog >= 5 || status === "running" || status === "completed") {
    entries.push({
      id: `log-ssrf-${scan?.id || "live"}`,
      timestamp,
      level: "info",
      module: "SSRF Guard",
      message: "Target URL and host validated against SSRF guardrails",
    })
  }

  if (prog >= 15 || status === "completed") {
    entries.push({
      id: `log-info-${scan?.id || "live"}`,
      timestamp,
      level: "info",
      module: "Reconnaissance",
      message: "DNS, WHOIS, IP resolution and technology detection in progress",
    })
  }

  if (prog >= 30 || status === "completed") {
    entries.push({
      id: `log-crawler-${scan?.id || "live"}`,
      timestamp,
      level: "info",
      module: "Web Crawler",
      message: "Primary HTTP response collected and endpoint response time verified",
    })
  }

  if (prog >= 45 || status === "completed") {
    entries.push({
      id: `log-headers-${scan?.id || "live"}`,
      timestamp,
      level: "info",
      module: "Security Headers",
      message: "Security headers and cookie security attributes audited",
    })
  }

  if (prog >= 55 || status === "completed") {
    entries.push({
      id: `log-ssl-${scan?.id || "live"}`,
      timestamp,
      level: "info",
      module: "SSL/TLS Analysis",
      message: "HTTPS enforcement and redirect chain analysis completed",
    })
  }

  if (prog >= 65 || status === "completed") {
    entries.push({
      id: `log-disclosure-${scan?.id || "live"}`,
      timestamp,
      level: "info",
      module: "Server Disclosure",
      message: "Server information disclosure, robots.txt and sitemap audited",
    })
  }

  if (prog >= 75 || status === "completed") {
    entries.push({
      id: `log-owasp-${scan?.id || "live"}`,
      timestamp,
      level: "info",
      module: "OWASP Engine",
      message: "OWASP Top 10 compliance checkers executed",
    })
  }

  if (prog >= 85 || status === "completed") {
    entries.push({
      id: `log-cors-${scan?.id || "live"}`,
      timestamp,
      level: "info",
      module: "Security Analysis",
      message: "CORS configuration and session management audited",
    })
  }

  if (prog >= 95 || status === "completed") {
    entries.push({
      id: `log-vuln-${scan?.id || "live"}`,
      timestamp,
      level: "info",
      module: "Vulnerability Engine",
      message: "Active vulnerability heuristics and security payload probes executed",
    })
  }

  // Real findings discovered by this scan
  for (const f of findings) {
    const isHighOrCrit = f.severity === "critical" || f.severity === "high"
    entries.push({
      id: `log-finding-${f.id}`,
      timestamp: f.created_at || f.createdAt || timestamp,
      level: isHighOrCrit ? "error" : "warning",
      module: f.category || "Vulnerability",
      message: `[${(f.severity || "info").toUpperCase()}] ${f.title} (${f.affected_url || f.affectedUrl || url})`,
    })
  }

  if (status === "completed") {
    entries.push({
      id: `log-done-${scan?.id || "live"}`,
      timestamp: scan?.completedAt || new Date().toISOString(),
      level: "success",
      module: "Core Engine",
      message: `Scan pipeline completed — ${scan?.findingsCount ?? findings.length} total issue(s) identified (${scan?.criticalCount ?? 0} critical, ${scan?.highCount ?? 0} high)`,
    })
  } else if (status === "failed") {
    entries.push({
      id: `log-fail-${scan?.id || "live"}`,
      timestamp: scan?.completedAt || new Date().toISOString(),
      level: "error",
      module: "Core Engine",
      message: "Scan pipeline execution terminated with failure state",
    })
  } else if (status === "cancelled") {
    entries.push({
      id: `log-cancel-${scan?.id || "live"}`,
      timestamp: scan?.completedAt || new Date().toISOString(),
      level: "warning",
      module: "Core Engine",
      message: "Scan was cancelled by operator",
    })
  }

  return entries
}

export function useScanEngine() {
  /* ── Target Selection State ── */
  const [targets, setTargets] = useState<Target[]>([])
  const [selectedTargetId, setSelectedTargetId] = useState<string>("")
  const [selectedProjectId, setSelectedProjectId] = useState<string>("")
  const [selectedTargetUrl, setSelectedTargetUrl] = useState<string>("")

  /* ── Scan Configuration State ── */
  const [scanType, setScanType] = useState<ScanType>("full")
  const [selectedModuleIds, setSelectedModuleIds] = useState<string[]>(
    AVAILABLE_MODULES.map((m) => m.id),
  )
  const [maxDepth, setMaxDepth] = useState<number>(10)
  const [maxConcurrency, setMaxConcurrency] = useState<number>(5)
  const [followRedirects, setFollowRedirects] = useState<boolean>(true)
  const [includePaths, setIncludePaths] = useState<string[]>(["/*"])
  const [excludePaths, setExcludePaths] = useState<string[]>(["/static/*", "/logout"])
  const [authentication, setAuthentication] = useState<boolean>(false)
  const [authHeader, setAuthHeader] = useState<string>("")

  /* ── Active Backend Scan State ── */
  const [activeScanId, setActiveScanId] = useState<string | null>(null)
  const [activeScan, setActiveScan] = useState<Scan | null>(null)
  const [scanFindings, setScanFindings] = useState<any[]>([])
  const [status, setStatus] = useState<ScanStatus>("idle")
  const [overallProgress, setOverallProgress] = useState<number>(0)

  // Target selection helper
  const handleSelectTargetId = useCallback(
    (targetId: string) => {
      const found = targets.find((t) => t.id === targetId)
      if (found) {
        setSelectedTargetId(found.id)
        setSelectedProjectId(found.projectId)
        setSelectedTargetUrl(found.url)
      } else {
        setSelectedTargetId(targetId)
      }
    },
    [targets],
  )

  const handleSelectTargetUrl = useCallback(
    (url: string) => {
      setSelectedTargetUrl(url)
      // Normalize for matching: trim, lowercase, strip trailing slash
      const normalize = (u: string) => u.trim().toLowerCase().replace(/\/$/, "")
      const normUrl = normalize(url)
      const found = targets.find((t) => normalize(t.url) === normUrl)
      if (found) {
        setSelectedTargetId(found.id)
        setSelectedProjectId(found.projectId)
      } else {
        // Clear stale target ID so a new target will be auto-registered on startScan
        setSelectedTargetId("")
        setSelectedProjectId("")
      }
    },
    [targets],
  )

  // Attach to an existing scan (e.g. running or from history)
  const attachScan = useCallback(async (scanId: string) => {
    try {
      const scan = await scansService.getScan(scanId)
      setActiveScanId(scan.id)
      setActiveScan(scan)
      setSelectedTargetId(scan.targetId)
      setSelectedProjectId(scan.projectId)
      setSelectedTargetUrl(scan.targetUrl)
      setStatus(scan.status)
      setOverallProgress(scan.progress)
      setScanType(scan.type)

      const findings = await scansService.getScanFindings(scan.id)
      setScanFindings(findings as any[])
    } catch (err) {
      console.error("Failed to attach to scan:", err)
    }
  }, [])

  // Initial load: Fetch targets and check for currently active scans
  useEffect(() => {
    targetsService
      .getTargets()
      .then((items) => {
        setTargets(items)
        // Never automatically select the first target - require deliberate selection
      })
      .catch((err) => {
        console.error("Failed to load targets in scan engine:", err)
      })

    // Auto-attach to any active scan currently in progress
    scansService
      .getScans()
      .then((scans) => {
        const active = scans.find((s) => s.status === "running" || s.status === "queued")
        if (active) {
          attachScan(active.id)
        }
      })
      .catch(() => {})

    const handleCreated = (e: any) => {
      const newId = e?.detail?.scanId
      if (newId) {
        attachScan(newId)
      }
    }

    window.addEventListener("awsap:scan_created", handleCreated)
    return () => window.removeEventListener("awsap:scan_created", handleCreated)
  }, [])

  // Polling loop for active scan status and findings
  useEffect(() => {
    if (!activeScanId) return
    if (status !== "queued" && status !== "running") return

    let isPolling = true

    const poll = async () => {
      try {
        const scan = await scansService.getScan(activeScanId)
        if (!isPolling) return

        setActiveScan(scan)
        setStatus(scan.status)
        setOverallProgress(scan.progress)

        // Retrieve live findings discovered by scan so far
        const findings = await scansService.getScanFindings(activeScanId)
        if (isPolling) {
          setScanFindings(findings as any[])
        }

        if (scan.status === "completed" || scan.status === "failed" || scan.status === "cancelled") {
          window.dispatchEvent(
            new CustomEvent("awsap:scan_created", { detail: { scanId: scan.id } }),
          )
          if (scan.status === "completed") {
            toast.success(`Scan completed with ${scan.findingsCount} finding(s) discovered`)
          } else if (scan.status === "failed") {
            toast.error("Scan execution failed on server")
          }
        }
      } catch (err) {
        console.error("Error polling scan progress:", err)
      }
    }

    const intervalId = setInterval(poll, 1500)
    // Run first poll immediately
    poll()

    return () => {
      isPolling = false
      clearInterval(intervalId)
    }
  }, [activeScanId, status])

  /* ── Presets & Module Toggles ── */
  const applyPreset = useCallback((preset: ScanPreset) => {
    setScanType(preset.scanType)
    setSelectedModuleIds(preset.modules)
    setMaxDepth(preset.maxDepth)
    setMaxConcurrency(preset.maxConcurrency)
  }, [])

  const toggleModule = useCallback((modId: string) => {
    setSelectedModuleIds((prev) =>
      prev.includes(modId) ? prev.filter((id) => id !== modId) : [...prev, modId],
    )
  }, [])

  const selectAllModules = useCallback(() => {
    setSelectedModuleIds(AVAILABLE_MODULES.map((m) => m.id))
  }, [])

  const deselectAllModules = useCallback(() => {
    setSelectedModuleIds([])
  }, [])

  const loadDefaultTargets = useCallback(async () => {
    try {
      const items = await targetsService.getTargets()
      setTargets(items)
      if (items.length > 0) {
        toast.success(`Loaded ${items.length} assessment target(s)`)
      }
    } catch (err) {
      console.error("Failed to reload targets:", err)
      toast.error("Failed to load targets from server")
    }
  }, [])

  /* ── Real Scan Actions ── */
  const startScan = useCallback(async () => {
    // 1. Validate URL format before anything else
    const rawUrl = selectedTargetUrl.trim()
    if (!rawUrl) {
      toast.error("Please enter an assessment target URL before starting a scan.")
      return
    }
    // Basic URL validation: must look like a URL
    const urlToTest = rawUrl.startsWith("http://") || rawUrl.startsWith("https://")
      ? rawUrl
      : `https://${rawUrl}`
    try {
      const parsed = new URL(urlToTest)
      if (!parsed.hostname || parsed.hostname.length < 2) {
        toast.error("Invalid target URL: missing or malformed hostname.")
        return
      }
    } catch {
      toast.error("Invalid target URL. Please enter a valid HTTP or HTTPS URL.")
      return
    }

    // 2. Resolve target — prefer matching by URL (not stale ID)
    const normalize = (u: string) => u.trim().toLowerCase().replace(/\/$/, "")
    const normUrl = normalize(rawUrl)

    let target = targets.find((t) => normalize(t.url) === normUrl)
    // Also try by selectedTargetId but only if its URL still matches the entered URL
    if (!target && selectedTargetId) {
      const byId = targets.find((t) => t.id === selectedTargetId)
      if (byId && normalize(byId.url) === normUrl) {
        target = byId
      }
    }

    // Auto-resolve or register target on the fly if user entered custom URL or picked preset
    if (!target) {
      try {
        const resolved = await scansService.getOrCreateTargetForUrl(rawUrl)
        const targetObj = resolved.target
        target = targetObj
        setTargets((prev) => {
          const exists = prev.some((x) => x.id === targetObj.id)
          return exists ? prev : [targetObj, ...prev]
        })
        setSelectedTargetId(targetObj.id)
        setSelectedProjectId(targetObj.projectId)
        setSelectedTargetUrl(targetObj.url)
      } catch (err: any) {
        console.error("Failed to auto-register target:", err)
        toast.error("Failed to register target URL for scanning: " + (err?.message || "Unknown error"))
        return
      }
    }

    if (!target) {
      toast.error("Please enter or select an assessment target before starting scan.")
      return
    }

    try {
      setStatus("queued")
      setOverallProgress(0)
      setScanFindings([])

      const created = await scansService.createScan(target.projectId, target.id, {
        scanType,
        targetUrl: target.url,
        targetId: target.id,
        config: {
          targetUrl: target.url,
          modules: selectedModuleIds,
          maxDepth,
          maxConcurrency,
          authHeader: authHeader || undefined,
        },
      })

      // Start asynchronous scan on backend
      const started = await scansService.startScan(created.id)
      setActiveScanId(started.id)
      setActiveScan(started)
      setStatus(started.status)
      setOverallProgress(started.progress)

      toast.success(`Security assessment started on ${target.url}`)
      window.dispatchEvent(
        new CustomEvent("awsap:scan_created", { detail: { scanId: started.id } }),
      )
    } catch (err: any) {
      console.error("Failed to start scan:", err)
      setStatus("failed")
      toast.error(err?.message || "Failed to start scan on server")
    }
  }, [
    targets,
    selectedTargetId,
    selectedTargetUrl,
    scanType,
    selectedModuleIds,
    maxDepth,
    maxConcurrency,
    authHeader,
  ])

  const stopScan = useCallback(async () => {
    if (!activeScanId) return
    try {
      const cancelled = await scansService.cancelScan(activeScanId)
      setActiveScan(cancelled)
      setStatus("cancelled")
      toast.info("Scan cancelled by operator")
      window.dispatchEvent(
        new CustomEvent("awsap:scan_created", { detail: { scanId: activeScanId } }),
      )
    } catch (err: any) {
      console.error("Failed to cancel scan:", err)
      toast.error(err?.message || "Failed to cancel scan")
    }
  }, [activeScanId])

  const pauseScan = useCallback(() => {
    toast.info("Pause is not supported by the passive scan engine. Use Stop Scan to cancel.")
  }, [])

  const resumeScan = useCallback(() => {
    toast.info("Scan resume is not supported. Please initiate a new scan.")
  }, [])

  const resetScan = useCallback(() => {
    setActiveScanId(null)
    setActiveScan(null)
    setScanFindings([])
    setStatus("idle")
    setOverallProgress(0)
    setSelectedTargetId("")
    setSelectedProjectId("")
    setSelectedTargetUrl("")
  }, [])

  /* ── Derived Metrics & State ── */
  const activeSubtask = useMemo(
    () => getSubtaskForProgress(overallProgress),
    [overallProgress],
  )

  const activeModules = useMemo(
    () => {
      if (activeScan?.modules && activeScan.modules.length > 0) {
        return activeScan.modules
      }
      return computeModuleStates(selectedModuleIds, overallProgress, status)
    },
    [activeScan?.modules, selectedModuleIds, overallProgress, status],
  )

  const logs = useMemo(
    () => computeRealLogs(activeScan, scanFindings, status, selectedTargetUrl, scanType),
    [activeScan, scanFindings, status, selectedTargetUrl, scanType],
  )

  const currentModuleIndex = useMemo(() => {
    const activeIdx = activeModules.findIndex((m) => m.status === "running")
    return activeIdx >= 0 ? activeIdx : 0
  }, [activeModules])

  const elapsedSeconds = useMemo(() => {
    if (!activeScan?.startedAt) return 0
    const startMs = new Date(activeScan.startedAt).getTime()
    const endMs = activeScan.completedAt ? new Date(activeScan.completedAt).getTime() : Date.now()
    return Math.max(0, Math.floor((endMs - startMs) / 1000))
  }, [activeScan?.startedAt, activeScan?.completedAt, status])

  const estimatedSecondsRemaining = useMemo(() => {
    if (status !== "running" || overallProgress <= 0 || overallProgress >= 100) return 0
    const estimatedTotal = (elapsedSeconds / overallProgress) * 100
    return Math.max(0, Math.round(estimatedTotal - elapsedSeconds))
  }, [status, overallProgress, elapsedSeconds])

  const criticalCount = activeScan?.criticalCount ?? 0
  const highCount = activeScan?.highCount ?? 0
  const mediumCount = activeScan?.mediumCount ?? 0
  const lowCount = activeScan?.lowCount ?? 0
  const infoCount = activeScan?.infoCount ?? 0
  const totalFindingsCount = activeScan?.findingsCount ?? scanFindings.length

  const requestsPerSec = status === "running" ? 1 : 0
  const totalRequests = activeScan?.modules && activeScan.modules.length > 0
    ? activeScan.modules.filter((m) => m.status === "completed").length
    : overallProgress > 0 ? Math.max(1, Math.round(overallProgress / 10)) : 0
  const activeThreads = status === "running" ? 1 : 0
  const memoryMb = 128
  const endpointsCrawled = activeScan ? 1 : 0
  const currentEndpoint = selectedTargetUrl

  return {
    /* Configuration State */
    targets,
    selectedTargetId,
    setSelectedTargetId: handleSelectTargetId,
    selectedProjectId,
    setSelectedProjectId,
    selectedTargetUrl,
    setSelectedTargetUrl: handleSelectTargetUrl,
    scanType,
    setScanType,
    selectedModuleIds,
    setSelectedModuleIds,
    maxDepth,
    setMaxDepth,
    maxConcurrency,
    setMaxConcurrency,
    followRedirects,
    setFollowRedirects,
    includePaths,
    setIncludePaths,
    excludePaths,
    setExcludePaths,
    authentication,
    setAuthentication,
    authHeader,
    setAuthHeader,

    /* Engine State */
    status,
    overallProgress,
    currentModuleIndex,
    activeSubtask,
    currentEndpoint,
    elapsedSeconds,
    estimatedSecondsRemaining,

    /* Metrics */
    requestsPerSec,
    totalRequests,
    activeThreads,
    memoryMb,
    endpointsCrawled,

    /* Findings */
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
    infoCount,
    totalFindingsCount,

    /* Modules & Logs */
    activeModules,
    logs,

    /* Data & Actions */
    AVAILABLE_MODULES,
    SCAN_PRESETS,
    startScan,
    pauseScan,
    resumeScan,
    stopScan,
    resetScan,
    attachScan,
    applyPreset,
    toggleModule,
    selectAllModules,
    deselectAllModules,
    loadDefaultTargets,
  }
}

export type ScanEngineReturn = ReturnType<typeof useScanEngine>
