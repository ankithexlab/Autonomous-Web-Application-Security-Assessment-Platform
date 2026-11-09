/**
 * Scan Service — API client integration for Scan Management.
 *
 * Connects the frontend to FastAPI scan endpoints:
 *   - POST  /api/v1/projects/{project_id}/targets/{target_id}/scans
 *   - GET   /api/v1/projects/{project_id}/targets/{target_id}/scans
 *   - GET   /api/v1/projects/{project_id}/scans
 *   - GET   /api/v1/scans
 *   - GET   /api/v1/scans/{scan_id}
 *   - PATCH /api/v1/scans/{scan_id}/cancel
 */

import type { Scan, ScanModule, ScanModuleStatus, ScanStatus, ScanType, Target } from "@/types"
import { apiClient } from "./api-client"
import { normaliseTarget } from "./targets.service"

// ── Backend Scan Response Shape (snake_case) ─────────────────────

interface BackendScan {
  id: string
  target_id: string
  project_id: string
  user_id: string
  scan_type: string
  status: string
  progress: number
  findings_count: number
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  info_count: number
  config_json?: string | null
  modules_json?: string | null
  started_at?: string | null
  completed_at?: string | null
  created_at: string
  updated_at: string
  target_url?: string | null
}

interface BackendScanListResponse {
  items: BackendScan[]
  total: number
}

export interface CreateScanPayload {
  scanType: ScanType
  config?: Record<string, unknown>
  activeConfirmed?: boolean
  targetUrl?: string
  targetId?: string
}

// ── Normaliser ───────────────────────────────────────────────────

function parseModulesJson(modulesJson?: string | null): ScanModule[] {
  if (!modulesJson) return []
  try {
    const parsed = typeof modulesJson === "string" ? JSON.parse(modulesJson) : modulesJson
    if (!parsed || typeof parsed !== "object") return []

    return Object.entries(parsed).map(([key, val]: [string, any]) => {
      const status: ScanModuleStatus =
        val?.status === "completed"
          ? "completed"
          : val?.status === "error"
          ? "failed"
          : val?.status === "skipped"
          ? "skipped"
          : val?.status === "running"
          ? "running"
          : "pending"

      const rawName = val?.module_name || key.replace(/_/g, " ").replace(/\b\w/g, (c: string) => c.toUpperCase())
      const description =
        val?.reason ||
        (val?.error ? `Error: ${val.error}` : "") ||
        (status === "completed" ? "Module assessment finished" : "Module queued")

      return {
        id: key,
        name: rawName,
        description,
        status,
        progress: status === "completed" ? 100 : status === "running" ? 50 : 0,
        findingsCount: val?.findings_count || (Array.isArray(val?.discovered) ? val.discovered.length : 0),
        duration: val?.elapsed_seconds ? `${val.elapsed_seconds}s` : undefined,
      }
    })
  } catch (err) {
    console.error("Failed to parse modules_json:", err)
    return []
  }
}

function normaliseScan(raw: BackendScan): Scan {
  const statusLower = (raw.status || "QUEUED").toLowerCase() as ScanStatus
  const parsedModules = parseModulesJson(raw.modules_json)

  return {
    id: raw.id,
    projectId: raw.project_id,
    targetId: raw.target_id,
    targetUrl: raw.target_url || "",
    type: (raw.scan_type || "full") as ScanType,
    status: statusLower,
    progress: raw.progress || 0,
    findingsCount: raw.findings_count || 0,
    criticalCount: raw.critical_count || 0,
    highCount: raw.high_count || 0,
    mediumCount: raw.medium_count || 0,
    lowCount: raw.low_count || 0,
    infoCount: raw.info_count || 0,
    modules: parsedModules,
    modulesJson: raw.modules_json,
    logs: [],
    config: {
      scanType: (raw.scan_type || "full") as ScanType,
      targetId: raw.target_id,
      targetUrl: raw.target_url || "",
      modules: [],
      maxDepth: 10,
      maxConcurrency: 5,
      followRedirects: true,
      includePaths: ["/*"],
      excludePaths: [],
      authentication: false,
      customHeaders: {},
    },
    startedAt: raw.started_at || undefined,
    completedAt: raw.completed_at || undefined,
    createdAt: raw.created_at,
  }
}

// ── Projects & Targets Helper Service ───────────────────────────

interface BackendProject {
  id: string
  user_id: string
  name: string
  description?: string
  status: string
  risk_level: string
  created_at: string
  updated_at: string
}

interface BackendTarget {
  id: string
  project_id: string
  url: string
  type: string
  status: string
  validation_status: string
  created_at: string
  updated_at: string
}

// ── Scan Service ─────────────────────────────────────────────────

export const scansService = {
  /**
   * Helper to ensure an active project & target exist for creating scans from UI.
   */
  getOrCreateDefaultTarget: async (): Promise<{ projectId: string; targetId: string }> => {
    try {
      const projects = await apiClient.get<BackendProject[]>("/projects")
      let project = projects[0]
      if (!project) {
        project = await apiClient.post<BackendProject>("/projects", {
          name: "Default Security Project",
          description: "Auto-created project for scan assessments",
          risk_level: "medium",
        })
      }

      const targets = await apiClient.get<BackendTarget[]>(`/projects/${project.id}/targets`)
      const target = targets[0]
      if (!target) {
        throw new Error("No target found in project. Please add or select an assessment target URL.")
      }

      return { projectId: project.id, targetId: target.id }
    } catch (error) {
      console.error("Failed to resolve project/target:", error)
      throw error
    }
  },

  /**
   * Resolve an existing target for the given URL, or create a new target under
   * the user's project if it does not yet exist.
   */
  getOrCreateTargetForUrl: async (
    targetUrl: string,
  ): Promise<{ projectId: string; targetId: string; target: Target }> => {
    let cleanUrl = targetUrl.trim()
    if (!cleanUrl.startsWith("http://") && !cleanUrl.startsWith("https://")) {
      cleanUrl = `https://${cleanUrl}`
    }

    try {
      const directTarget = await apiClient.post<BackendTarget>("/targets", {
        url: cleanUrl,
        type: "web",
      })
      return {
        projectId: directTarget.project_id,
        targetId: directTarget.id,
        target: normaliseTarget(directTarget),
      }
    } catch (err: any) {
      // If server returned validation/SSRF error (status 400) or auth error, propagate immediately
      if (err?.status && err.status !== 404) {
        throw err
      }

      // Fallback: look up user projects and find/create target
      const projects = await apiClient.get<BackendProject[]>("/projects")
      let project = projects[0]
      if (!project) {
        project = await apiClient.post<BackendProject>("/projects", {
          name: "Web Security Assessment",
          description: "Default workspace for security assessments",
          risk_level: "medium",
        })
      }

      const targets = await apiClient.get<BackendTarget[]>(`/projects/${project.id}/targets`)
      const cleanMatch = cleanUrl.toLowerCase().replace(/\/$/, "")
      const existing = targets.find((t) => t.url.toLowerCase().replace(/\/$/, "") === cleanMatch)
      if (existing) {
        return { projectId: project.id, targetId: existing.id, target: normaliseTarget(existing) }
      }

      const newTarget = await apiClient.post<BackendTarget>(`/projects/${project.id}/targets`, {
        url: cleanUrl,
        type: "web",
      })
      return { projectId: project.id, targetId: newTarget.id, target: normaliseTarget(newTarget) }
    }
  },

  /**
   * POST /projects/{projectId}/targets/{targetId}/scans
   */
  createScan: async (
    projectId: string,
    targetId: string,
    payload: CreateScanPayload
  ): Promise<Scan> => {
    const raw = await apiClient.post<BackendScan>(
      `/projects/${projectId}/targets/${targetId}/scans`,
      {
        scan_type: payload.scanType,
        config: payload.config,
        active_confirmed: payload.activeConfirmed ?? false,
        target_url: payload.targetUrl || (payload.config?.targetUrl as string) || undefined,
        target_id: targetId,
        project_id: projectId,
      }
    )
    return normaliseScan(raw)
  },

  /**
   * POST /scans — Direct scan creation endpoint
   */
  createDirectScan: async (payload: CreateScanPayload): Promise<Scan> => {
    const raw = await apiClient.post<BackendScan>("/scans", {
      scan_type: payload.scanType,
      config: payload.config,
      active_confirmed: payload.activeConfirmed ?? false,
      target_url: payload.targetUrl || (payload.config?.targetUrl as string) || undefined,
      target_id: payload.targetId || undefined,
    })
    return normaliseScan(raw)
  },

  /**
   * GET /scans — List all scans for the current authenticated user
   */
  getScans: async (): Promise<Scan[]> => {
    const raw = await apiClient.get<BackendScanListResponse>("/scans")
    return raw.items.map(normaliseScan)
  },

  /**
   * GET /scans/{scanId}
   */
  getScan: async (scanId: string): Promise<Scan> => {
    const raw = await apiClient.get<BackendScan>(`/scans/${scanId}`)
    return normaliseScan(raw)
  },

  /**
   * PATCH /scans/{scanId}/cancel
   */
  cancelScan: async (scanId: string): Promise<Scan> => {
    const raw = await apiClient.patch<BackendScan>(`/scans/${scanId}/cancel`)
    return normaliseScan(raw)
  },

  /**
   * POST /scans/{scanId}/start — Triggers scanner engine execution
   */
  startScan: async (scanId: string): Promise<Scan> => {
    const raw = await apiClient.post<BackendScan>(`/scans/${scanId}/start`)
    return normaliseScan(raw)
  },

  /**
   * DELETE /scans/{scanId} — Permanently delete a scan record
   */
  deleteScan: async (scanId: string): Promise<void> => {
    await apiClient.delete(`/scans/${scanId}`)
  },

  /**
   * GET /scans/{scanId}/findings — Returns vulnerabilities discovered by scan
   */
  getScanFindings: async (scanId: string): Promise<unknown[]> => {
    return await apiClient.get<unknown[]>(`/scans/${scanId}/findings`)
  },
}
