/**
 * Targets Service — API client integration for Target Management.
 *
 * Connects the frontend to FastAPI target endpoints:
 *   - POST /api/v1/projects/{project_id}/targets
 *   - GET  /api/v1/projects/{project_id}/targets
 *   - GET  /api/v1/projects/{project_id}/targets/{target_id}
 */

import type { Target, TargetType, TargetStatus, ValidationStatus, TargetRiskLevel } from "@/types"
import { apiClient } from "./api-client"
import { projectsService } from "./projects.service"

interface BackendTarget {
  id: string
  project_id: string
  url: string
  type: string
  status: string
  validation_status: string
  risk_level?: string
  total_scans?: number
  total_findings?: number
  critical_findings?: number
  tags?: string[]
  created_at: string
  updated_at: string
}

export function normaliseTarget(raw: BackendTarget): Target {
  return {
    id: raw.id,
    projectId: raw.project_id,
    url: raw.url,
    type: (raw.type?.toLowerCase() || "web") as TargetType,
    status: (raw.status?.toLowerCase() || "active") as TargetStatus,
    validationStatus: (raw.validation_status?.toLowerCase() || "pending") as ValidationStatus,
    riskLevel: (raw.risk_level?.toLowerCase() || "medium") as TargetRiskLevel,
    tags: raw.tags || ["web"],
    scope: ["/*"],
    description: `Security assessment target ${raw.url}`,
    totalScans: raw.total_scans || 0,
    totalFindings: raw.total_findings || 0,
    criticalFindings: raw.critical_findings || 0,
    scanHistory: [],
    createdAt: raw.created_at,
    updatedAt: raw.updated_at,
  }
}

export const targetsService = {
  /**
   * DELETE /targets/{targetId} or /projects/{projectId}/targets/{targetId}
   * Supports both flat route and project-scoped target deletion.
   */
  deleteTarget: async (projectIdOrTargetId: string, maybeTargetId?: string): Promise<void> => {
    if (maybeTargetId) {
      await apiClient.delete(`/projects/${projectIdOrTargetId}/targets/${maybeTargetId}`)
    } else {
      await apiClient.delete(`/targets/${projectIdOrTargetId}`)
    }
  },

  /**
   * DELETE /targets/{targetId} — Remove a target by ID (flat route)
   */
  deleteTargetById: async (targetId: string): Promise<void> => {
    await apiClient.delete(`/targets/${targetId}`)
  },

  /**
   * DELETE /projects/{projectId}/targets/{targetId} — Remove a target under a project
   */
  deleteProjectTarget: async (projectId: string, targetId: string): Promise<void> => {
    await apiClient.delete(`/projects/${projectId}/targets/${targetId}`)
  },

  /**
   * GET /targets/{targetId} — Get target details by ID (flat route)
   */
  getTargetById: async (targetId: string): Promise<Target> => {
    const raw = await apiClient.get<BackendTarget>(`/targets/${targetId}`)
    return normaliseTarget(raw)
  },

  /**
   * List all targets across user projects (or for a specific project).
   */
  getTargets: async (projectId?: string): Promise<Target[]> => {
    if (projectId) {
      const items = await apiClient.get<BackendTarget[]>(`/projects/${projectId}/targets`)
      return items.map(normaliseTarget)
    }

    // Fast-path: Fetch all user targets in a single request
    try {
      const items = await apiClient.get<BackendTarget[]>("/targets")
      return items.map(normaliseTarget)
    } catch {
      // Fallback: Fetch projects first then aggregate targets
      const projects = await projectsService.getProjects()
      if (projects.length === 0) return []

      const allTargets: Target[] = []
      for (const proj of projects) {
        try {
          const items = await apiClient.get<BackendTarget[]>(`/projects/${proj.id}/targets`)
          allTargets.push(...items.map(normaliseTarget))
        } catch {
          // Continue for next projects if empty
        }
      }
      return allTargets
    }
  },

  getTarget: async (projectIdOrTargetId: string, maybeTargetId?: string): Promise<Target> => {
    if (maybeTargetId) {
      const raw = await apiClient.get<BackendTarget>(`/projects/${projectIdOrTargetId}/targets/${maybeTargetId}`)
      return normaliseTarget(raw)
    }
    const raw = await apiClient.get<BackendTarget>(`/targets/${projectIdOrTargetId}`)
    return normaliseTarget(raw)
  },

  createTarget: async (
    projectId: string,
    payload: {
      url: string
      type?: string
      tags?: string[]
    }
  ): Promise<Target> => {
    const raw = await apiClient.post<BackendTarget>(`/projects/${projectId}/targets`, {
      url: payload.url,
      type: payload.type || "web",
    })
    return normaliseTarget(raw)
  },
}
