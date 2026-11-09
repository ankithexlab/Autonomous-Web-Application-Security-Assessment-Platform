/**
 * Projects Service — API client integration for Security Projects.
 *
 * Connects the frontend to FastAPI project endpoints:
 *   - GET    /api/v1/projects
 *   - POST   /api/v1/projects
 *   - GET    /api/v1/projects/{id}
 *   - PUT    /api/v1/projects/{id}
 *   - DELETE /api/v1/projects/{id}
 */

import type { Project, ProjectStatus, ProjectRiskLevel } from "@/types"
import { apiClient } from "./api-client"

interface BackendProject {
  id: string
  user_id: string
  name: string
  description?: string
  status: string
  risk_level: string
  target_count?: number
  scan_count?: number
  critical_count?: number
  high_count?: number
  medium_count?: number
  low_count?: number
  tags?: string[]
  owner?: string
  created_at: string
  updated_at: string
}

function normaliseProject(raw: BackendProject): Project {
  return {
    id: raw.id,
    name: raw.name,
    description: raw.description || "",
    status: (raw.status?.toLowerCase() || "active") as ProjectStatus,
    riskLevel: (raw.risk_level?.toLowerCase() || "medium") as ProjectRiskLevel,
    targetCount: raw.target_count || 0,
    scanCount: raw.scan_count || 0,
    criticalCount: raw.critical_count || 0,
    highCount: raw.high_count || 0,
    mediumCount: raw.medium_count || 0,
    lowCount: raw.low_count || 0,
    tags: raw.tags || ["default"],
    owner: raw.owner || "Security Team",
    createdAt: raw.created_at,
    updatedAt: raw.updated_at,
  }
}

export const projectsService = {
  getProjects: async (): Promise<Project[]> => {
    const items = await apiClient.get<BackendProject[]>("/projects")
    return items.map(normaliseProject)
  },

  getProject: async (id: string): Promise<Project> => {
    const raw = await apiClient.get<BackendProject>(`/projects/${id}`)
    return normaliseProject(raw)
  },

  createProject: async (data: {
    name: string
    description?: string
    status?: string
    risk_level?: string
    tags?: string[]
  }): Promise<Project> => {
    const raw = await apiClient.post<BackendProject>("/projects", {
      name: data.name,
      description: data.description || "",
      status: data.status || "active",
      risk_level: data.risk_level || "medium",
      tags: data.tags || [],
    })
    return normaliseProject(raw)
  },

  updateProject: async (
    id: string,
    data: Partial<{
      name: string
      description: string
      status: string
      risk_level: string
      tags: string[]
    }>
  ): Promise<Project> => {
    const raw = await apiClient.put<BackendProject>(`/projects/${id}`, data)
    return normaliseProject(raw)
  },

  deleteProject: async (id: string): Promise<void> => {
    await apiClient.delete(`/projects/${id}`)
  },
}
