export type ProjectStatus = "active" | "archived" | "paused"

export type ProjectRiskLevel = "critical" | "high" | "medium" | "low"

export interface Project {
  id: string
  name: string
  description?: string
  status: ProjectStatus
  riskLevel: ProjectRiskLevel
  targetCount: number
  scanCount: number
  criticalCount: number
  highCount: number
  mediumCount: number
  lowCount: number
  tags: string[]
  owner: string
  createdAt: string
  updatedAt: string
}
