export type TargetType = "web" | "api" | "network"

export type TargetStatus = "active" | "inactive" | "scanning"

export type ValidationStatus = "verified" | "pending" | "failed" | "unverified"

export type TargetRiskLevel = "critical" | "high" | "medium" | "low"

export interface TargetScanHistory {
  id: string
  scanType: string
  status: "completed" | "failed" | "running"
  findingsCount: number
  duration: string
  startedAt: string
  completedAt?: string
}

export interface Target {
  id: string
  projectId: string
  url: string
  type: TargetType
  status: TargetStatus
  validationStatus: ValidationStatus
  riskLevel?: TargetRiskLevel
  tags: string[]
  scope: string[]
  description?: string
  ipAddress?: string
  technology?: string[]
  lastScannedAt?: string
  totalScans: number
  totalFindings: number
  criticalFindings: number
  scanHistory: TargetScanHistory[]
  createdAt: string
  updatedAt: string
}
