export type ScanStatus =
  | "idle"
  | "queued"
  | "running"
  | "paused"
  | "completed"
  | "failed"
  | "cancelled"

export type ScanType = "full" | "quick" | "targeted" | "continuous" | "active" | "passive"

export type ScanModuleStatus = "pending" | "running" | "completed" | "failed" | "skipped"

export interface ScanModule {
  id: string
  name: string
  description: string
  status: ScanModuleStatus
  progress: number
  findingsCount: number
  startedAt?: string
  completedAt?: string
  duration?: string
}

export interface ScanLogEntry {
  id: string
  timestamp: string
  level: "info" | "warning" | "error" | "debug" | "success"
  module: string
  message: string
}

export interface ScanConfig {
  scanType: ScanType
  targetId: string
  targetUrl: string
  modules: string[]
  maxDepth: number
  maxConcurrency: number
  followRedirects: boolean
  includePaths: string[]
  excludePaths: string[]
  authentication: boolean
  customHeaders: Record<string, string>
  activeConfirmed?: boolean
}

export interface Scan {
  id: string
  projectId: string
  targetId: string
  targetUrl: string
  type: ScanType
  status: ScanStatus
  progress: number
  findingsCount: number
  criticalCount: number
  highCount: number
  mediumCount: number
  lowCount: number
  infoCount: number
  modules: ScanModule[]
  logs: ScanLogEntry[]
  config: ScanConfig
  startedAt?: string
  completedAt?: string
  estimatedTimeRemaining?: string
  duration?: string
  modulesJson?: string | null
  createdAt: string
}
