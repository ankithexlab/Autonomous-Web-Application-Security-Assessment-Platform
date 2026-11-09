/**
 * Dashboard API Service.
 *
 * Fetches real-time SOC summary metrics from GET /api/v1/dashboard/summary.
 */

import { apiClient } from "./api-client"

export interface DashboardSummary {
  total_projects: number
  total_targets: number
  total_scans: number
  running_scans: number
  completed_scans: number
  failed_scans: number
  total_findings: number
  critical_findings: number
  high_findings: number
  medium_findings: number
  low_findings: number
  info_findings: number
  overall_security_score: number
  recent_scans: {
    id: string
    target_name: string
    target_url: string
    project_id?: string
    project_name?: string
    scan_type: string
    status: string
    created_at: string | null
    completed_at: string | null
    findings_count?: number
    critical_count?: number
    high_count?: number
    medium_count?: number
    low_count?: number
  }[]
  recent_findings: {
    id: string
    title: string
    severity: "critical" | "high" | "medium" | "low" | "info"
    confidence: string
    category: string
    owasp_category?: string
    target: string
    created_at: string | null
    cvss_score: number
  }[]
  recent_reports: {
    id: string
    title: string
    report_type: string
    file_format: string
    status: string
    project_name?: string
    created_at: string | null
    overall_score?: number
  }[]
  owasp_distribution: {
    category: string
    name?: string
    count: number
  }[]
  recent_activities: {
    id: string
    type: string
    title: string
    description: string
    timestamp: string | null
    severity?: string
    scan_type?: string
    scan_status?: string
  }[]
  scan_activity?: {
    day: string
    completed: number
    failed: number
  }[]
  vulnerability_trend?: {
    date: string
    critical: number
    high: number
    medium: number
    low: number
  }[]
  threat_trend?: {
    period: string
    velocity: number
    exploitsPrevented: number
    activeThreats: number
  }[]
  risk_factors?: {
    label: string
    value: number
    status: "good" | "warning" | "danger"
  }[]
}

export interface NotificationItem {
  id: string
  title: string
  message: string
  timestamp: string | null
  type: "critical" | "warning" | "success" | "info"
  read: boolean
}

export const dashboardService = {
  /**
   * GET /dashboard/summary — Fetch aggregated SOC dashboard summary
   */
  getSummary: async (): Promise<DashboardSummary> => {
    return await apiClient.get<DashboardSummary>("/dashboard/summary")
  },

  /**
   * GET /dashboard/notifications — Fetch real-time security notifications
   */
  getNotifications: async (): Promise<NotificationItem[]> => {
    return await apiClient.get<NotificationItem[]>("/dashboard/notifications")
  },
}
