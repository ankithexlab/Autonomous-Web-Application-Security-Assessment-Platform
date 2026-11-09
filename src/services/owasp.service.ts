import { apiClient } from "./api-client"

export interface BackendOWASPCategorySummary {
  category_id: string
  category_name: string
  short_name: string
  rank: number
  findings_count: number
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  info_count: number
  compliance_status: "PASS" | "WARNING" | "FAIL"
}

export interface BackendOWASPStatsResponse {
  total_vulnerabilities: number
  categories_covered: number
  overall_risk_score: number
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  info_count: number
  category_breakdown: BackendOWASPCategorySummary[]
  risk_trend?: {
    date: string
    riskScore: number
    criticalFindings: number
    highFindings: number
  }[]
  most_affected_assets?: {
    asset: string
    findingsCount: number
    criticalCount: number
    riskScore: number
  }[]
  top_findings?: {
    id: string
    categoryId: string
    title: string
    description: string
    severity: "critical" | "high" | "medium" | "low" | "info"
    cvssScore: number
    affectedAsset: string
    discoveredAt: string
    status: string
    remediation: string
  }[]
  scan_timeline?: {
    id: string
    time: string
    event: string
    category: string
    severity: "critical" | "high" | "medium" | "low" | "info"
    target: string
  }[]
}

export const owaspService = {
  /**
   * GET /owasp/summary — Returns aggregated OWASP posture metrics and category breakdown
   */
  getOWASPSummary: async (): Promise<BackendOWASPStatsResponse> => {
    return await apiClient.get<BackendOWASPStatsResponse>("/owasp/summary")
  },
}
