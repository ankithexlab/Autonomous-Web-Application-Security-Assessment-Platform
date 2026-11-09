export type ReportType = "executive" | "technical" | "compliance" | "custom"

export type ReportStatus = "generating" | "completed" | "failed"

export type ReportFormat = "pdf" | "html" | "json" | "csv"

export interface ReportExecutiveSummary {
  overallRiskScore: number
  riskGrade: "A" | "B" | "C" | "D" | "F"
  summaryText: string
  keyTakeaways: string[]
  criticalFindingsCount: number
  highFindingsCount: number
  mediumFindingsCount: number
  lowFindingsCount: number
  recommendations: string[]
}

export interface ReportChartData {
  severityDistribution: { severity: string; count: number; fill: string }[]
  categoryDistribution: { category: string; count: number }[]
  trendData: { month: string; critical: number; high: number; medium: number; low: number }[]
}

export interface Report {
  id: string
  projectId: string
  projectName: string
  title: string
  description?: string
  type: ReportType
  status: ReportStatus
  availableFormats: ReportFormat[]
  fileSizeMb?: number
  author: string
  targetUrls: string[]
  executiveSummary?: ReportExecutiveSummary
  chartData?: ReportChartData
  createdAt: string
  updatedAt: string
}
