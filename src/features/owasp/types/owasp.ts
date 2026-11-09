/* ── OWASP Top 10 Types ── */

export type OWASPCategory =
  | "A01:2021" // Broken Access Control
  | "A02:2021" // Cryptographic Failures
  | "A03:2021" // Injection
  | "A04:2021" // Insecure Design
  | "A05:2021" // Security Misconfiguration
  | "A06:2021" // Vulnerable and Outdated Components
  | "A07:2021" // Identification and Authentication Failures
  | "A08:2021" // Software and Data Integrity Failures
  | "A09:2021" // Security Logging and Monitoring Failures
  | "A10:2021" // Server-Side Request Forgery

export type OWASPSeverity = "critical" | "high" | "medium" | "low" | "info"

export type OWASPCoverageStatus = "covered" | "partial" | "uncovered"

export interface OWASPCategoryMeta {
  id: OWASPCategory
  rank: number
  name: string
  shortName: string
  description: string
  color: string
  bgColor: string
  borderColor: string
}

export interface OWASPFinding {
  id: string
  categoryId: OWASPCategory
  title: string
  description: string
  severity: OWASPSeverity
  cvssScore: number
  affectedAsset: string
  discoveredAt: string
  status: "open" | "in_progress" | "resolved" | "accepted"
  evidence?: string
  remediation?: string
}

export interface OWASPCoverage {
  categoryId: OWASPCategory
  status: OWASPCoverageStatus
  findingsCount: number
  criticalCount: number
  highCount: number
  mediumCount: number
  lowCount: number
  lastScanned?: string
  coveragePercent: number
}

export interface OWASPRiskTrendPoint {
  date: string
  riskScore: number
  criticalFindings: number
  highFindings: number
}

export interface OWASPStats {
  totalFindings: number
  criticalCount: number
  highCount: number
  mediumCount: number
  lowCount: number
  infoCount: number
  securityScore: number
  riskScore: number
  overallCoverage: number
  resolvedCount: number
}
