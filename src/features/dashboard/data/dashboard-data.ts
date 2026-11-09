import type { Severity, ScanStatus, ScanType } from "@/types"

export interface DashboardStat {
  label: string
  value: string | number
  change: number
  changeLabel: string
  icon: string
}

export interface VulnerabilityTrendPoint {
  date: string
  critical: number
  high: number
  medium: number
  low: number
}

export interface SeverityCount {
  severity: Severity
  count: number
  fill: string
}

export interface ScanActivityPoint {
  day: string
  completed: number
  failed: number
}

export type ActivityType =
  | "scan_completed"
  | "scan_failed"
  | "scan_cancelled"
  | "scan_started"
  | "scan_running"
  | "scan_queued"
  | "finding_discovered"
  | "finding_resolved"
  | "report_generated"
  | "target_created"
  | "project_created"
  | (string & {})

export interface ActivityItem {
  id: string
  type: ActivityType
  title: string
  description: string
  timestamp: string | null
  severity?: Severity
  scanType?: ScanType
  scanStatus?: ScanStatus
}

export interface RecentFinding {
  id: string
  title: string
  severity: Severity
  category: string
  target: string
  discoveredAt: string
  cvssScore: number
}

export const STATS: DashboardStat[] = [
  {
    label: "Total Scans",
    value: 1284,
    change: 12.5,
    changeLabel: "vs last month",
    icon: "radar",
  },
  {
    label: "Open Findings",
    value: 342,
    change: -8.3,
    changeLabel: "vs last month",
    icon: "shield-alert",
  },
  {
    label: "Critical Issues",
    value: 23,
    change: -15.2,
    changeLabel: "vs last month",
    icon: "alert-triangle",
  },
  {
    label: "Security Score",
    value: "78/100",
    change: 4.1,
    changeLabel: "vs last month",
    icon: "shield-check",
  },
]

export const VULNERABILITY_TREND: VulnerabilityTrendPoint[] = [
  { date: "Jan", critical: 18, high: 45, medium: 78, low: 120 },
  { date: "Feb", critical: 22, high: 52, medium: 85, low: 115 },
  { date: "Mar", critical: 15, high: 48, medium: 72, low: 108 },
  { date: "Apr", critical: 28, high: 58, medium: 90, low: 125 },
  { date: "May", critical: 20, high: 42, medium: 68, low: 98 },
  { date: "Jun", critical: 25, high: 55, medium: 82, low: 110 },
  { date: "Jul", critical: 23, high: 50, medium: 75, low: 105 },
]

export const SEVERITY_DISTRIBUTION: SeverityCount[] = [
  { severity: "critical", count: 23, fill: "var(--chart-5)" },
  { severity: "high", count: 89, fill: "var(--chart-3)" },
  { severity: "medium", count: 156, fill: "var(--chart-4)" },
  { severity: "low", count: 74, fill: "var(--chart-2)" },
]

export const SCAN_ACTIVITY: ScanActivityPoint[] = [
  { day: "Mon", completed: 18, failed: 2 },
  { day: "Tue", completed: 24, failed: 1 },
  { day: "Wed", completed: 32, failed: 3 },
  { day: "Thu", completed: 28, failed: 0 },
  { day: "Fri", completed: 35, failed: 2 },
  { day: "Sat", completed: 12, failed: 1 },
  { day: "Sun", completed: 8, failed: 0 },
]

export const RECENT_ACTIVITY: ActivityItem[] = [
  {
    id: "1",
    type: "finding_discovered",
    title: "SQL Injection Found",
    description: "Critical vulnerability discovered in /api/users endpoint",
    timestamp: "2 minutes ago",
    severity: "critical",
  },
  {
    id: "2",
    type: "scan_completed",
    title: "Full Scan Completed",
    description: "Production environment scan finished — 14 findings",
    timestamp: "18 minutes ago",
    scanType: "full",
    scanStatus: "completed",
  },
  {
    id: "3",
    type: "finding_resolved",
    title: "XSS Vulnerability Resolved",
    description: "Reflected XSS in search parameter has been patched",
    timestamp: "1 hour ago",
    severity: "high",
  },
  {
    id: "4",
    type: "scan_started",
    title: "Quick Scan Started",
    description: "Scanning staging.example.com for OWASP Top 10",
    timestamp: "2 hours ago",
    scanType: "quick",
    scanStatus: "running",
  },
  {
    id: "5",
    type: "report_generated",
    title: "Executive Report Ready",
    description: "Q2 2026 security assessment report generated",
    timestamp: "3 hours ago",
  },
  {
    id: "6",
    type: "finding_discovered",
    title: "Insecure CORS Configuration",
    description: "Wildcard origin allowed on api.example.com",
    timestamp: "5 hours ago",
    severity: "medium",
  },
]

export const RECENT_FINDINGS: RecentFinding[] = [
  {
    id: "f1",
    title: "SQL Injection — User Authentication Bypass",
    severity: "critical",
    category: "Injection",
    target: "api.example.com",
    discoveredAt: "2 min ago",
    cvssScore: 9.8,
  },
  {
    id: "f2",
    title: "Cross-Site Scripting (Reflected)",
    severity: "high",
    category: "XSS",
    target: "app.example.com",
    discoveredAt: "45 min ago",
    cvssScore: 7.5,
  },
  {
    id: "f3",
    title: "Missing Content-Security-Policy Header",
    severity: "medium",
    category: "Headers",
    target: "www.example.com",
    discoveredAt: "2 hours ago",
    cvssScore: 5.3,
  },
  {
    id: "f4",
    title: "Server Version Disclosure",
    severity: "low",
    category: "Information Disclosure",
    target: "api.example.com",
    discoveredAt: "4 hours ago",
    cvssScore: 3.1,
  },
  {
    id: "f5",
    title: "Insecure Cookie — Missing SameSite Attribute",
    severity: "medium",
    category: "Session Management",
    target: "app.example.com",
    discoveredAt: "6 hours ago",
    cvssScore: 4.7,
  },
]

export const SECURITY_SCORE = 78

export const SCORE_BREAKDOWN = [
  { label: "Vulnerability Management", score: 82, maxScore: 100 },
  { label: "Configuration", score: 71, maxScore: 100 },
  { label: "Authentication", score: 90, maxScore: 100 },
  { label: "Data Protection", score: 68, maxScore: 100 },
  { label: "Monitoring", score: 76, maxScore: 100 },
]

export interface RiskMetric {
  score: number
  level: "Low" | "Moderate" | "High" | "Critical"
  change: number
  factors: {
    label: string
    value: number
    status: "good" | "warning" | "danger"
  }[]
}

export const RISK_SCORE_DATA: RiskMetric = {
  score: 34,
  level: "Moderate",
  change: -4.5,
  factors: [
    { label: "Exploitability Index", value: 42, status: "warning" },
    { label: "Attack Surface Exposure", value: 28, status: "good" },
    { label: "Remediation Velocity", value: 65, status: "warning" },
    { label: "Asset Criticality Weight", value: 85, status: "danger" },
  ],
}

export interface RecentScanOverview {
  id: string
  targetName: string
  targetUrl: string
  scanType: ScanType
  status: ScanStatus
  startedAt: string
  duration: string
  endpointsScanned: number
  payloadsTested: number
  findingsCount: {
    critical: number
    high: number
    medium: number
    low: number
  }
}

export const RECENT_SCAN_OVERVIEW: RecentScanOverview = {
  id: "scn-2026-8891",
  targetName: "Production Payment Gateway API",
  targetUrl: "https://api.payments.example.com",
  scanType: "full",
  status: "completed",
  startedAt: "20 minutes ago",
  duration: "4 min 18 sec",
  endpointsScanned: 142,
  payloadsTested: 1240,
  findingsCount: {
    critical: 2,
    high: 5,
    medium: 12,
    low: 8,
  },
}

export interface ThreatTrendPoint {
  period: string
  velocity: number
  exploitsPrevented: number
  activeThreats: number
}

export const THREAT_TREND_DATA: ThreatTrendPoint[] = [
  { period: "Mon", velocity: 45, exploitsPrevented: 140, activeThreats: 12 },
  { period: "Tue", velocity: 62, exploitsPrevented: 185, activeThreats: 18 },
  { period: "Wed", velocity: 88, exploitsPrevented: 240, activeThreats: 23 },
  { period: "Thu", velocity: 74, exploitsPrevented: 210, activeThreats: 19 },
  { period: "Fri", velocity: 95, exploitsPrevented: 290, activeThreats: 28 },
  { period: "Sat", velocity: 50, exploitsPrevented: 160, activeThreats: 14 },
  { period: "Sun", velocity: 40, exploitsPrevented: 130, activeThreats: 10 },
]

