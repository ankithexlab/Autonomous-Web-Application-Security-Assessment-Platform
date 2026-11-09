export type Severity = "critical" | "high" | "medium" | "low" | "info"

export type FindingStatus =
  | "open"
  | "confirmed"
  | "in_progress"
  | "resolved"
  | "reopened"
  | "false_positive"
  | "accepted_risk"

export interface CvssMetrics {
  score: number
  vector: string
  attackVector: "Network" | "Adjacent" | "Local" | "Physical"
  attackComplexity: "Low" | "High"
  privilegesRequired: "None" | "Low" | "High"
  userInteraction: "None" | "Required"
  scope: "Unchanged" | "Changed"
  confidentialityImpact: "None" | "Low" | "High"
  integrityImpact: "None" | "Low" | "High"
  availabilityImpact: "None" | "Low" | "High"
}

export interface OwaspMapping {
  id: string
  name: string
  year: number
  category: string
}

export interface AiExplanation {
  summary: string
  impact: string
  exploitScenario: string
  businessRisk: string
}

export interface RemediationStep {
  order: number
  title: string
  description: string
  codeExample?: string
  language?: string
}

export interface Finding {
  id: string
  scanId: string
  projectId: string
  title: string
  description: string
  severity: Severity
  status: FindingStatus
  category: string
  affectedUrl: string
  affectedParameter?: string
  httpMethod?: string
  evidence?: string
  cvssScore?: number
  cvss?: CvssMetrics
  cweId?: string
  cweName?: string
  owasp?: OwaspMapping[]
  aiExplanation?: AiExplanation
  aiExplanationJson?: string
  aiRemediationJson?: string
  remediation?: string
  remediationSteps?: RemediationStep[]
  references?: string[]
  tags?: string[]
  assignee?: string
  createdAt: string
  updatedAt: string
}
