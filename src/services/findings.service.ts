import { apiClient } from "./api-client"
import type { Finding, FindingStatus, Severity } from "@/types"

export interface BackendFindingRead {
  id: string
  scan_id: string
  target_id: string
  project_id: string
  user_id: string
  title: string
  description: string
  severity: string
  status: string
  confidence: string
  category: string
  owasp_category?: string
  cwe_id?: string
  cvss_score?: number
  affected_url?: string
  remediation?: string
  proof_of_concept?: string
  ai_explanation_json?: string
  ai_remediation_json?: string
  created_at: string
  updated_at: string
}

export interface BackendFindingPaginatedResponse {
  items: BackendFindingRead[]
  total: number
  page: number
  page_size: number
  total_pages: number
}

export interface FindingFilterParams {
  page?: number
  pageSize?: number
  severity?: string
  confidence?: string
  owaspCategory?: string
  scanId?: string
  targetId?: string
  projectId?: string
  status?: string
}

function normaliseFinding(raw: BackendFindingRead): Finding {
  const sev = (raw.severity?.toLowerCase() ?? "info") as Severity
  const stat = (raw.status?.toLowerCase() ?? "open") as FindingStatus

  let aiExplanation: any = undefined
  if (raw.ai_explanation_json) {
    try {
      const parsed = JSON.parse(raw.ai_explanation_json)
      aiExplanation = {
        summary: parsed.summary,
        impact: parsed.impact,
        exploitScenario: parsed.risk_explanation,
        businessRisk: parsed.why_it_matters || parsed.impact,
      }
    } catch {
      // ignore parsing error
    }
  }

  let remediationSteps: any = undefined
  if (raw.ai_remediation_json) {
    try {
      const parsedRem = JSON.parse(raw.ai_remediation_json)
      if (Array.isArray(parsedRem.implementation_steps)) {
        remediationSteps = parsedRem.implementation_steps.map((step: string, i: number) => ({
          order: i + 1,
          title: `Step ${i + 1}`,
          description: step,
          codeExample: i === 0 ? parsedRem.secure_code_example : undefined,
          language: i === 0 && parsedRem.secure_code_example ? "python" : undefined,
        }))
      }
    } catch {
      // ignore parsing error
    }
  }

  return {
    id: raw.id,
    scanId: raw.scan_id,
    projectId: raw.project_id,
    title: raw.title,
    description: raw.description,
    severity: ["critical", "high", "medium", "low", "info"].includes(sev) ? sev : "info",
    status: ["open", "confirmed", "in_progress", "resolved", "reopened", "false_positive", "accepted_risk"].includes(stat)
      ? stat
      : "open",
    category: raw.category || "Web Security",
    affectedUrl: raw.affected_url || "",
    evidence: raw.proof_of_concept,
    cvssScore: raw.cvss_score ?? undefined,
    cweId: raw.cwe_id ?? undefined,
    owasp: raw.owasp_category
      ? [
          {
            id: raw.owasp_category.split("-")[0] || "A05:2021",
            name: raw.owasp_category.split("-")[1] || raw.owasp_category,
            year: 2021,
            category: raw.owasp_category,
          },
        ]
      : undefined,
    aiExplanation,
    aiExplanationJson: raw.ai_explanation_json,
    aiRemediationJson: raw.ai_remediation_json,
    remediation: raw.remediation ?? undefined,
    remediationSteps,
    createdAt: raw.created_at,
    updatedAt: raw.updated_at,
  }
}

export const findingsService = {
  /**
   * GET /findings — Returns paginated findings with server-side filters
   */
  getFindings: async (
    params: FindingFilterParams = {},
  ): Promise<{ items: Finding[]; total: number; page: number; totalPages: number }> => {
    const query = new URLSearchParams()
    if (params.page) query.append("page", params.page.toString())
    if (params.pageSize) query.append("page_size", params.pageSize.toString())
    if (params.severity && params.severity !== "all") query.append("severity", params.severity)
    if (params.confidence) query.append("confidence", params.confidence)
    if (params.owaspCategory && params.owaspCategory !== "all") query.append("owasp_category", params.owaspCategory)
    if (params.scanId) query.append("scan_id", params.scanId)
    if (params.targetId) query.append("target_id", params.targetId)
    if (params.projectId) query.append("project_id", params.projectId)
    if (params.status && params.status !== "all") query.append("status", params.status)

    const queryString = query.toString() ? `?${query.toString()}` : ""
    const raw = await apiClient.get<BackendFindingPaginatedResponse>(`/findings${queryString}`)

    return {
      items: raw.items.map(normaliseFinding),
      total: raw.total,
      page: raw.page,
      totalPages: raw.total_pages,
    }
  },

  /**
   * GET /findings/{id} — Returns detailed finding by ID
   */
  getFinding: async (id: string): Promise<Finding> => {
    const raw = await apiClient.get<BackendFindingRead>(`/findings/${id}`)
    return normaliseFinding(raw)
  },

  /**
   * PATCH /findings/{id} — Updates finding status
   */
  updateStatus: async (id: string, status: FindingStatus): Promise<Finding> => {
    const raw = await apiClient.patch<BackendFindingRead>(`/findings/${id}`, { status })
    return normaliseFinding(raw)
  },

  /**
   * DELETE /findings/{id} — Permanently deletes a finding
   */
  deleteFinding: async (id: string): Promise<void> => {
    await apiClient.delete(`/findings/${id}`)
  },
}
