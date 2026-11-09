import { apiClient } from "./api-client"
import type { ChatMessage } from "@/types"

export interface AIAnalysisResponse {
  summary: string
  risk_explanation: string
  impact: string
  why_it_matters: string
  remediation_guidance: string[]
  secure_code_example?: string
  confidence: string
  limitations: string[]
}

export interface AIRemediationResponse {
  remediation_summary: string
  root_cause: string
  recommended_fix: string
  implementation_steps: string[]
  secure_configuration_example?: string
  secure_code_example?: string
  affected_component?: string
  verification_steps: string[]
  limitations: string[]
  confidence: string
}

export interface ChatResponse {
  reply: string
  code_blocks: { language: string; code: string }[]
  provider?: string
  model?: string
  is_advisory?: boolean
  context_attached?: string[]
}

export interface AIStatusResponse {
  status: string
  provider: string
  model: string
  timeout_seconds?: number
  has_api_key?: boolean
  rate_limit_per_minute?: number
  max_tokens?: number
  features?: Record<string, boolean>
}

export interface ChatContextParams {
  finding_id?: string
  scan_id?: string
  target_id?: string
  report_id?: string
}

export const aiService = {
  /**
   * POST /ai/findings/{findingId}/analyze — Generates AI analysis for a finding
   */
  analyzeFinding: async (findingId: string): Promise<AIAnalysisResponse> => {
    return await apiClient.post<AIAnalysisResponse>(`/ai/findings/${findingId}/analyze`, {})
  },

  /**
   * POST /ai/findings/{findingId}/remediation — Generates structured remediation plan
   */
  getRemediation: async (findingId: string): Promise<AIRemediationResponse> => {
    return await apiClient.post<AIRemediationResponse>(`/ai/findings/${findingId}/remediation`, {})
  },

  /**
   * POST /ai/chat — Sends chat messages to security assistant AI
   */
  sendChatMessage: async (
    messages: ChatMessage[],
    context?: ChatContextParams,
  ): Promise<ChatResponse> => {
    const formatted = messages.map((m) => ({
      role: m.role,
      content: m.content,
    }))
    const payload: Record<string, any> = { messages: formatted }
    if (context?.finding_id) payload.finding_id = context.finding_id
    if (context?.scan_id) payload.scan_id = context.scan_id
    if (context?.target_id) payload.target_id = context.target_id
    if (context?.report_id) payload.report_id = context.report_id

    return await apiClient.post<ChatResponse>("/ai/chat", payload)
  },

  /**
   * GET /ai/status — Gets active AI provider status
   */
  getStatus: async (): Promise<AIStatusResponse> => {
    return await apiClient.get<AIStatusResponse>("/ai/status")
  },
}
