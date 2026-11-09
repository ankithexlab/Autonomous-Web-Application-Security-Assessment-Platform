export interface SecurityPayload {
  id: string
  description: string
  payload: string
  context: string
  type: string
  severity: "critical" | "high" | "medium" | "low" | "info"
  example_usage: string | null
  created_at: string
  updated_at: string
}

export interface SecurityPayloadStats {
  total: number
  by_severity: Record<string, number>
  by_type: Record<string, number>
}

export interface SecurityPayloadPaginatedResponse {
  items: SecurityPayload[]
  total: number
  page: number
  page_size: number
  total_pages: number
}

export interface PayloadFilterParams {
  page?: number
  pageSize?: number
  type?: string
  severity?: string
  q?: string
}
