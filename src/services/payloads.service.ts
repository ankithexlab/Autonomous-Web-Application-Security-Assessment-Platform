import { apiClient } from "./api-client"
import type {
  SecurityPayload,
  SecurityPayloadStats,
  SecurityPayloadPaginatedResponse,
  PayloadFilterParams,
} from "@/types"

export const payloadsService = {
  async getPayloads(params: PayloadFilterParams = {}): Promise<SecurityPayloadPaginatedResponse> {
    const sp = new URLSearchParams()
    if (params.page) sp.set("page", String(params.page))
    if (params.pageSize) sp.set("page_size", String(params.pageSize))
    if (params.type && params.type !== "all") sp.set("type", params.type)
    if (params.severity && params.severity !== "all") sp.set("severity", params.severity)
    if (params.q && params.q.trim()) sp.set("q", params.q.trim())

    const query = sp.toString() ? `?${sp.toString()}` : ""
    return apiClient.get<SecurityPayloadPaginatedResponse>(`/payloads${query}`)
  },

  async getStats(): Promise<SecurityPayloadStats> {
    return apiClient.get<SecurityPayloadStats>("/payloads/stats")
  },

  async getPayloadById(id: string): Promise<SecurityPayload> {
    return apiClient.get<SecurityPayload>(`/payloads/${encodeURIComponent(id)}`)
  },
}
