import { apiClient, getAccessToken, API_BASE_URL } from "./api-client"

export interface BackendReportRead {
  id: string
  project_id: string
  user_id: string
  target_id?: string
  scan_id?: string
  title: string
  report_type: string
  file_format: string
  status: string
  overall_score: number
  findings_summary_json?: string
  file_path?: string
  completed_at?: string
  created_at: string
  updated_at: string
}

export interface BackendReportListResponse {
  items: BackendReportRead[]
  total: number
}

export interface ReportCreatePayload {
  title: string
  report_type: string
  file_format: string
  scan_id?: string
  target_id?: string
}

export const reportsService = {
  /**
   * POST /projects/{projectId}/reports — Creates and generates a new report job
   */
  createReport: async (projectId: string, payload: ReportCreatePayload): Promise<BackendReportRead> => {
    return await apiClient.post<BackendReportRead>(`/projects/${projectId}/reports`, payload)
  },

  /**
   * GET /reports — Lists all generated reports for the current user
   */
  getReports: async (): Promise<BackendReportRead[]> => {
    const raw = await apiClient.get<BackendReportListResponse>("/reports")
    return raw.items
  },

  /**
   * GET /reports/{id} — Returns detailed report status by ID
   */
  getReport: async (id: string): Promise<BackendReportRead> => {
    return await apiClient.get<BackendReportRead>(`/reports/${id}`)
  },

  /**
   * DELETE /reports/{id} — Permanently deletes a report
   */
  deleteReport: async (id: string): Promise<void> => {
    await apiClient.delete(`/reports/${id}`)
  },

  /**
   * GET /reports/{id}/download — Downloads report payload in requested or stored format
   */
  downloadReport: async (id: string, filename: string, format?: string): Promise<void> => {
    const token = getAccessToken()
    const query = format ? `?format=${encodeURIComponent(format)}` : ""
    const response = await fetch(`${API_BASE_URL}/reports/${id}/download${query}`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    })

    if (!response.ok) {
      throw new Error("Failed to download report document")
    }

    const blob = await response.blob()
    const url = URL.createObjectURL(blob)
    const link = document.createElement("a")
    link.href = url
    link.setAttribute("download", filename)
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
    URL.revokeObjectURL(url)
  },

  /**
   * GET /reports/{id}/preview — Fetches clean live HTML report for iframe preview
   */
  getReportContent: async (id: string): Promise<{ text: string; contentType: string }> => {
    const token = getAccessToken()
    const response = await fetch(`${API_BASE_URL}/reports/${id}/preview`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    })

    if (!response.ok) {
      throw new Error("Failed to retrieve report content from server")
    }

    const contentType = response.headers.get("content-type") || "text/html"
    const text = await response.text()
    return { text, contentType }
  },
}
