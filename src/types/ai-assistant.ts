export type MessageRole = "user" | "assistant" | "system"

export interface ChatMessage {
  id: string
  role: MessageRole
  content: string
  timestamp: string
  codeBlocks?: { language: string; code: string }[]
}

export interface Conversation {
  id: string
  title: string
  category: "remediation" | "code_audit" | "compliance" | "general" | "vulnerability"
  messages: ChatMessage[]
  findingId?: string
  scanId?: string
  createdAt: string
  updatedAt: string
}

export interface SuggestedPrompt {
  id: string
  title: string
  prompt: string
  category: string
  iconName: string
}
