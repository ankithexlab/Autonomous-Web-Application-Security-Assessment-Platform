import { useState, useRef, useEffect } from "react"
import { useSearchParams } from "react-router"
import { motion, AnimatePresence } from "framer-motion"
import { Send, Bot, User, Sparkles, RefreshCcw, Menu, X, Copy, Check, ShieldAlert } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import { toast } from "sonner"
import { MarkdownRenderer } from "../components/markdown-renderer"
import { TypingIndicator } from "../components/typing-indicator"
import { SuggestedPrompts } from "../components/suggested-prompts"
import { ConversationSidebar } from "../components/conversation-sidebar"
import { aiService } from "@/services/ai.service"
import { cn, formatRelativeTime } from "@/utils"
import { useAuthStore } from "@/stores/auth-store"
import type { Conversation, ChatMessage } from "@/types"

function getStorageKey(userId?: string | null): string {
  return userId ? `awasap_sentinel_conversations_${userId}` : "awasap_sentinel_conversations"
}

function loadStoredConversations(userId?: string | null): Conversation[] {
  try {
    const raw = localStorage.getItem(getStorageKey(userId))
    if (raw) {
      const parsed = JSON.parse(raw)
      if (Array.isArray(parsed)) return parsed
    }
  } catch {
    // ignore
  }
  return []
}

export function AIAssistantPage() {
  const user = useAuthStore((s) => s.user)
  const [conversations, setConversations] = useState<Conversation[]>(() => loadStoredConversations(user?.id))
  const [activeConvId, setActiveConvId] = useState<string | null>(() => {
    const stored = loadStoredConversations(user?.id)
    return stored[0]?.id ?? null
  })
  const [inputQuery, setInputQuery] = useState("")
  const [isGenerating, setIsGenerating] = useState(false)
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState(false)
  const [copiedMsgId, setCopiedMsgId] = useState<string | null>(null)
  const messagesEndRef = useRef<HTMLDivElement>(null)

  const [searchParams, setSearchParams] = useSearchParams()

  const activeConv = conversations.find((c) => c.id === activeConvId) ?? null

  const [engineStatus, setEngineStatus] = useState<{ provider: string; model: string; online: boolean }>({
    provider: "gemini",
    model: "gemini-3.5-flash",
    online: true,
  })

  // Synchronize conversations with per-user localStorage to prevent cross-user leakage
  useEffect(() => {
    if (!user?.id) return
    try {
      localStorage.setItem(getStorageKey(user.id), JSON.stringify(conversations))
    } catch {
      // ignore
    }
  }, [conversations, user?.id])

  // Reload conversations when user ID changes (e.g. account switch)
  useEffect(() => {
    const stored = loadStoredConversations(user?.id)
    setConversations(stored)
    setActiveConvId(stored[0]?.id ?? null)
  }, [user?.id])

  // Handle URL query parameters for contextual chat initiation (e.g. from Finding Detail View)
  useEffect(() => {
    const findingId = searchParams.get("findingId")
    const title = searchParams.get("title")
    const query = searchParams.get("query")

    if (findingId || title || query) {
      const targetId = findingId || `query-${Date.now()}`
      const convId = `conv-${targetId}`
      const convTitle = title ? `Finding: ${title.slice(0, 26)}...` : "Target Security Audit"

      setConversations((prev) => {
        const existing = prev.find((c) => c.id === convId)
        if (existing) {
          setActiveConvId(convId)
          return prev
        }
        const newConv: Conversation = {
          id: convId,
          title: convTitle,
          category: "vulnerability",
          findingId: findingId || undefined,
          messages: [],
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        }
        setActiveConvId(convId)
        return [newConv, ...prev]
      })

      if (query) {
        setInputQuery(query)
      } else if (title) {
        setInputQuery(`Explain the risk, business impact, and provide secure code remediation for: ${title}`)
      }

      setSearchParams({}, { replace: true })
    }
  }, [searchParams, setSearchParams])

  // Auto-scroll to bottom of message thread
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" })
  }, [activeConv?.messages.length, isGenerating])

  // Fetch AI engine status on mount
  useEffect(() => {
    aiService
      .getStatus()
      .then((data) => {
        setEngineStatus({
          provider: data.provider || "gemini",
          model: data.model || "gemini-3.5-flash",
          online: data.status === "online",
        })
      })
      .catch(() => {})
  }, [])

  function handleSelectConversation(conv: Conversation) {
    setActiveConvId(conv.id)
    setMobileSidebarOpen(false)
  }

  function handleNewChat() {
    const newId = `conv-${Date.now()}`
    const newConv: Conversation = {
      id: newId,
      title: "New Security Session",
      category: "general",
      messages: [],
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    }
    setConversations([newConv, ...conversations])
    setActiveConvId(newId)
    setMobileSidebarOpen(false)
  }

  function handleDeleteConversation(id: string) {
    setConversations((prev) => prev.filter((c) => c.id !== id))
    if (activeConvId === id) {
      const remaining = conversations.filter((c) => c.id !== id)
      setActiveConvId(remaining[0]?.id ?? null)
    }
    toast.success("Security chat thread deleted")
  }

  function handleCopyMessage(content: string, id: string) {
    navigator.clipboard.writeText(content)
    setCopiedMsgId(id)
    toast.success("Response copied to clipboard")
    setTimeout(() => setCopiedMsgId(null), 2000)
  }

  function handleSendMessage(textToSend?: string) {
    const promptText = (textToSend || inputQuery).trim()
    if (!promptText || isGenerating) return

    const now = new Date().toISOString()

    const userMessage: ChatMessage = {
      id: `msg-${Date.now()}`,
      role: "user",
      content: promptText,
      timestamp: now,
    }

    let updatedConvId = activeConvId
    let currentConv = activeConv

    if (!currentConv) {
      updatedConvId = `conv-${Date.now()}`
      currentConv = {
        id: updatedConvId,
        title: promptText.slice(0, 30) + (promptText.length > 30 ? "..." : ""),
        category: "general",
        messages: [],
        createdAt: now,
        updatedAt: now,
      }
      setConversations([currentConv, ...conversations])
      setActiveConvId(updatedConvId)
    }

    // Append user message
    const updatedMessages = [...currentConv.messages, userMessage]
    const title = currentConv.messages.length === 0
      ? promptText.slice(0, 32) + (promptText.length > 32 ? "..." : "")
      : currentConv.title

    setConversations((prev) =>
      prev.map((c) =>
        c.id === updatedConvId
          ? { ...c, title, messages: updatedMessages, updatedAt: now }
          : c,
      ),
    )

    setInputQuery("")
    setIsGenerating(true)

    const chatContext = {
      finding_id: currentConv.findingId,
      scan_id: currentConv.scanId,
    }

    aiService
      .sendChatMessage(updatedMessages, chatContext)
      .then((res) => {
        const assistantMessage: ChatMessage = {
          id: `msg-ai-${Date.now()}`,
          role: "assistant",
          content: res.reply,
          timestamp: new Date().toISOString(),
          codeBlocks: res.code_blocks,
        }

        setConversations((prev) =>
          prev.map((c) =>
            c.id === updatedConvId
              ? { ...c, messages: [...c.messages, assistantMessage], updatedAt: new Date().toISOString() }
              : c,
          ),
        )
      })
      .catch((err: any) => {
        const errorDetail =
          err?.response?.data?.detail ||
          err?.response?.data?.message ||
          err?.message ||
          "AI security engine request failed."
        toast.error(`Sentinel AI Error: ${errorDetail}`)

        const assistantMessage: ChatMessage = {
          id: `msg-ai-${Date.now()}`,
          role: "assistant",
          content: `### ⚠️ Sentinel AI Assistant Notice\n\n${errorDetail}\n\n*Troubleshooting tips:*\n- Verify \`GEMINI_API_KEY\` is set in \`backend/.env\`.\n- Confirm the FastAPI backend service is running on \`http://localhost:8000\`.\n- Check whether your Google Gemini API quota has been reached.`,
          timestamp: new Date().toISOString(),
        }

        setConversations((prev) =>
          prev.map((c) =>
            c.id === updatedConvId
              ? { ...c, messages: [...c.messages, assistantMessage], updatedAt: new Date().toISOString() }
              : c,
          ),
        )
      })
      .finally(() => {
        setIsGenerating(false)
      })
  }

  function handleClearChat() {
    if (!activeConvId) return
    setConversations((prev) =>
      prev.map((c) => (c.id === activeConvId ? { ...c, messages: [] } : c)),
    )
    toast.info("Cleared current chat thread")
  }

  return (
    <div className="relative flex h-[calc(100vh-120px)] overflow-hidden rounded-2xl border border-border/80 bg-card shadow-sm">
      {/* Desktop Sidebar History */}
      <div className="hidden sm:block shrink-0 w-64 h-full">
        <ConversationSidebar
          conversations={conversations}
          activeId={activeConvId}
          onSelectConversation={handleSelectConversation}
          onNewChat={handleNewChat}
          onDeleteConversation={handleDeleteConversation}
        />
      </div>

      {/* Mobile Drawer Sidebar */}
      <AnimatePresence>
        {mobileSidebarOpen && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-50 bg-black/60 backdrop-blur-xs sm:hidden"
            onClick={() => setMobileSidebarOpen(false)}
          >
            <motion.div
              initial={{ x: "-100%" }}
              animate={{ x: 0 }}
              exit={{ x: "-100%" }}
              transition={{ duration: 0.25 }}
              className="h-full w-72 bg-card border-r border-border"
              onClick={(e) => e.stopPropagation()}
            >
              <div className="flex items-center justify-between p-3 border-b border-border">
                <span className="text-xs font-bold text-foreground">Chat History</span>
                <Button variant="ghost" size="icon" onClick={() => setMobileSidebarOpen(false)} className="h-7 w-7">
                  <X className="h-4 w-4" />
                </Button>
              </div>
              <ConversationSidebar
                conversations={conversations}
                activeId={activeConvId}
                onSelectConversation={handleSelectConversation}
                onNewChat={handleNewChat}
                onDeleteConversation={handleDeleteConversation}
              />
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Main Chat Window */}
      <div className="flex flex-1 flex-col min-w-0 bg-background/40">
        {/* Chat Banner Header */}
        <div className="flex items-center justify-between border-b border-border/70 bg-card px-4 sm:px-5 py-3 select-none">
          <div className="flex items-center gap-3">
            {/* Mobile Menu Toggle */}
            <Button
              variant="ghost"
              size="icon"
              onClick={() => setMobileSidebarOpen(true)}
              className="sm:hidden h-8 w-8"
            >
              <Menu className="h-4 w-4" />
            </Button>

            <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-primary/10 text-primary border border-primary/20">
              <Bot className="h-4.5 w-4.5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-sm font-extrabold text-foreground">
                  Sentinel AI Security Assistant
                </h2>
                <Badge
                  variant="outline"
                  className={cn(
                    "text-[10px] gap-1 font-bold",
                    engineStatus.provider === "mock"
                      ? "border-sky-500/30 text-sky-400 bg-sky-500/10"
                      : engineStatus.online
                        ? "border-emerald-500/30 text-emerald-400 bg-emerald-500/10"
                        : "border-amber-500/30 text-amber-400 bg-amber-500/10"
                  )}
                >
                  <span
                    className={cn(
                      "h-1.5 w-1.5 rounded-full animate-pulse",
                      engineStatus.provider === "mock"
                        ? "bg-sky-400"
                        : engineStatus.online
                          ? "bg-emerald-400"
                          : "bg-amber-400"
                    )}
                  />
                  {engineStatus.provider === "mock"
                    ? "MOCK ENGINE (Offline/Fallback)"
                    : engineStatus.provider === "gemini"
                      ? "Gemini AI"
                      : engineStatus.provider.toUpperCase()} • {engineStatus.online ? "Online" : "Standby"}
                </Badge>
              </div>
              <p className="text-[11px] text-muted-foreground hidden sm:block">
                Specialized in vulnerability remediation, security architecture, & code audits
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {activeConv && activeConv.messages.length > 0 && (
              <Button
                variant="ghost"
                size="sm"
                onClick={handleClearChat}
                className="gap-1.5 text-xs text-muted-foreground hover:text-foreground"
              >
                <RefreshCcw className="h-3.5 w-3.5" />
                Clear Thread
              </Button>
            )}
          </div>
        </div>

        {/* Advisory Disclaimer Notice */}
        <div className="flex items-center gap-2 px-4 py-1.5 bg-muted/40 border-b border-border/50 text-[11px] text-muted-foreground">
          <ShieldAlert className="h-3.5 w-3.5 text-primary shrink-0" />
          <span className="truncate">
            <strong className="text-foreground">Advisory Assistant:</strong> Sentinel AI outputs are security guidance grounded in your authorized live scan records. Scanner findings originate strictly from automated verification evidence.
          </span>
        </div>

        {/* Message Thread Container */}
        <div className="flex-1 overflow-y-auto p-4 sm:p-6 space-y-4">
          {!activeConv || activeConv.messages.length === 0 ? (
            <div className="max-w-2xl mx-auto py-6">
              <div className="text-center space-y-2 mb-6">
                <div className="inline-flex h-12 w-12 items-center justify-center rounded-2xl bg-primary/10 text-primary border border-primary/20 mb-2">
                  <Sparkles className="h-6 w-6" />
                </div>
                <h3 className="text-lg font-extrabold text-foreground">
                  How can Sentinel AI assist your security posture today?
                </h3>
                <p className="text-xs text-muted-foreground max-w-md mx-auto">
                  Ask remediation questions, review vulnerability evidence, generate Nginx configs, or audit code snippets.
                </p>
              </div>

              <SuggestedPrompts onSelectPrompt={(p) => handleSendMessage(p)} />
            </div>
          ) : (
            activeConv.messages.map((msg) => {
              const isUser = msg.role === "user"
              return (
                <motion.div
                  key={msg.id}
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.25 }}
                  className={cn("flex items-start gap-3 group", isUser && "flex-row-reverse")}
                >
                  {/* Avatar */}
                  <div
                    className={cn(
                      "flex h-8 w-8 shrink-0 items-center justify-center rounded-xl border text-xs font-bold shadow-xs",
                      isUser
                        ? "bg-secondary text-secondary-foreground border-border"
                        : "bg-primary/10 text-primary border-primary/20",
                    )}
                  >
                    {isUser ? <User className="h-4 w-4" /> : <Bot className="h-4 w-4" />}
                  </div>

                  {/* Message Bubble */}
                  <div
                    className={cn(
                      "max-w-[85%] rounded-2xl px-4 py-3 shadow-xs space-y-1 relative",
                      isUser
                        ? "rounded-tr-none bg-primary text-primary-foreground font-medium"
                        : "rounded-tl-none bg-card border border-border/80 text-foreground",
                    )}
                  >
                    {isUser ? (
                      <p className="text-xs leading-relaxed whitespace-pre-wrap">
                        {msg.content}
                      </p>
                    ) : (
                      <MarkdownRenderer content={msg.content} />
                    )}
                    <div
                      className={cn(
                        "flex items-center justify-between text-[10px] pt-1 font-mono opacity-60",
                        isUser ? "text-primary-foreground" : "text-muted-foreground",
                      )}
                    >
                      <span>{formatRelativeTime(new Date(msg.timestamp))}</span>
                      {!isUser && (
                        <button
                          type="button"
                          onClick={() => handleCopyMessage(msg.content, msg.id)}
                          className="opacity-0 group-hover:opacity-100 hover:text-primary transition-opacity flex items-center gap-1 ml-2"
                          title="Copy response"
                        >
                          {copiedMsgId === msg.id ? (
                            <Check className="h-3 w-3 text-emerald-400" />
                          ) : (
                            <Copy className="h-3 w-3" />
                          )}
                          <span>Copy</span>
                        </button>
                      )}
                    </div>
                  </div>
                </motion.div>
              )
            })
          )}

          {/* Animated Typing Indicator */}
          {isGenerating && <TypingIndicator />}
          <div ref={messagesEndRef} />
        </div>

        {/* Message Input Footer */}
        <div className="border-t border-border/70 bg-card p-3 sm:p-4">
          <form
            onSubmit={(e) => {
              e.preventDefault()
              handleSendMessage()
            }}
            className="flex items-center gap-2"
          >
            <Input
              placeholder="Ask Sentinel AI about vulnerabilities, remediation, or code security..."
              value={inputQuery}
              onChange={(e) => setInputQuery(e.target.value)}
              disabled={isGenerating}
              className="flex-1 text-xs bg-background/50 font-mono"
            />
            <Button
              type="submit"
              disabled={!inputQuery.trim() || isGenerating}
              className="gap-1.5 font-bold shrink-0"
            >
              <Send className="h-4 w-4" />
              <span>Send</span>
            </Button>
          </form>
        </div>
      </div>
    </div>
  )
}
