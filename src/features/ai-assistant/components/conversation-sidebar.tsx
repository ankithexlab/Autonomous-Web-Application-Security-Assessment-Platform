
import { useState } from "react"
import { motion } from "framer-motion"
import { Plus, MessageSquare, Search, Trash2 } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { cn, formatRelativeTime } from "@/utils"
import type { Conversation } from "@/types"

interface ConversationSidebarProps {
  conversations: Conversation[]
  activeId: string | null
  onSelectConversation: (conv: Conversation) => void
  onNewChat: () => void
  onDeleteConversation?: (id: string) => void
}

export function ConversationSidebar({
  conversations,
  activeId,
  onSelectConversation,
  onNewChat,
  onDeleteConversation,
}: ConversationSidebarProps) {
  const [search, setSearch] = useState("")

  const filtered = conversations.filter((c) =>
    c.title.toLowerCase().includes(search.toLowerCase()),
  )

  return (
    <div className="flex h-full w-full flex-col border-r border-border/80 bg-card/60 p-3">
      {/* New Chat Button */}
      <Button onClick={onNewChat} className="w-full justify-start gap-2 mb-3 font-bold">
        <Plus className="h-4 w-4" />
        New Security Chat
      </Button>

      {/* Search Input */}
      <div className="relative mb-3">
        <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
        <Input
          placeholder="Search conversation threads..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="h-8 pl-8 text-xs bg-background/50 font-mono"
        />
      </div>

      {/* Conversation List */}
      <div className="flex-1 overflow-y-auto space-y-1 pr-1">
        <p className="px-2 text-[10px] font-bold uppercase tracking-wider text-muted-foreground mb-1.5">
          Recent Security Sessions
        </p>

        {filtered.length === 0 ? (
          <p className="px-2 py-6 text-xs text-muted-foreground text-center">
            No chats found matching query
          </p>
        ) : (
          filtered.map((conv) => {
            const isActive = conv.id === activeId
            return (
              <motion.div
                key={conv.id}
                whileHover={{ x: 2 }}
                className={cn(
                  "group relative flex items-center justify-between rounded-xl px-3 py-2 text-left transition-colors cursor-pointer",
                  isActive
                    ? "bg-primary/10 text-primary font-bold border border-primary/25 shadow-xs"
                    : "text-muted-foreground hover:bg-muted/30 hover:text-foreground",
                )}
                onClick={() => onSelectConversation(conv)}
              >
                <div className="flex flex-col gap-0.5 min-w-0 flex-1">
                  <div className="flex items-center gap-2 min-w-0">
                    <MessageSquare className="h-3.5 w-3.5 shrink-0 text-primary/70" />
                    <span className="truncate text-xs">{conv.title}</span>
                  </div>
                  <span className="text-[10px] opacity-60 pl-5 font-mono">
                    {formatRelativeTime(new Date(conv.updatedAt))}
                  </span>
                </div>

                {onDeleteConversation && (
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation()
                      onDeleteConversation(conv.id)
                    }}
                    className="opacity-0 group-hover:opacity-100 p-1 text-muted-foreground hover:text-red-400 transition-opacity"
                    title="Delete Chat"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                )}
              </motion.div>
            )
          })
        )}
      </div>
    </div>
  )
}
