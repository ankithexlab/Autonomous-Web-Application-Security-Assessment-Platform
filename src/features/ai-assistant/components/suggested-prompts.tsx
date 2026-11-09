import { motion } from "framer-motion"
import { ShieldAlert, Lock, KeyRound, Server } from "lucide-react"
import { SUGGESTED_PROMPTS } from "../data/ai-assistant-data"

const iconMap: Record<string, typeof ShieldAlert> = {
  ShieldAlert,
  Lock,
  KeyRound,
  Server,
}

interface SuggestedPromptsProps {
  onSelectPrompt: (promptText: string) => void
}

export function SuggestedPrompts({ onSelectPrompt }: SuggestedPromptsProps) {
  return (
    <div className="space-y-3 my-6">
      <div className="flex items-center justify-between">
        <span className="text-xs font-bold text-muted-foreground uppercase tracking-wider">
          Suggested Security Insights & Remediation
        </span>
        <span className="text-[10px] text-muted-foreground">Click any prompt to launch</span>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        {SUGGESTED_PROMPTS.map((sp, i) => {
          const Icon = iconMap[sp.iconName] || ShieldAlert
          return (
            <motion.button
              key={sp.id}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.25, delay: i * 0.05 }}
              onClick={() => onSelectPrompt(sp.prompt)}
              className="flex items-start gap-3 rounded-2xl border border-border/80 bg-card p-3.5 text-left transition-all hover:border-primary/40 hover:bg-primary/[0.04] hover:shadow-sm group"
            >
              <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-primary/10 text-primary group-hover:bg-primary group-hover:text-primary-foreground transition-colors">
                <Icon className="h-4 w-4" />
              </div>
              <div className="min-w-0 flex-1">
                <div className="flex items-center justify-between gap-1">
                  <span className="text-xs font-bold text-foreground group-hover:text-primary transition-colors truncate">
                    {sp.title}
                  </span>
                  <span className="rounded bg-muted/60 px-1.5 py-0.5 text-[9px] font-bold text-muted-foreground uppercase font-mono shrink-0">
                    {sp.category}
                  </span>
                </div>
                <p className="mt-1 text-[11px] text-muted-foreground line-clamp-2 leading-relaxed">
                  "{sp.prompt}"
                </p>
              </div>
            </motion.button>
          )
        })}
      </div>
    </div>
  )
}
