import { motion } from "framer-motion"
import { cn } from "@/utils"
import type { OWASPSeverity } from "../types/owasp"
import { OWASPSeverityBadge } from "./owasp-severity-badge"

interface TimelineEvent {
  id: string
  time: string
  event: string
  category: string
  severity: OWASPSeverity | "info"
  target: string
}

interface OWASPTimelineProps {
  events: TimelineEvent[]
}

const severityDotColor: Record<OWASPSeverity | "info", string> = {
  critical: "bg-red-500 shadow-red-500/50 shadow-md",
  high: "bg-orange-500 shadow-orange-500/40 shadow-sm",
  medium: "bg-amber-500",
  low: "bg-blue-500",
  info: "bg-zinc-500",
}

export function OWASPTimeline({ events }: OWASPTimelineProps) {
  if (events.length === 0) {
    return (
      <div className="py-8 text-center text-xs text-muted-foreground">
        No OWASP scan timeline events recorded yet. Run a vulnerability scan to populate live audit history.
      </div>
    )
  }

  return (
    <div className="space-y-0">
      {events.map((event, index) => (
        <motion.div
          key={event.id}
          initial={{ opacity: 0, x: -8 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.25, delay: index * 0.06 }}
          className="group relative flex gap-3 pb-5"
        >
          {/* Connector line */}
          {index < events.length - 1 && (
            <div className="absolute left-[9px] top-[22px] bottom-0 w-px bg-border/60" />
          )}

          {/* Dot */}
          <div className={cn(
            "relative z-10 mt-[3px] h-5 w-5 shrink-0 rounded-full border-2 border-background",
            severityDotColor[event.severity],
          )} />

          {/* Content */}
          <div className="min-w-0 flex-1 space-y-1">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs font-bold text-foreground">{event.event}</span>
              <OWASPSeverityBadge
                severity={event.severity === "info" ? "info" : event.severity}
                showLabel={false}
              />
            </div>
            <div className="flex flex-wrap items-center gap-3 text-[11px] text-muted-foreground">
              <span className="font-mono bg-muted/30 px-1.5 py-0.5 rounded text-primary font-semibold">
                {event.category}
              </span>
              <span>{event.target}</span>
              <span className="font-mono text-muted-foreground/60">{event.time}</span>
            </div>
          </div>
        </motion.div>
      ))}
    </div>
  )
}
