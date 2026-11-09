import { cn } from "@/utils"

type Status = "online" | "offline" | "warning" | "critical" | "scanning"

interface StatusIndicatorProps {
  status: Status
  className?: string
  showPulse?: boolean
}

const statusStyles: Record<Status, string> = {
  online: "bg-emerald-500",
  offline: "bg-zinc-500",
  warning: "bg-amber-500",
  critical: "bg-red-500",
  scanning: "bg-blue-500",
}

export function StatusIndicator({
  status,
  className,
  showPulse = false,
}: StatusIndicatorProps) {
  return (
    <span className={cn("relative flex h-2.5 w-2.5", className)}>
      {showPulse && (
        <span
          className={cn(
            "absolute inline-flex h-full w-full animate-ping rounded-full opacity-75",
            statusStyles[status],
          )}
        />
      )}
      <span
        className={cn(
          "relative inline-flex h-2.5 w-2.5 rounded-full",
          statusStyles[status],
        )}
      />
    </span>
  )
}
