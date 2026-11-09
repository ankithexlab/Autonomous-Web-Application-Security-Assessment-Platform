import { Skeleton } from "@/components/ui/skeleton"
import { cn } from "@/utils"

interface SectionLoaderProps {
  rows?: number
  className?: string
}

export function SectionLoader({ rows = 3, className }: SectionLoaderProps) {
  return (
    <div className={cn("space-y-4", className)}>
      {Array.from({ length: rows }).map((_, i) => (
        <Skeleton key={i} className="h-12 w-full rounded-md" />
      ))}
    </div>
  )
}
