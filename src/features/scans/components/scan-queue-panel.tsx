import { useState, useEffect } from "react"
import { motion, AnimatePresence } from "framer-motion"
import { ListOrdered, Clock, Trash2, Loader2 } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { toast } from "sonner"
import { scansService } from "@/services/scans.service"
import { formatRelativeTime } from "@/utils"
import type { Scan } from "@/types"

export function ScanQueuePanel() {
  const [queue, setQueue] = useState<Scan[]>([])
  const [isLoading, setIsLoading] = useState(true)

  const loadQueue = async () => {
    setIsLoading(true)
    try {
      const scans = await scansService.getScans()
      const activeScans = scans.filter((s) => s.status === "queued" || s.status === "running")
      setQueue(activeScans)
    } catch {
      toast.error("Failed to load active scan queue")
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    loadQueue()
    const handleCreated = () => loadQueue()
    window.addEventListener("awsap:scan_created", handleCreated)
    return () => window.removeEventListener("awsap:scan_created", handleCreated)
  }, [])

  const handleCancelScan = async (id: string) => {
    try {
      await scansService.cancelScan(id)
      setQueue((prev) => prev.filter((item) => item.id !== id))
      toast.success("Scan cancelled and removed from queue")
      window.dispatchEvent(new CustomEvent("awsap:scan_created"))
    } catch {
      toast.error("Failed to cancel scan")
    }
  }

  return (
    <div className="rounded-xl border border-border bg-card p-5 space-y-4 shadow-sm">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-semibold text-foreground flex items-center gap-2">
            <ListOrdered className="h-4 w-4 text-primary" />
            Scanner Engine Execution Queue
            {isLoading && <Loader2 className="h-3.5 w-3.5 animate-spin text-muted-foreground" />}
          </h3>
          <p className="text-xs text-muted-foreground">
            Active and queued security assessments waiting for execution worker threads ({queue.length} active)
          </p>
        </div>
        <Badge variant="outline" className="bg-primary/10 text-primary border-primary/30 text-xs">
          Engine Scheduler Active
        </Badge>
      </div>

      {queue.length === 0 ? (
        <div className="p-8 text-center border border-dashed border-border rounded-lg">
          <Clock className="mx-auto h-8 w-8 text-muted-foreground/40 mb-2" />
          <p className="text-xs font-medium text-foreground">The scan queue is currently empty.</p>
          <p className="text-[11px] text-muted-foreground mt-1">
            All submitted assessment jobs have finished executing or no tasks are waiting for worker execution.
          </p>
        </div>
      ) : (
        <div className="space-y-2">
          <AnimatePresence>
            {queue.map((item, index) => (
              <motion.div
                key={item.id}
                initial={{ opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, x: -10 }}
                className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 rounded-lg border border-border/80 bg-muted/20 p-3 hover:bg-muted/40 transition-colors"
              >
                <div className="flex items-center gap-3">
                  <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md bg-background border border-border text-xs font-bold text-foreground">
                    #{index + 1}
                  </span>
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-bold text-foreground truncate">{item.targetUrl}</span>
                      <Badge
                        variant="secondary"
                        className={
                          item.status === "running"
                            ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30 text-[10px]"
                            : "bg-amber-500/10 text-amber-400 border-amber-500/30 text-[10px]"
                        }
                      >
                        {item.status.toUpperCase()}
                      </Badge>
                    </div>
                    <div className="flex items-center gap-3 text-[11px] text-muted-foreground mt-0.5">
                      <span className="capitalize">{item.type} Scan</span>
                      <span>•</span>
                      <span>Progress: {item.progress}%</span>
                      <span>•</span>
                      <span className="flex items-center gap-1 font-mono">
                        <Clock className="h-3 w-3" />
                        Created: {formatRelativeTime(new Date(item.createdAt))}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Queue Actions */}
                <div className="flex items-center gap-1.5 shrink-0 self-end sm:self-auto">
                  <Button
                    size="icon"
                    variant="ghost"
                    onClick={() => handleCancelScan(item.id)}
                    className="h-7 w-7 text-destructive hover:text-destructive hover:bg-destructive/10"
                    title="Cancel active scan"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </Button>
                </div>
              </motion.div>
            ))}
          </AnimatePresence>
        </div>
      )}
    </div>
  )
}
