import { useNavigate } from "react-router"
import { Button } from "@/components/ui/button"
import { ROUTES } from "@/constants"
import { Radar, Plus, FileText, Sparkles } from "lucide-react"

export function QuickActionsBar() {
  const navigate = useNavigate()

  return (
    <div className="flex flex-wrap items-center gap-2.5">
      <Button
        size="sm"
        onClick={() => navigate(ROUTES.SCANS)}
        className="gap-2 text-xs font-semibold shadow-xs"
      >
        <Radar className="h-3.5 w-3.5" />
        New Scan
      </Button>

      <Button
        size="sm"
        variant="outline"
        onClick={() => navigate(ROUTES.TARGETS)}
        className="gap-2 text-xs font-semibold"
      >
        <Plus className="h-3.5 w-3.5" />
        Add Target
      </Button>

      <Button
        size="sm"
        variant="outline"
        onClick={() => navigate(ROUTES.REPORTS)}
        className="gap-2 text-xs font-semibold"
      >
        <FileText className="h-3.5 w-3.5 text-muted-foreground" />
        Generate Report
      </Button>

      <Button
        size="sm"
        variant="secondary"
        onClick={() => navigate(ROUTES.AI_ASSISTANT)}
        className="gap-2 text-xs font-semibold border border-violet-500/30 text-violet-300 bg-violet-500/10 hover:bg-violet-500/20"
      >
        <Sparkles className="h-3.5 w-3.5 text-violet-400" />
        Ask Sentinel AI
      </Button>
    </div>
  )
}
