import { motion } from "framer-motion"
import {
  FolderKanban,
  MoreHorizontal,
  Edit2,
  Trash2,
  Target,
  Radar,
  AlertTriangle,
  User,
  Pause,
  Play,
  Archive,
} from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { cn, formatRelativeTime } from "@/utils"
import type { Project, ProjectStatus, ProjectRiskLevel } from "@/types"

const statusConfig: Record<
  ProjectStatus,
  { label: string; className: string; dotClass: string }
> = {
  active: {
    label: "Active",
    className: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
    dotClass: "bg-emerald-400 animate-pulse",
  },
  paused: {
    label: "Paused",
    className: "bg-amber-500/10 text-amber-400 border-amber-500/20",
    dotClass: "bg-amber-400",
  },
  archived: {
    label: "Archived",
    className: "bg-zinc-500/10 text-zinc-400 border-zinc-500/20",
    dotClass: "bg-zinc-400",
  },
}

const riskConfig: Record<ProjectRiskLevel, { label: string; className: string }> = {
  critical: { label: "Critical Risk", className: "bg-red-500/15 text-red-400 border-red-500/30" },
  high: { label: "High Risk", className: "bg-orange-500/15 text-orange-400 border-orange-500/30" },
  medium: { label: "Medium Risk", className: "bg-amber-500/15 text-amber-400 border-amber-500/30" },
  low: { label: "Low Risk", className: "bg-blue-500/15 text-blue-400 border-blue-500/30" },
}

interface ProjectCardProps {
  project: Project
  index: number
  onEdit: (project: Project) => void
  onToggleStatus: (project: Project, newStatus: ProjectStatus) => void
  onDelete: (project: Project) => void
}

export function ProjectCard({
  project,
  index,
  onEdit,
  onToggleStatus,
  onDelete,
}: ProjectCardProps) {
  const st = statusConfig[project.status]
  const rk = riskConfig[project.riskLevel]

  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3, delay: index * 0.05 }}
      className="group flex flex-col justify-between rounded-xl border border-border bg-card p-5 transition-all hover:border-primary/40 hover:shadow-md"
    >
      <div>
        {/* Top bar: icon + title + actions */}
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-center gap-3 min-w-0">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-primary/10 text-primary">
              <FolderKanban className="h-5 w-5" />
            </div>
            <div className="min-w-0">
              <h3 className="truncate font-bold text-base text-foreground group-hover:text-primary transition-colors">
                {project.name}
              </h3>
              <div className="mt-1 flex items-center gap-2 flex-wrap">
                <span
                  className={cn(
                    "inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-semibold",
                    st.className,
                  )}
                >
                  <span className={cn("h-1.5 w-1.5 rounded-full", st.dotClass)} />
                  {st.label}
                </span>

                <span
                  className={cn(
                    "inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide",
                    rk.className,
                  )}
                >
                  {rk.label}
                </span>
              </div>
            </div>
          </div>

          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="icon-xs" className="shrink-0">
                <MoreHorizontal className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-44">
              <DropdownMenuItem onClick={() => onEdit(project)}>
                <Edit2 className="mr-2 h-3.5 w-3.5" />
                Edit Project
              </DropdownMenuItem>

              <DropdownMenuSeparator />

              {project.status !== "active" && (
                <DropdownMenuItem onClick={() => onToggleStatus(project, "active")}>
                  <Play className="mr-2 h-3.5 w-3.5 text-emerald-400" />
                  Set Active
                </DropdownMenuItem>
              )}
              {project.status !== "paused" && (
                <DropdownMenuItem onClick={() => onToggleStatus(project, "paused")}>
                  <Pause className="mr-2 h-3.5 w-3.5 text-amber-400" />
                  Pause Project
                </DropdownMenuItem>
              )}
              {project.status !== "archived" && (
                <DropdownMenuItem onClick={() => onToggleStatus(project, "archived")}>
                  <Archive className="mr-2 h-3.5 w-3.5 text-zinc-400" />
                  Archive Project
                </DropdownMenuItem>
              )}

              <DropdownMenuSeparator />

              <DropdownMenuItem
                onClick={() => onDelete(project)}
                className="text-red-400 focus:text-red-400"
              >
                <Trash2 className="mr-2 h-3.5 w-3.5" />
                Delete Project
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>

        {/* Description */}
        {project.description && (
          <p className="mt-3 text-xs text-muted-foreground line-clamp-2 leading-relaxed">
            {project.description}
          </p>
        )}

        {/* Metrics Grid */}
        <div className="mt-4 grid grid-cols-3 gap-2 rounded-lg bg-muted/20 p-2.5 text-center text-xs">
          <div>
            <span className="flex items-center justify-center gap-1 text-[10px] text-muted-foreground">
              <Target className="h-3 w-3 text-primary" /> Targets
            </span>
            <p className="mt-0.5 font-bold text-foreground">{project.targetCount}</p>
          </div>
          <div>
            <span className="flex items-center justify-center gap-1 text-[10px] text-muted-foreground">
              <Radar className="h-3 w-3 text-blue-400" /> Scans
            </span>
            <p className="mt-0.5 font-bold text-foreground">{project.scanCount}</p>
          </div>
          <div>
            <span className="flex items-center justify-center gap-1 text-[10px] text-muted-foreground">
              <AlertTriangle className="h-3 w-3 text-red-400" /> Critical
            </span>
            <p className="mt-0.5 font-bold text-red-400">{project.criticalCount}</p>
          </div>
        </div>

        {/* Tags */}
        {project.tags.length > 0 && (
          <div className="mt-3 flex flex-wrap gap-1">
            {project.tags.map((tag) => (
              <Badge key={tag} variant="secondary" className="text-[10px] px-1.5 py-0 font-mono">
                #{tag}
              </Badge>
            ))}
          </div>
        )}
      </div>

      {/* Footer info */}
      <div className="mt-4 pt-3 border-t border-border/40 flex items-center justify-between text-[11px] text-muted-foreground">
        <span className="flex items-center gap-1">
          <User className="h-3 w-3" />
          {project.owner}
        </span>
        <span>Updated {formatRelativeTime(new Date(project.updatedAt))}</span>
      </div>
    </motion.div>
  )
}
