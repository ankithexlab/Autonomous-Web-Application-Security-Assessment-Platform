import { Search, SlidersHorizontal } from "lucide-react"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuCheckboxItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import type { ProjectStatus, ProjectRiskLevel } from "@/types"

interface ProjectFiltersProps {
  search: string
  onSearchChange: (val: string) => void
  statusFilter: ProjectStatus | "all"
  onStatusFilterChange: (val: ProjectStatus | "all") => void
  riskFilter: ProjectRiskLevel | "all"
  onRiskFilterChange: (val: ProjectRiskLevel | "all") => void
}

export function ProjectFilters({
  search,
  onSearchChange,
  statusFilter,
  onStatusFilterChange,
  riskFilter,
  onRiskFilterChange,
}: ProjectFiltersProps) {
  const activeCount = [statusFilter, riskFilter].filter((f) => f !== "all").length

  return (
    <div className="flex items-center gap-3">
      <div className="relative flex-1 max-w-sm">
        <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          placeholder="Search projects, tags, owners..."
          value={search}
          onChange={(e) => onSearchChange(e.target.value)}
          className="pl-9"
        />
      </div>

      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="outline" size="sm" className="gap-2">
            <SlidersHorizontal className="h-3.5 w-3.5" />
            Filters
            {activeCount > 0 && (
              <Badge variant="default" className="h-5 min-w-5 rounded-full px-1.5 text-[10px] font-bold">
                {activeCount}
              </Badge>
            )}
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-48">
          <DropdownMenuLabel className="text-xs">Project Status</DropdownMenuLabel>
          {(["all", "active", "paused", "archived"] as const).map((s) => (
            <DropdownMenuCheckboxItem
              key={s}
              checked={statusFilter === s}
              onCheckedChange={() => onStatusFilterChange(s)}
            >
              {s === "all" ? "All Statuses" : s.charAt(0).toUpperCase() + s.slice(1)}
            </DropdownMenuCheckboxItem>
          ))}

          <DropdownMenuSeparator />

          <DropdownMenuLabel className="text-xs">Risk Level</DropdownMenuLabel>
          {(["all", "critical", "high", "medium", "low"] as const).map((r) => (
            <DropdownMenuCheckboxItem
              key={r}
              checked={riskFilter === r}
              onCheckedChange={() => onRiskFilterChange(r)}
            >
              {r === "all" ? "All Risk Levels" : r.charAt(0).toUpperCase() + r.slice(1)}
            </DropdownMenuCheckboxItem>
          ))}
        </DropdownMenuContent>
      </DropdownMenu>
    </div>
  )
}
