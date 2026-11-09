import { Search, Filter, SlidersHorizontal, LayoutGrid, Table } from "lucide-react"
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
import type { TargetType, TargetStatus, ValidationStatus } from "@/types"

interface TargetFiltersProps {
  search: string
  onSearchChange: (value: string) => void
  typeFilter: TargetType | "all"
  onTypeFilterChange: (value: TargetType | "all") => void
  statusFilter: TargetStatus | "all"
  onStatusFilterChange: (value: TargetStatus | "all") => void
  validationFilter: ValidationStatus | "all"
  onValidationFilterChange: (value: ValidationStatus | "all") => void
  viewMode?: "cards" | "table"
  onViewModeChange?: (mode: "cards" | "table") => void
}

export function TargetFilters({
  search,
  onSearchChange,
  typeFilter,
  onTypeFilterChange,
  statusFilter,
  onStatusFilterChange,
  validationFilter,
  onValidationFilterChange,
  viewMode = "cards",
  onViewModeChange,
}: TargetFiltersProps) {
  const activeFilterCount = [typeFilter, statusFilter, validationFilter].filter(
    (f) => f !== "all",
  ).length

  return (
    <div className="flex items-center justify-between gap-3">
      {/* Search */}
      <div className="relative flex-1 max-w-sm">
        <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          placeholder="Search targets, URLs, tech, tags..."
          value={search}
          onChange={(e) => onSearchChange(e.target.value)}
          className="pl-9"
        />
      </div>

      <div className="flex items-center gap-2">
        {/* View Mode Toggle */}
        {onViewModeChange && (
          <div className="flex items-center rounded-lg border border-border bg-muted/20 p-1">
            <button
              onClick={() => onViewModeChange("cards")}
              className={`rounded-md p-1.5 transition-colors ${
                viewMode === "cards"
                  ? "bg-card text-foreground shadow-xs"
                  : "text-muted-foreground hover:text-foreground"
              }`}
              title="Card Grid View"
            >
              <LayoutGrid className="h-3.5 w-3.5" />
            </button>
            <button
              onClick={() => onViewModeChange("table")}
              className={`rounded-md p-1.5 transition-colors ${
                viewMode === "table"
                  ? "bg-card text-foreground shadow-xs"
                  : "text-muted-foreground hover:text-foreground"
              }`}
              title="Data Table View"
            >
              <Table className="h-3.5 w-3.5" />
            </button>
          </div>
        )}

        {/* Filter dropdown */}
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="outline" size="sm" className="gap-2">
              <SlidersHorizontal className="h-3.5 w-3.5" />
              Filters
              {activeFilterCount > 0 && (
                <Badge
                  variant="default"
                  className="h-5 min-w-5 rounded-full px-1.5 text-[10px] font-bold"
                >
                  {activeFilterCount}
                </Badge>
              )}
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-52">
            {/* Type filter */}
            <DropdownMenuLabel className="flex items-center gap-1.5 text-xs">
              <Filter className="h-3 w-3" />
              Target Type
            </DropdownMenuLabel>
            <DropdownMenuCheckboxItem
              checked={typeFilter === "all"}
              onCheckedChange={() => onTypeFilterChange("all")}
            >
              All Types
            </DropdownMenuCheckboxItem>
            <DropdownMenuCheckboxItem
              checked={typeFilter === "web"}
              onCheckedChange={() => onTypeFilterChange("web")}
            >
              Web App
            </DropdownMenuCheckboxItem>
            <DropdownMenuCheckboxItem
              checked={typeFilter === "api"}
              onCheckedChange={() => onTypeFilterChange("api")}
            >
              API
            </DropdownMenuCheckboxItem>
            <DropdownMenuCheckboxItem
              checked={typeFilter === "network"}
              onCheckedChange={() => onTypeFilterChange("network")}
            >
              Network
            </DropdownMenuCheckboxItem>

            <DropdownMenuSeparator />

            {/* Status filter */}
            <DropdownMenuLabel className="flex items-center gap-1.5 text-xs">
              Target Status
            </DropdownMenuLabel>
            <DropdownMenuCheckboxItem
              checked={statusFilter === "all"}
              onCheckedChange={() => onStatusFilterChange("all")}
            >
              All Statuses
            </DropdownMenuCheckboxItem>
            <DropdownMenuCheckboxItem
              checked={statusFilter === "active"}
              onCheckedChange={() => onStatusFilterChange("active")}
            >
              Active
            </DropdownMenuCheckboxItem>
            <DropdownMenuCheckboxItem
              checked={statusFilter === "scanning"}
              onCheckedChange={() => onStatusFilterChange("scanning")}
            >
              Scanning
            </DropdownMenuCheckboxItem>
            <DropdownMenuCheckboxItem
              checked={statusFilter === "inactive"}
              onCheckedChange={() => onStatusFilterChange("inactive")}
            >
              Inactive
            </DropdownMenuCheckboxItem>

            <DropdownMenuSeparator />

            {/* Validation filter */}
            <DropdownMenuLabel className="flex items-center gap-1.5 text-xs">
              Validation Status
            </DropdownMenuLabel>
            <DropdownMenuCheckboxItem
              checked={validationFilter === "all"}
              onCheckedChange={() => onValidationFilterChange("all")}
            >
              All Validation
            </DropdownMenuCheckboxItem>
            <DropdownMenuCheckboxItem
              checked={validationFilter === "verified"}
              onCheckedChange={() => onValidationFilterChange("verified")}
            >
              Verified
            </DropdownMenuCheckboxItem>
            <DropdownMenuCheckboxItem
              checked={validationFilter === "pending"}
              onCheckedChange={() => onValidationFilterChange("pending")}
            >
              Pending
            </DropdownMenuCheckboxItem>
            <DropdownMenuCheckboxItem
              checked={validationFilter === "failed"}
              onCheckedChange={() => onValidationFilterChange("failed")}
            >
              Failed
            </DropdownMenuCheckboxItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </div>
  )
}
