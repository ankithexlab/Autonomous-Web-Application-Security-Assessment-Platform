import { Search, SlidersHorizontal, X } from "lucide-react"
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
import { cn } from "@/utils"
import type { Severity, FindingStatus } from "@/types"

interface FindingFiltersProps {
  search: string
  onSearchChange: (search: string) => void
  severityFilter: Severity | "all"
  onSeverityFilterChange: (severity: Severity | "all") => void
  statusFilter: FindingStatus | "all"
  onStatusFilterChange: (status: FindingStatus | "all") => void
  owaspFilter?: string
  onOwaspFilterChange?: (owasp: string) => void
}

const severityOptions: { value: Severity | "all"; label: string; color?: string }[] = [
  { value: "all", label: "All Severities" },
  { value: "critical", label: "Critical", color: "text-red-400" },
  { value: "high", label: "High", color: "text-orange-400" },
  { value: "medium", label: "Medium", color: "text-amber-400" },
  { value: "low", label: "Low", color: "text-blue-400" },
  { value: "info", label: "Info", color: "text-zinc-400" },
]

const statusOptions: { value: FindingStatus | "all"; label: string }[] = [
  { value: "all", label: "All Statuses" },
  { value: "open", label: "Open" },
  { value: "confirmed", label: "Confirmed" },
  { value: "in_progress", label: "In Progress" },
  { value: "resolved", label: "Resolved" },
  { value: "reopened", label: "Reopened" },
  { value: "false_positive", label: "False Positive" },
  { value: "accepted_risk", label: "Accepted Risk" },
]

const owaspCategories = [
  "all",
  "A01: Broken Access Control",
  "A03: Injection",
  "A05: Security Misconfiguration",
  "A06: Outdated Components",
  "A07: Authentication Failures",
  "A10: SSRF",
]

export function FindingFilters({
  search,
  onSearchChange,
  severityFilter,
  onSeverityFilterChange,
  statusFilter,
  onStatusFilterChange,
  owaspFilter = "all",
  onOwaspFilterChange,
}: FindingFiltersProps) {
  const activeCount = [
    severityFilter !== "all",
    statusFilter !== "all",
    owaspFilter !== "all",
  ].filter(Boolean).length

  function handleReset() {
    onSearchChange("")
    onSeverityFilterChange("all")
    onStatusFilterChange("all")
    if (onOwaspFilterChange) onOwaspFilterChange("all")
  }

  return (
    <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-border/80 bg-card p-3 shadow-xs">
      {/* Left: Search input */}
      <div className="relative min-w-[240px] max-w-sm flex-1">
        <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          placeholder="Search vulnerabilities, URLs, CWE, OWASP..."
          value={search}
          onChange={(e) => onSearchChange(e.target.value)}
          className="pl-9 pr-8 text-xs font-mono"
        />
        {search && (
          <button
            type="button"
            onClick={() => onSearchChange("")}
            className="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        )}
      </div>

      {/* Right: Quick Pills & Dropdown Filters */}
      <div className="flex items-center gap-2">
        {/* Severity Quick Pills */}
        <div className="hidden sm:flex items-center gap-1 rounded-lg border border-border/60 bg-muted/30 p-1">
          {severityOptions.map((opt) => (
            <button
              key={opt.value}
              type="button"
              onClick={() => onSeverityFilterChange(opt.value)}
              className={cn(
                "rounded-md px-2 py-1 text-[11px] font-bold transition-all",
                severityFilter === opt.value
                  ? "bg-card text-foreground shadow-xs"
                  : "text-muted-foreground hover:text-foreground",
                opt.color && severityFilter === opt.value && opt.color,
              )}
            >
              {opt.label}
            </button>
          ))}
        </div>

        {/* Dropdown Filters */}
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="outline" size="sm" className="gap-2 text-xs">
              <SlidersHorizontal className="h-3.5 w-3.5" />
              Filters
              {activeCount > 0 && (
                <Badge variant="default" className="h-5 min-w-5 rounded-full px-1.5 text-[10px] font-bold">
                  {activeCount}
                </Badge>
              )}
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-56">
            <DropdownMenuLabel className="text-xs">Filter by Status</DropdownMenuLabel>
            {statusOptions.map((st) => (
              <DropdownMenuCheckboxItem
                key={st.value}
                checked={statusFilter === st.value}
                onCheckedChange={() => onStatusFilterChange(st.value)}
                className="text-xs"
              >
                {st.label}
              </DropdownMenuCheckboxItem>
            ))}

            <DropdownMenuSeparator />
            <DropdownMenuLabel className="text-xs">Filter by OWASP Category</DropdownMenuLabel>
            {owaspCategories.map((cat) => (
              <DropdownMenuCheckboxItem
                key={cat}
                checked={owaspFilter === cat}
                onCheckedChange={() => onOwaspFilterChange && onOwaspFilterChange(cat)}
                className="text-xs"
              >
                {cat === "all" ? "All OWASP Categories" : cat}
              </DropdownMenuCheckboxItem>
            ))}
          </DropdownMenuContent>
        </DropdownMenu>

        {/* Reset button */}
        {(activeCount > 0 || search) && (
          <Button
            variant="ghost"
            size="sm"
            onClick={handleReset}
            className="text-xs text-muted-foreground hover:text-foreground"
          >
            Reset
          </Button>
        )}
      </div>
    </div>
  )
}
