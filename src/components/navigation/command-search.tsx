import { useEffect, useState } from "react"
import { useNavigate } from "react-router"
import { Search, FolderKanban, Crosshair, Radar, ShieldAlert, ShieldCheck, FileText, Settings, Bot, Database } from "lucide-react"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { ROUTES } from "@/constants"

interface SearchItem {
  id: string
  title: string
  category: string
  href: string
  icon: typeof Search
}

const searchItems: SearchItem[] = [
  { id: "1", title: "Dashboard Overview", category: "Navigation", href: ROUTES.DASHBOARD, icon: FolderKanban },
  { id: "2", title: "All Security Projects", category: "Navigation", href: ROUTES.PROJECTS, icon: FolderKanban },
  { id: "3", title: "Scan Targets & Scope", category: "Navigation", href: ROUTES.TARGETS, icon: Crosshair },
  { id: "4", title: "Active Security Scans", category: "Navigation", href: ROUTES.SCANS, icon: Radar },
  { id: "5", title: "Vulnerability Findings", category: "Navigation", href: ROUTES.FINDINGS, icon: ShieldAlert },
  { id: "6", title: "OWASP Top 10 Security Posture", category: "Navigation", href: ROUTES.OWASP.DASHBOARD, icon: ShieldCheck },
  { id: "7", title: "Reports & Compliance", category: "Navigation", href: ROUTES.REPORTS, icon: FileText },
  { id: "8", title: "Security Payloads Library", category: "Navigation", href: ROUTES.PAYLOADS, icon: Database },
  { id: "9", title: "AI Security Assistant", category: "Navigation", href: ROUTES.AI_ASSISTANT, icon: Bot },
  { id: "10", title: "Platform Settings", category: "Navigation", href: ROUTES.SETTINGS, icon: Settings },
]

export function CommandSearch() {
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState("")
  const navigate = useNavigate()

  useEffect(() => {
    const down = (e: KeyboardEvent) => {
      if ((e.key === "k" && (e.metaKey || e.ctrlKey)) || e.key === "/") {
        if (
          (e.target instanceof HTMLElement && e.target.isContentEditable) ||
          e.target instanceof HTMLInputElement ||
          e.target instanceof HTMLTextAreaElement
        ) {
          return
        }
        e.preventDefault()
        setOpen((open) => !open)
      }
    }

    document.addEventListener("keydown", down)
    return () => document.removeEventListener("keydown", down)
  }, [])

  const filtered = searchItems.filter((item) =>
    item.title.toLowerCase().includes(query.toLowerCase()) ||
    item.category.toLowerCase().includes(query.toLowerCase())
  )

  const handleSelect = (href: string) => {
    setOpen(false)
    navigate(href)
  }

  return (
    <>
      <Button
        variant="outline"
        onClick={() => setOpen(true)}
        className="relative h-9 w-9 p-0 sm:w-64 sm:justify-start sm:px-3 text-muted-foreground hover:text-foreground"
      >
        <Search className="h-4 w-4 sm:mr-2 shrink-0" />
        <span className="hidden sm:inline-block text-xs">Search platform...</span>
        <kbd className="pointer-events-none absolute right-2 top-2 hidden h-5 select-none items-center gap-1 rounded border border-border bg-muted px-1.5 font-mono text-[10px] font-medium opacity-100 sm:flex">
          <span className="text-xs">⌘</span>K
        </kbd>
      </Button>

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="sm:max-w-lg p-0 gap-0 overflow-hidden">
          <DialogHeader className="sr-only">
            <DialogTitle>Search Platform</DialogTitle>
          </DialogHeader>
          <div className="flex items-center border-b border-border px-3">
            <Search className="h-4 w-4 shrink-0 text-muted-foreground mr-2" />
            <Input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search projects, targets, findings, commands..."
              className="border-0 focus-visible:ring-0 focus-visible:ring-offset-0 h-12 text-sm bg-transparent"
              autoFocus
            />
          </div>

          <div className="max-h-72 overflow-y-auto p-2">
            {filtered.length === 0 ? (
              <p className="p-4 text-center text-xs text-muted-foreground">No results found.</p>
            ) : (
              filtered.map((item) => {
                const Icon = item.icon
                return (
                  <button
                    key={item.id}
                    onClick={() => handleSelect(item.href)}
                    className="flex w-full items-center gap-3 rounded-md px-3 py-2.5 text-xs text-foreground hover:bg-accent hover:text-accent-foreground text-left transition-colors"
                  >
                    <Icon className="h-4 w-4 text-muted-foreground shrink-0" />
                    <span className="font-medium flex-1">{item.title}</span>
                    <span className="text-[10px] uppercase tracking-wider text-muted-foreground font-semibold">
                      {item.category}
                    </span>
                  </button>
                )
              })
            )}
          </div>
        </DialogContent>
      </Dialog>
    </>
  )
}
