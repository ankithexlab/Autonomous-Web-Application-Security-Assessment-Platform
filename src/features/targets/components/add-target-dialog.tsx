import { useEffect, useState } from "react"
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Badge } from "@/components/ui/badge"
import {
  Globe,
  Server,
  Network,
  Plus,
  X,
  Loader2,
  FolderKanban,
} from "lucide-react"
import { toast } from "sonner"
import { projectsService } from "@/services/projects.service"
import { cn } from "@/utils"
import type { Project, Target, TargetType } from "@/types"

const targetTypes: {
  value: TargetType
  label: string
  description: string
  icon: typeof Globe
}[] = [
  {
    value: "web",
    label: "Web App",
    description: "Website or web application",
    icon: Globe,
  },
  {
    value: "api",
    label: "API",
    description: "REST, GraphQL, or gRPC endpoint",
    icon: Server,
  },
  {
    value: "network",
    label: "Network",
    description: "IP range or network segment",
    icon: Network,
  },
]

interface AddTargetDialogProps {
  open: boolean
  onClose: () => void
  onAddTarget?: (targetData: Partial<Target> & { projectId: string }) => void
}

export function AddTargetDialog({ open, onClose, onAddTarget }: AddTargetDialogProps) {
  const [projects, setProjects] = useState<Project[]>([])
  const [selectedProjectId, setSelectedProjectId] = useState<string>("")
  const [isLoadingProjects, setIsLoadingProjects] = useState(false)
  const [selectedType, setSelectedType] = useState<TargetType>("web")
  const [url, setUrl] = useState("")
  const [description, setDescription] = useState("")
  const [tagInput, setTagInput] = useState("")
  const [tags, setTags] = useState<string[]>([])
  const [scopeInput, setScopeInput] = useState("")
  const [scopeRules, setScopeRules] = useState<string[]>([])
  const [isSubmitting, setIsSubmitting] = useState(false)

  useEffect(() => {
    if (open) {
      setIsLoadingProjects(true)
      projectsService
        .getProjects()
        .then((items) => {
          setProjects(items)
          if (items.length > 0 && items[0] && !selectedProjectId) {
            setSelectedProjectId(items[0].id)
          }
        })
        .catch(() => {
          toast.error("Failed to load authorized projects")
        })
        .finally(() => {
          setIsLoadingProjects(false)
        })
    }
  }, [open])

  function addTag() {
    const trimmed = tagInput.trim().toLowerCase()
    if (trimmed && !tags.includes(trimmed)) {
      setTags([...tags, trimmed])
      setTagInput("")
    }
  }

  function removeTag(tag: string) {
    setTags(tags.filter((t) => t !== tag))
  }

  function addScope() {
    const trimmed = scopeInput.trim()
    if (trimmed && !scopeRules.includes(trimmed)) {
      setScopeRules([...scopeRules, trimmed])
      setScopeInput("")
    }
  }

  function removeScope(rule: string) {
    setScopeRules(scopeRules.filter((r) => r !== rule))
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!selectedProjectId) {
      toast.error("Please select an authorized project for this target.")
      return
    }

    setIsSubmitting(true)
    if (onAddTarget) {
      onAddTarget({
        projectId: selectedProjectId,
        url: url.trim(),
        type: selectedType,
        description: description.trim() || undefined,
        tags,
        scope: scopeRules.length > 0 ? scopeRules : ["/*"],
        validationStatus: "pending",
      })
    }
    setIsSubmitting(false)
    handleReset()
    onClose()
  }

  function handleReset() {
    setSelectedType("web")
    setUrl("")
    setDescription("")
    setTagInput("")
    setTags([])
    setScopeInput("")
    setScopeRules([])
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        if (!o) {
          handleReset()
          onClose()
        }
      }}
    >
      <DialogContent className="sm:max-w-[540px]">
        <DialogHeader>
          <DialogTitle>Add New Target</DialogTitle>
          <DialogDescription>
            Add an authorized target URL for security assessment under your project. Ownership
            verification will be required before scanning.
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleSubmit} className="space-y-5">
          {/* Project Selector */}
          <div className="space-y-2">
            <Label htmlFor="target-project" className="flex items-center gap-1.5 font-semibold">
              <FolderKanban className="h-4 w-4 text-primary" />
              Target Project <span className="text-destructive">*</span>
            </Label>
            {isLoadingProjects ? (
              <div className="flex items-center gap-2 rounded-md border border-border p-2.5 text-xs text-muted-foreground">
                <Loader2 className="h-4 w-4 animate-spin text-primary" />
                Loading authorized projects...
              </div>
            ) : projects.length === 0 ? (
              <div className="flex flex-col gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-400">
                <p>No active projects found. Create a project before registering targets:</p>
                <Button
                  type="button"
                  size="sm"
                  variant="secondary"
                  className="w-fit gap-1.5 h-7 text-xs"
                  onClick={async () => {
                    try {
                      const newProj = await projectsService.createProject({
                        name: "Web Security Assessment",
                        description: "Default workspace for security assessment targets",
                        risk_level: "medium",
                      })
                      setProjects([newProj])
                      setSelectedProjectId(newProj.id)
                      toast.success("Created default project!")
                    } catch {
                      toast.error("Failed to create project")
                    }
                  }}
                >
                  <Plus className="h-3.5 w-3.5" />
                  Create Default Project
                </Button>
              </div>
            ) : (
              <select
                id="target-project"
                value={selectedProjectId}
                onChange={(e) => setSelectedProjectId(e.target.value)}
                className="w-full rounded-md border border-input bg-card px-3 py-2 text-sm text-foreground ring-offset-background focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2"
                required
              >
                <option value="" disabled>Select project...</option>
                {projects.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name}
                  </option>
                ))}
              </select>
            )}
          </div>
          {/* Target Type Selector */}
          <div className="space-y-2">
            <Label>Target Type</Label>
            <div className="grid grid-cols-3 gap-2">
              {targetTypes.map((tt) => (
                <button
                  key={tt.value}
                  type="button"
                  onClick={() => setSelectedType(tt.value)}
                  className={cn(
                    "flex flex-col items-center gap-1.5 rounded-lg border-2 p-3 text-center transition-all",
                    selectedType === tt.value
                      ? "border-primary bg-primary/5 text-primary"
                      : "border-border bg-card text-muted-foreground hover:border-muted-foreground/30 hover:bg-muted/30",
                  )}
                >
                  <tt.icon className="h-5 w-5" />
                  <span className="text-xs font-semibold">{tt.label}</span>
                  <span className="text-[10px] leading-tight opacity-70">
                    {tt.description}
                  </span>
                </button>
              ))}
            </div>
          </div>

          {/* URL */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <Label htmlFor="target-url">
                {selectedType === "network" ? "IP Range / CIDR" : "Target URL"}
              </Label>
              <div className="flex items-center gap-1">
                {[
                  { name: "vulnweb", url: "http://testphp.vulnweb.com" },
                  { name: "testfire", url: "http://demo.testfire.net" },
                  { name: "juice-shop", url: "https://juice-shop.herokuapp.com" },
                  { name: "localhost", url: "http://localhost:5173" },
                ].map((item) => (
                  <button
                    key={item.url}
                    type="button"
                    onClick={() => setUrl(item.url)}
                    className="rounded border border-border/80 bg-muted/40 px-1.5 py-0.5 text-[10px] font-mono text-muted-foreground hover:text-foreground"
                  >
                    {item.name}
                  </button>
                ))}
              </div>
            </div>
            <Input
              id="target-url"
              placeholder={
                selectedType === "network"
                  ? "e.g., 10.0.2.0/24"
                  : "e.g., https://api.example.com"
              }
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              required
            />
          </div>

          {/* Description */}
          <div className="space-y-2">
            <Label htmlFor="target-description">
              Description{" "}
              <span className="text-muted-foreground font-normal">
                (optional)
              </span>
            </Label>
            <Input
              id="target-description"
              placeholder="Brief description of this target"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
            />
          </div>

          {/* Tags */}
          <div className="space-y-2">
            <Label>Tags</Label>
            <div className="flex gap-2">
              <Input
                placeholder="Add a tag…"
                value={tagInput}
                onChange={(e) => setTagInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    e.preventDefault()
                    addTag()
                  }
                }}
                className="flex-1"
              />
              <Button
                type="button"
                variant="outline"
                size="icon"
                onClick={addTag}
              >
                <Plus className="h-4 w-4" />
              </Button>
            </div>
            {tags.length > 0 && (
              <div className="flex flex-wrap gap-1.5 pt-1">
                {tags.map((tag) => (
                  <Badge
                    key={tag}
                    variant="secondary"
                    className="gap-1 rounded-md pr-1 text-[11px]"
                  >
                    {tag}
                    <button
                      type="button"
                      onClick={() => removeTag(tag)}
                      className="ml-0.5 rounded-sm p-0.5 transition-colors hover:bg-foreground/10"
                    >
                      <X className="h-2.5 w-2.5" />
                    </button>
                  </Badge>
                ))}
              </div>
            )}
          </div>

          {/* Scope */}
          <div className="space-y-2">
            <Label>
              Scope Rules{" "}
              <span className="text-muted-foreground font-normal">
                (optional)
              </span>
            </Label>
            <div className="flex gap-2">
              <Input
                placeholder="e.g., /api/* or !/admin/*"
                value={scopeInput}
                onChange={(e) => setScopeInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    e.preventDefault()
                    addScope()
                  }
                }}
                className="flex-1 font-mono text-xs"
              />
              <Button
                type="button"
                variant="outline"
                size="icon"
                onClick={addScope}
              >
                <Plus className="h-4 w-4" />
              </Button>
            </div>
            {scopeRules.length > 0 && (
              <div className="space-y-1 pt-1">
                {scopeRules.map((rule) => (
                  <div
                    key={rule}
                    className="flex items-center gap-2 rounded-md bg-muted/30 px-3 py-1.5"
                  >
                    <span className="text-primary text-xs">›</span>
                    <span className="flex-1 font-mono text-xs text-foreground">
                      {rule}
                    </span>
                    <button
                      type="button"
                      onClick={() => removeScope(rule)}
                      className="rounded-sm p-0.5 text-muted-foreground transition-colors hover:text-foreground"
                    >
                      <X className="h-3 w-3" />
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>

          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>
              Cancel
            </Button>
            <Button
              type="submit"
              disabled={!url.trim() || isSubmitting || !selectedProjectId || projects.length === 0}
            >
              {isSubmitting ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Adding…
                </>
              ) : (
                <>
                  <Plus className="h-4 w-4" />
                  Add Target
                </>
              )}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
