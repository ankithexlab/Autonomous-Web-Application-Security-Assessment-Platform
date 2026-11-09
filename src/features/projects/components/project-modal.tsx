import { useState, useEffect } from "react"
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
import { X, Plus, Loader2 } from "lucide-react"
import type { Project, ProjectStatus, ProjectRiskLevel } from "@/types"

interface ProjectModalProps {
  open: boolean
  projectToEdit?: Project | null
  onClose: () => void
  onSave: (projectData: Partial<Project>) => void
}

export function ProjectModal({
  open,
  projectToEdit,
  onClose,
  onSave,
}: ProjectModalProps) {
  const isEditing = Boolean(projectToEdit)

  const [name, setName] = useState("")
  const [description, setDescription] = useState("")
  const [status, setStatus] = useState<ProjectStatus>("active")
  const [riskLevel, setRiskLevel] = useState<ProjectRiskLevel>("medium")
  const [owner, setOwner] = useState("Alex Rivera")
  const [tags, setTags] = useState<string[]>([])
  const [tagInput, setTagInput] = useState("")
  const [isSubmitting, setIsSubmitting] = useState(false)

  useEffect(() => {
    if (projectToEdit) {
      setName(projectToEdit.name)
      setDescription(projectToEdit.description || "")
      setStatus(projectToEdit.status)
      setRiskLevel(projectToEdit.riskLevel)
      setOwner(projectToEdit.owner)
      setTags(projectToEdit.tags || [])
    } else {
      setName("")
      setDescription("")
      setStatus("active")
      setRiskLevel("medium")
      setOwner("Alex Rivera")
      setTags([])
    }
  }, [projectToEdit, open])

  function handleAddTag() {
    const trimmed = tagInput.trim().toLowerCase().replace(/[^a-z0-9-]/g, "")
    if (trimmed && !tags.includes(trimmed)) {
      setTags([...tags, trimmed])
      setTagInput("")
    }
  }

  function handleRemoveTag(tagToRemove: string) {
    setTags(tags.filter((t) => t !== tagToRemove))
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!name.trim()) return

    setIsSubmitting(true)
    setTimeout(() => {
      onSave({
        id: projectToEdit?.id,
        name: name.trim(),
        description: description.trim() || undefined,
        status,
        riskLevel,
        owner: owner.trim() || "Alex Rivera",
        tags,
      })
      setIsSubmitting(false)
      onClose()
    }, 500)
  }

  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="sm:max-w-[500px]">
        <DialogHeader>
          <DialogTitle>
            {isEditing ? "Edit Security Project" : "Create New Security Project"}
          </DialogTitle>
          <DialogDescription>
            {isEditing
              ? "Update project metadata, risk classification, and scope tags."
              : "Organize web applications, APIs, and targets under a unified security project."}
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleSubmit} className="space-y-4">
          {/* Project Name */}
          <div className="space-y-1.5">
            <Label htmlFor="proj-name">Project Name *</Label>
            <Input
              id="proj-name"
              placeholder="e.g. Acme SaaS Infrastructure"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
            />
          </div>

          {/* Description */}
          <div className="space-y-1.5">
            <Label htmlFor="proj-desc">Description</Label>
            <Input
              id="proj-desc"
              placeholder="Brief summary of targets and architecture scope..."
              value={description}
              onChange={(e) => setDescription(e.target.value)}
            />
          </div>

          {/* Status & Risk Level Grid */}
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <Label htmlFor="proj-status">Status</Label>
              <select
                id="proj-status"
                value={status}
                onChange={(e) => setStatus(e.target.value as ProjectStatus)}
                className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-xs transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring dark:bg-input/30"
              >
                <option value="active">Active</option>
                <option value="paused">Paused</option>
                <option value="archived">Archived</option>
              </select>
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="proj-risk">Initial Risk Level</Label>
              <select
                id="proj-risk"
                value={riskLevel}
                onChange={(e) => setRiskLevel(e.target.value as ProjectRiskLevel)}
                className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-xs transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring dark:bg-input/30"
              >
                <option value="critical">Critical Risk</option>
                <option value="high">High Risk</option>
                <option value="medium">Medium Risk</option>
                <option value="low">Low Risk</option>
              </select>
            </div>
          </div>

          {/* Owner */}
          <div className="space-y-1.5">
            <Label htmlFor="proj-owner">Lead Security Owner</Label>
            <Input
              id="proj-owner"
              placeholder="Alex Rivera"
              value={owner}
              onChange={(e) => setOwner(e.target.value)}
            />
          </div>

          {/* Tags Builder */}
          <div className="space-y-1.5">
            <Label>Project Scope Tags</Label>
            <div className="flex items-center gap-2">
              <Input
                placeholder="Add tag (e.g. production, aws) and press Enter..."
                value={tagInput}
                onChange={(e) => setTagInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    e.preventDefault()
                    handleAddTag()
                  }
                }}
              />
              <Button type="button" variant="outline" size="sm" onClick={handleAddTag}>
                <Plus className="h-4 w-4" />
              </Button>
            </div>

            {tags.length > 0 && (
              <div className="flex flex-wrap gap-1 pt-1">
                {tags.map((tag) => (
                  <Badge key={tag} variant="secondary" className="gap-1 font-mono text-xs">
                    #{tag}
                    <button type="button" onClick={() => handleRemoveTag(tag)}>
                      <X className="h-3 w-3 hover:text-red-400" />
                    </button>
                  </Badge>
                ))}
              </div>
            )}
          </div>

          <DialogFooter className="pt-2">
            <Button type="button" variant="outline" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" disabled={!name.trim() || isSubmitting}>
              {isSubmitting ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin mr-1" />
                  Saving...
                </>
              ) : isEditing ? (
                "Save Changes"
              ) : (
                "Create Project"
              )}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
