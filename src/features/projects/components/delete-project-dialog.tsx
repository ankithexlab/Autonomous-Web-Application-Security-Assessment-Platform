import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import { AlertTriangle } from "lucide-react"
import type { Project } from "@/types"

interface DeleteProjectDialogProps {
  project: Project | null
  open: boolean
  onClose: () => void
  onConfirm: (projectId: string) => void
}

export function DeleteProjectDialog({
  project,
  open,
  onClose,
  onConfirm,
}: DeleteProjectDialogProps) {
  if (!project) return null

  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="sm:max-w-[420px]">
        <DialogHeader>
          <div className="flex items-center gap-2 text-red-400">
            <AlertTriangle className="h-5 w-5" />
            <DialogTitle>Delete Project</DialogTitle>
          </div>
          <DialogDescription className="pt-2 text-xs">
            Are you sure you want to delete <strong className="text-foreground">{project.name}</strong>? This action cannot be undone and will remove all associated target configurations and scan histories.
          </DialogDescription>
        </DialogHeader>

        <DialogFooter className="pt-3">
          <Button variant="outline" size="sm" onClick={onClose}>
            Cancel
          </Button>
          <Button
            variant="destructive"
            size="sm"
            onClick={() => {
              onConfirm(project.id)
              onClose()
            }}
          >
            Delete Project
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
