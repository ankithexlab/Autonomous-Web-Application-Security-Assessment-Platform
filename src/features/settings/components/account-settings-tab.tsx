import { useState } from "react"
import { Building2, Globe, Users, Database, AlertTriangle, Download, Trash2, Loader2 } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog"
import { toast } from "sonner"
import { useAuthStore } from "@/stores/auth-store"

const WORKSPACE_STORAGE_KEY = "awsap-workspace-settings"

export function AccountSettingsTab() {
  const [orgName, setOrgName] = useState(() => {
    try {
      const stored = localStorage.getItem(WORKSPACE_STORAGE_KEY)
      if (stored) return JSON.parse(stored).orgName ?? "Acme Cybersecurity Corp"
    } catch {
      // fallback
    }
    return "Acme Cybersecurity Corp"
  })

  const [slug, setSlug] = useState(() => {
    try {
      const stored = localStorage.getItem(WORKSPACE_STORAGE_KEY)
      if (stored) return JSON.parse(stored).slug ?? "acmecorp"
    } catch {
      // fallback
    }
    return "acmecorp"
  })

  const [isSaving, setIsSaving] = useState(false)
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false)
  const [isDeleting, setIsDeleting] = useState(false)
  const [confirmText, setConfirmText] = useState("")
  const deleteAccount = useAuthStore((s) => s.deleteAccount)

  async function handleDeleteAccount() {
    setIsDeleting(true)
    try {
      await deleteAccount()
      toast.success("Account successfully deleted. All sessions have been revoked.")
      window.location.href = "/auth/login"
    } catch {
      toast.error("Failed to delete account. Please try again.")
      setIsDeleting(false)
    }
  }

  function handleSaveOrg(e: React.FormEvent) {
    e.preventDefault()
    setIsSaving(true)
    try {
      localStorage.setItem(
        WORKSPACE_STORAGE_KEY,
        JSON.stringify({ orgName, slug }),
      )
      toast.success("Workspace organization settings saved")
    } catch {
      toast.error("Failed to save workspace settings")
    } finally {
      setIsSaving(false)
    }
  }

  function handleClearCache() {
    try {
      sessionStorage.clear()
      toast.success("Local session cache and temporary logs cleared")
    } catch {
      toast.error("Failed to clear local cache")
    }
  }

  function handleExportData() {
    const data = JSON.stringify({ orgName, slug, exportedAt: new Date().toISOString() }, null, 2)
    const blob = new Blob([data], { type: "application/json" })
    const url = URL.createObjectURL(blob)
    const a = document.createElement("a")
    a.href = url
    a.download = "Sentinel-Workspace-Data-Backup.json"
    a.click()
    toast.success("Account data backup exported as JSON")
  }


  return (
    <div className="space-y-6">
      {/* Workspace Details */}
      <form onSubmit={handleSaveOrg} className="rounded-2xl border border-border/80 bg-card p-6 space-y-5 shadow-sm">
        <div>
          <h3 className="text-sm font-bold text-foreground flex items-center gap-2">
            <Building2 className="h-4 w-4 text-primary" />
            Organization & Workspace Details
          </h3>
          <p className="text-xs text-muted-foreground mt-0.5">
            Configure enterprise domain routing and team seat allocation
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="space-y-1.5">
            <label className="text-xs font-semibold text-foreground">Organization Name</label>
            <Input
              value={orgName}
              onChange={(e) => setOrgName(e.target.value)}
              className="text-xs bg-background/50"
              required
            />
          </div>

          <div className="space-y-1.5">
            <label className="text-xs font-semibold text-foreground flex items-center gap-1">
              <Globe className="h-3.5 w-3.5 text-muted-foreground" />
              Workspace Subdomain Slug
            </label>
            <div className="flex items-center">
              <Input
                value={slug}
                onChange={(e) => setSlug(e.target.value)}
                className="text-xs bg-background/50 font-mono rounded-r-none"
                required
              />
              <span className="rounded-r-md border border-l-0 border-border bg-muted/40 px-3 py-2 text-xs font-mono text-muted-foreground select-none">
                .sentinel.io
              </span>
            </div>
          </div>
        </div>

        {/* Seat Usage Bar */}
        <div className="rounded-xl border border-border/40 bg-muted/20 p-4 space-y-2">
          <div className="flex items-center justify-between text-xs">
            <span className="font-bold text-foreground flex items-center gap-1.5">
              <Users className="h-3.5 w-3.5 text-primary" />
              Enterprise Security Analyst Seats
            </span>
            <span className="font-mono text-muted-foreground">4 of 10 Seats Used</span>
          </div>
          <div className="h-2 w-full overflow-hidden rounded-full bg-muted">
            <div className="h-full w-[40%] bg-primary" />
          </div>
        </div>

        <div className="flex justify-end pt-1">
          <Button type="submit" disabled={isSaving} className="text-xs font-bold">
            {isSaving ? "Saving..." : "Save Workspace Changes"}
          </Button>
        </div>
      </form>

      {/* Data Management & Cache */}
      <div className="rounded-2xl border border-border/80 bg-card p-6 space-y-4 shadow-sm">
        <h3 className="text-sm font-bold text-foreground flex items-center gap-2">
          <Database className="h-4 w-4 text-blue-400" />
          Data Management & Storage
        </h3>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <div className="rounded-xl border border-border p-4 space-y-2">
            <p className="text-xs font-bold text-foreground">Clear Application Cache</p>
            <p className="text-[11px] text-muted-foreground">Purge local temporary state, scan logs, and cached finding metadata.</p>
            <Button size="sm" variant="outline" onClick={handleClearCache} className="h-7 text-xs font-bold">
              Clear Local Cache
            </Button>
          </div>

          <div className="rounded-xl border border-border p-4 space-y-2">
            <p className="text-xs font-bold text-foreground">Export Account Backup</p>
            <p className="text-[11px] text-muted-foreground">Download a complete JSON export of workspace configurations and finding histories.</p>
            <Button size="sm" variant="outline" onClick={handleExportData} className="h-7 text-xs font-bold gap-1">
              <Download className="h-3.5 w-3.5" />
              Export JSON Backup
            </Button>
          </div>
        </div>
      </div>

      {/* Danger Zone */}
      <div className="rounded-2xl border border-red-500/30 bg-red-500/5 p-6 space-y-4 shadow-sm">
        <div className="flex items-center gap-2 text-red-400">
          <AlertTriangle className="h-4 w-4" />
          <h3 className="text-sm font-bold">Danger Zone</h3>
          <Badge variant="outline" className="text-[9px] font-mono border-red-500/30 text-red-400">
            DESTRUCTIVE ACTIONS
          </Badge>
        </div>

        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
          <div>
            <p className="text-xs font-bold text-foreground">Delete Account & All Workspace Data</p>
            <p className="text-[11px] text-muted-foreground">Permanently delete your user account, target endpoints, scan history, vulnerabilities, and reports.</p>
          </div>
          <Button
            variant="destructive"
            size="sm"
            onClick={() => {
              setConfirmText("")
              setDeleteDialogOpen(true)
            }}
            className="h-8 text-xs font-bold gap-1.5 shrink-0"
          >
            <Trash2 className="h-3.5 w-3.5" />
            Delete Account
          </Button>
        </div>
      </div>

      {/* Confirmation Dialog for DELETE /auth/me */}
      <Dialog open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle className="text-destructive flex items-center gap-2">
              <AlertTriangle className="h-5 w-5" />
              Permanently Delete Account
            </DialogTitle>
            <DialogDescription className="text-xs text-muted-foreground leading-relaxed pt-2">
              This action is permanent and cannot be undone. All your projects, targets, scans, findings, reports, and active sessions will be permanently purged from the database.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-3 py-2">
            <p className="text-xs font-medium text-foreground">
              To confirm deletion, type <span className="font-mono font-bold text-destructive">DELETE</span> below:
            </p>
            <Input
              value={confirmText}
              onChange={(e) => setConfirmText(e.target.value)}
              placeholder="DELETE"
              className="text-xs font-mono"
            />
          </div>

          <DialogFooter className="gap-2 sm:gap-0">
            <Button
              type="button"
              variant="outline"
              size="sm"
              disabled={isDeleting}
              onClick={() => setDeleteDialogOpen(false)}
              className="text-xs"
            >
              Cancel
            </Button>
            <Button
              type="button"
              variant="destructive"
              size="sm"
              disabled={confirmText !== "DELETE" || isDeleting}
              onClick={handleDeleteAccount}
              className="text-xs gap-1.5 font-bold"
            >
              {isDeleting ? (
                <>
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  Deleting Account...
                </>
              ) : (
                <>
                  <Trash2 className="h-3.5 w-3.5" />
                  Confirm Delete Account
                </>
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
