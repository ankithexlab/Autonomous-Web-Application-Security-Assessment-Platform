import { useEffect, useState } from "react"
import { User as UserIcon, Mail, Shield, Clock, Camera, Save, Check } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import { toast } from "sonner"
import { useAuthStore } from "@/stores/auth-store"
import { extractErrorMessage } from "@/services/auth.service"

const PREFS_STORAGE_KEY = "awsap-profile-preferences"

export function ProfileSettingsTab() {
  const { user, updateProfile } = useAuthStore()

  const [fullName, setFullName] = useState(user?.name ?? "")
  const [email, setEmail] = useState(user?.email ?? "")
  const [role, setRole] = useState(user?.role?.toUpperCase() ?? "ANALYST")
  const [department, setDepartment] = useState("SecOps / Red Team")
  const [timezone, setTimezone] = useState("UTC-05:00 (Eastern Time)")
  const [isSaving, setIsSaving] = useState(false)
  const [saved, setSaved] = useState(false)

  // Load client-persisted preferences and sync user
  useEffect(() => {
    if (user) {
      setFullName(user.name)
      setEmail(user.email)
      setRole(user.role.toUpperCase())
    }
    try {
      const stored = localStorage.getItem(PREFS_STORAGE_KEY)
      if (stored) {
        const parsed = JSON.parse(stored)
        if (parsed.department) setDepartment(parsed.department)
        if (parsed.timezone) setTimezone(parsed.timezone)
      }
    } catch {
      // Ignore localStorage parse errors
    }
  }, [user])

  const initials = (fullName || user?.name || "U")
    .split(" ")
    .map((w) => w[0])
    .join("")
    .slice(0, 2)
    .toUpperCase()

  async function handleSaveProfile(e: React.FormEvent) {
    e.preventDefault()
    setIsSaving(true)
    try {
      await updateProfile({ name: fullName.trim() })
      try {
        localStorage.setItem(
          PREFS_STORAGE_KEY,
          JSON.stringify({ department, timezone }),
        )
      } catch {
        // Ignore localStorage error
      }
      setSaved(true)
      toast.success("Profile updated successfully")
      setTimeout(() => setSaved(false), 2500)
    } catch (err) {
      toast.error(extractErrorMessage(err, "Failed to update profile"))
    } finally {
      setIsSaving(false)
    }
  }

  return (
    <form onSubmit={handleSaveProfile} className="space-y-6">
      {/* Top Banner: Avatar & Summary */}
      <div className="flex flex-col sm:flex-row sm:items-center gap-4 rounded-2xl border border-border/80 bg-card p-5 shadow-sm">
        <div className="relative group shrink-0">
          <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-primary/15 font-mono text-xl font-extrabold text-primary border border-primary/30 shadow-xs">
            {initials}
          </div>
          <button
            type="button"
            className="absolute -bottom-1 -right-1 flex h-6 w-6 items-center justify-center rounded-full bg-primary text-primary-foreground shadow-sm hover:scale-105 transition-transform"
            title="Change Avatar"
          >
            <Camera className="h-3 w-3" />
          </button>
        </div>

        <div className="space-y-1 flex-1">
          <div className="flex items-center gap-2">
            <h3 className="text-base font-bold text-foreground">{fullName || "User Profile"}</h3>
            <Badge variant="outline" className="text-[10px] font-mono border-primary/30 text-primary">
              {user?.role?.toUpperCase() ?? "ANALYST"}
            </Badge>
          </div>
          <p className="text-xs text-muted-foreground">{role} · {department}</p>
          <p className="text-[11px] font-mono text-muted-foreground/80">{email}</p>
        </div>

        <Button type="submit" disabled={isSaving} className="gap-2 font-bold self-start sm:self-center">
          {saved ? <Check className="h-4 w-4 text-emerald-400" /> : <Save className="h-4 w-4" />}
          {isSaving ? "Saving..." : saved ? "Saved!" : "Save Profile"}
        </Button>
      </div>


      {/* Form Fields Grid */}
      <div className="rounded-2xl border border-border/80 bg-card p-6 space-y-5 shadow-sm">
        <h4 className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
          Personal & Professional Information
        </h4>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="space-y-1.5">
            <label className="text-xs font-semibold text-foreground flex items-center gap-1.5">
              <UserIcon className="h-3.5 w-3.5 text-muted-foreground" />
              Full Name
            </label>
            <Input
              value={fullName}
              onChange={(e) => setFullName(e.target.value)}
              className="text-xs bg-background/50"
              required
            />
          </div>

          <div className="space-y-1.5">
            <label className="text-xs font-semibold text-foreground flex items-center gap-1.5">
              <Mail className="h-3.5 w-3.5 text-muted-foreground" />
              Email Address
            </label>
            <Input
              type="email"
              value={email}
              disabled
              title="Email address is associated with your login account and cannot be modified directly"
              className="text-xs bg-muted/40 font-mono cursor-not-allowed opacity-80"
            />
          </div>

          <div className="space-y-1.5">
            <label className="text-xs font-semibold text-foreground flex items-center gap-1.5">
              <Shield className="h-3.5 w-3.5 text-muted-foreground" />
              Job Title / Role
            </label>
            <Input
              value={role}
              onChange={(e) => setRole(e.target.value)}
              className="text-xs bg-background/50"
            />
          </div>

          <div className="space-y-1.5">
            <label className="text-xs font-semibold text-foreground flex items-center gap-1.5">
              <UserIcon className="h-3.5 w-3.5 text-muted-foreground" />
              Department / Team
            </label>
            <Input
              value={department}
              onChange={(e) => setDepartment(e.target.value)}
              className="text-xs bg-background/50"
            />
          </div>

        </div>

        <div className="pt-2 border-t border-border/40">
          <h4 className="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-3">
            Localization & Regional Preferences
          </h4>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-foreground flex items-center gap-1.5">
                <Clock className="h-3.5 w-3.5 text-muted-foreground" />
                Default Timezone
              </label>
              <select
                value={timezone}
                onChange={(e) => setTimezone(e.target.value)}
                className="w-full rounded-md border border-border bg-background/50 px-3 py-2 text-xs font-mono text-foreground focus:outline-hidden focus:ring-1 focus:ring-primary"
              >
                <option value="UTC-05:00 (Eastern Time)">UTC-05:00 (Eastern Time - US & Canada)</option>
                <option value="UTC-08:00 (Pacific Time)">UTC-08:00 (Pacific Time - US & Canada)</option>
                <option value="UTC+00:00 (GMT/UTC)">UTC+00:00 (Greenwich Mean Time / UTC)</option>
                <option value="UTC+01:00 (Central European Time)">UTC+01:00 (Central European Time)</option>
                <option value="UTC+05:30 (India Standard Time)">UTC+05:30 (India Standard Time)</option>
              </select>
            </div>
          </div>
        </div>
      </div>
    </form>
  )
}
