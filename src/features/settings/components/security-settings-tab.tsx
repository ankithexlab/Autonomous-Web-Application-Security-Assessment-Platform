import { useState } from "react"
import { Lock, Smartphone, Monitor, Globe, Key, LogOut } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import { toast } from "sonner"
import { formatRelativeTime } from "@/utils"
import { useAuthStore } from "@/stores/auth-store"
import { extractErrorMessage } from "@/services/auth.service"

interface ActiveSession {
  id: string
  device: string
  browser: string
  ip: string
  location: string
  lastActive: string
  current: boolean
}

const INITIAL_SESSIONS: ActiveSession[] = [
  {
    id: "sess-1",
    device: "Current Browser Session",
    browser: typeof navigator !== "undefined" ? navigator.userAgent.slice(0, 32) : "Web Browser",
    ip: "Client Local",
    location: "Active Authorized Session",
    lastActive: new Date().toISOString(),
    current: true,
  },
]

export function SecuritySettingsTab() {
  const { changePassword } = useAuthStore()

  const [currentPassword, setCurrentPassword] = useState("")
  const [newPassword, setNewPassword] = useState("")
  const [confirmPassword, setConfirmPassword] = useState("")
  const [isChangingPass, setIsChangingPass] = useState(false)
  const [sessions, setSessions] = useState<ActiveSession[]>(INITIAL_SESSIONS)

  async function handleChangePassword(e: React.FormEvent) {
    e.preventDefault()
    if (!currentPassword) {
      toast.error("Please enter your current password")
      return
    }
    if (newPassword.length < 8) {
      toast.error("New password must be at least 8 characters long")
      return
    }
    if (newPassword !== confirmPassword) {
      toast.error("New passwords do not match")
      return
    }

    setIsChangingPass(true)
    try {
      await changePassword(currentPassword, newPassword)
      setCurrentPassword("")
      setNewPassword("")
      setConfirmPassword("")
      toast.success("Account password updated successfully. Please use your new password next time you sign in.")
    } catch (err) {
      toast.error(extractErrorMessage(err, "Failed to update password"))
    } finally {
      setIsChangingPass(false)
    }
  }

  function handleRevokeSession(id: string) {
    setSessions((prev) => prev.filter((s) => s.id !== id))
    toast.info("Session removed from view. To invalidate all tokens across all devices immediately, change your account password.")
  }

  // Simple password strength calculation
  const passStrength = newPassword.length === 0
    ? 0
    : newPassword.length > 12 && /[A-Z]/.test(newPassword) && /[0-9]/.test(newPassword) && /[^A-Za-z0-9]/.test(newPassword)
    ? 100
    : newPassword.length >= 8
    ? 60
    : 30

  return (
    <div className="space-y-6">
      {/* 2FA Status Card */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 rounded-2xl border border-border/80 bg-card p-6 shadow-sm">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-primary/10 text-primary border border-primary/20">
            <Smartphone className="h-5 w-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-bold text-foreground">Two-Factor Authentication (2FA / TOTP)</h3>
              <Badge variant="outline" className="text-primary border-primary/30 text-[10px] font-bold">
                ENTERPRISE ROADMAP
              </Badge>
            </div>
            <p className="text-xs text-muted-foreground mt-0.5">
              Time-based one-time passwords (TOTP via Google Authenticator or 1Password) integration is scheduled for an upcoming backend release. The platform currently enforces bcrypt password hashing and cryptographic JWT tokens.
            </p>
          </div>
        </div>

        <Button
          variant="outline"
          disabled
          className="text-xs font-bold self-start sm:self-center opacity-70 cursor-not-allowed"
        >
          Scheduled for v1.1
        </Button>
      </div>

      {/* Change Password Form */}
      <form onSubmit={handleChangePassword} className="rounded-2xl border border-border/80 bg-card p-6 space-y-4 shadow-sm">
        <div>
          <h3 className="text-sm font-bold text-foreground flex items-center gap-2">
            <Lock className="h-4 w-4 text-primary" />
            Change Account Password
          </h3>
          <p className="text-xs text-muted-foreground mt-0.5">
            Update your authentication credential. Enforce strong unique passphrases.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="space-y-1.5">
            <label className="text-xs font-semibold text-foreground">Current Password</label>
            <Input
              type="password"
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              className="text-xs bg-background/50 font-mono"
            />
          </div>

          <div className="space-y-1.5">
            <label className="text-xs font-semibold text-foreground">New Password</label>
            <Input
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              className="text-xs bg-background/50 font-mono"
            />
          </div>

          <div className="space-y-1.5">
            <label className="text-xs font-semibold text-foreground">Confirm New Password</label>
            <Input
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              className="text-xs bg-background/50 font-mono"
            />
          </div>
        </div>

        {/* Password Strength Gauge */}
        {newPassword.length > 0 && (
          <div className="space-y-1.5 pt-1">
            <div className="flex items-center justify-between text-[11px]">
              <span className="text-muted-foreground">Password Complexity:</span>
              <span className="font-mono font-bold text-foreground">
                {passStrength === 100 ? "Strong" : passStrength >= 60 ? "Moderate" : "Weak"}
              </span>
            </div>
            <div className="h-1.5 w-full overflow-hidden rounded-full bg-muted">
              <div
                className={`h-full transition-all ${
                  passStrength === 100 ? "bg-emerald-500" : passStrength >= 60 ? "bg-amber-500" : "bg-red-500"
                }`}
                style={{ width: `${passStrength}%` }}
              />
            </div>
          </div>
        )}

        <div className="flex justify-end pt-2">
          <Button type="submit" disabled={isChangingPass || !currentPassword} className="text-xs font-bold gap-1.5">
            <Key className="h-3.5 w-3.5" />
            {isChangingPass ? "Updating..." : "Update Password"}
          </Button>
        </div>
      </form>

      {/* Active Login Sessions Table */}
      <div className="overflow-hidden rounded-2xl border border-border/80 bg-card shadow-sm">
        <div className="p-5 border-b border-border/70 flex items-center justify-between">
          <div>
            <h3 className="text-sm font-bold text-foreground flex items-center gap-2">
              <Monitor className="h-4 w-4 text-blue-400" />
              Active Login Sessions & Devices
            </h3>
            <p className="text-xs text-muted-foreground mt-0.5">
              Review devices currently logged into your Sentinel account
            </p>
          </div>
        </div>

        <div className="divide-y divide-border/40">
          {sessions.map((sess) => (
            <div
              key={sess.id}
              className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-4 hover:bg-muted/20 transition-colors"
            >
              <div className="flex items-center gap-3">
                <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-muted/40 text-muted-foreground">
                  <Globe className="h-4 w-4" />
                </div>

                <div>
                  <div className="flex items-center gap-2">
                    <p className="text-xs font-bold text-foreground">{sess.device}</p>
                    {sess.current && (
                      <Badge variant="default" className="text-[9px] font-mono bg-emerald-500/15 text-emerald-400">
                        THIS DEVICE
                      </Badge>
                    )}
                  </div>
                  <p className="text-[11px] text-muted-foreground font-mono mt-0.5">
                    {sess.ip} · {sess.location} · {formatRelativeTime(new Date(sess.lastActive))}
                  </p>
                </div>
              </div>

              {!sess.current && (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => handleRevokeSession(sess.id)}
                  className="h-7 text-xs text-red-400 border-red-500/30 hover:bg-red-500/10 gap-1 self-start sm:self-center"
                >
                  <LogOut className="h-3 w-3" />
                  Revoke Session
                </Button>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
