import { useState } from "react"
import { Mail, Volume2, Webhook, Send, Check } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import { toast } from "sonner"

const NOTIF_STORAGE_KEY = "awsap-notification-preferences"

interface NotificationPreferences {
  criticalAlerts: boolean
  weeklySummary: boolean
  scanCompletions: boolean
  productUpdates: boolean
  audioAlerts: boolean
  webhookUrl: string
}

const DEFAULT_PREFS: NotificationPreferences = {
  criticalAlerts: true,
  weeklySummary: true,
  scanCompletions: true,
  productUpdates: false,
  audioAlerts: true,
  webhookUrl: "",
}

export function NotificationSettingsTab() {
  const [prefs, setPrefs] = useState<NotificationPreferences>(() => {
    try {
      const stored = localStorage.getItem(NOTIF_STORAGE_KEY)
      if (stored) return { ...DEFAULT_PREFS, ...JSON.parse(stored) }
    } catch {
      // fallback
    }
    return DEFAULT_PREFS
  })

  const [testingWebhook, setTestingWebhook] = useState(false)

  function updatePref<K extends keyof NotificationPreferences>(key: K, value: NotificationPreferences[K]) {
    setPrefs((prev) => {
      const next = { ...prev, [key]: value }
      try {
        localStorage.setItem(NOTIF_STORAGE_KEY, JSON.stringify(next))
      } catch {
        // ignore
      }
      return next
    })
  }

  function handleTestWebhook() {
    if (!prefs.webhookUrl || !prefs.webhookUrl.startsWith("https://")) {
      toast.error("Please provide a valid HTTPS Webhook endpoint URL")
      return
    }
    setTestingWebhook(true)
    setTimeout(() => {
      setTestingWebhook(false)
      toast.info("Webhook format verified. Note: Automatic dispatch for live scans requires backend outbound worker configuration.")
    }, 800)
  }


  return (
    <div className="space-y-6">
      {/* Email Notifications */}
      <div className="rounded-2xl border border-border/80 bg-card p-6 space-y-4 shadow-sm">
        <div>
          <h3 className="text-sm font-bold text-foreground flex items-center gap-2">
            <Mail className="h-4 w-4 text-primary" />
            Email Security Alerts & Summaries
          </h3>
          <p className="text-xs text-muted-foreground mt-0.5">
            Configure automated email notifications dispatched for security events
          </p>
        </div>

        <div className="divide-y divide-border/40">
          <div className="flex items-center justify-between py-3">
            <div>
              <div className="flex items-center gap-2">
                <p className="text-xs font-bold text-foreground">Critical Vulnerability Direct Dispatch</p>
                <Badge variant="default" className="bg-red-500/15 text-red-400 text-[9px]">
                  HIGH PRIORITY
                </Badge>
              </div>
              <p className="text-[11px] text-muted-foreground">Receive instant emails when a Critical CVSS 9.0+ vulnerability is detected</p>
            </div>
            <input
              type="checkbox"
              checked={prefs.criticalAlerts}
              onChange={(e) => {
                updatePref("criticalAlerts", e.target.checked)
                toast.success(`Critical vulnerability email alerts ${e.target.checked ? "enabled" : "disabled"}`)
              }}
              className="h-4 w-4 rounded border-border text-primary focus:ring-primary/40"
            />
          </div>

          <div className="flex items-center justify-between py-3">
            <div>
              <p className="text-xs font-bold text-foreground">Weekly Executive Summary Digest</p>
              <p className="text-[11px] text-muted-foreground">Receive weekly PDF risk posture summaries every Monday morning</p>
            </div>
            <input
              type="checkbox"
              checked={prefs.weeklySummary}
              onChange={(e) => {
                updatePref("weeklySummary", e.target.checked)
                toast.success(`Weekly summary digest ${e.target.checked ? "enabled" : "disabled"}`)
              }}
              className="h-4 w-4 rounded border-border text-primary focus:ring-primary/40"
            />
          </div>

          <div className="flex items-center justify-between py-3">
            <div>
              <p className="text-xs font-bold text-foreground">Continuous Scan Completion Notices</p>
              <p className="text-[11px] text-muted-foreground">Notify when automated nightly scans finish executing</p>
            </div>
            <input
              type="checkbox"
              checked={prefs.scanCompletions}
              onChange={(e) => {
                updatePref("scanCompletions", e.target.checked)
                toast.success(`Scan completion emails ${e.target.checked ? "enabled" : "disabled"}`)
              }}
              className="h-4 w-4 rounded border-border text-primary focus:ring-primary/40"
            />
          </div>

          <div className="flex items-center justify-between py-3">
            <div>
              <p className="text-xs font-bold text-foreground">Sentinel Platform Product Updates</p>
              <p className="text-[11px] text-muted-foreground">News regarding new vulnerability plugins and security rules</p>
            </div>
            <input
              type="checkbox"
              checked={prefs.productUpdates}
              onChange={(e) => {
                updatePref("productUpdates", e.target.checked)
                toast.success(`Product update emails ${e.target.checked ? "enabled" : "disabled"}`)
              }}
              className="h-4 w-4 rounded border-border text-primary focus:ring-primary/40"
            />
          </div>
        </div>
      </div>

      {/* In-App & Sound Notifications */}
      <div className="rounded-2xl border border-border/80 bg-card p-6 space-y-4 shadow-sm">
        <div>
          <h3 className="text-sm font-bold text-foreground flex items-center gap-2">
            <Volume2 className="h-4 w-4 text-amber-400" />
            In-App Audio Alerts
          </h3>
          <p className="text-xs text-muted-foreground mt-0.5">
            Console audio alerts during active live scans
          </p>
        </div>

        <div className="flex items-center justify-between py-2">
          <div>
            <p className="text-xs font-bold text-foreground">Play Sound on Critical Finding</p>
            <p className="text-[11px] text-muted-foreground">Triggers audio tone when an active scan discovers a Critical vulnerability</p>
          </div>
          <input
            type="checkbox"
            checked={prefs.audioAlerts}
            onChange={(e) => {
              updatePref("audioAlerts", e.target.checked)
              toast.success(`Audio alert sounds ${e.target.checked ? "enabled" : "disabled"}`)
            }}
            className="h-4 w-4 rounded border-border text-primary focus:ring-primary/40"
          />
        </div>
      </div>

      {/* Webhook Integrations */}
      <div className="rounded-2xl border border-border/80 bg-card p-6 space-y-4 shadow-sm">
        <div>
          <h3 className="text-sm font-bold text-foreground flex items-center gap-2">
            <Webhook className="h-4 w-4 text-emerald-400" />
            Slack / Discord / PagerDuty Webhook Integration
          </h3>
          <p className="text-xs text-muted-foreground mt-0.5">
            Post JSON alert payloads directly into team communication channels
          </p>
        </div>

        <div className="space-y-3">
          <div className="space-y-1.5">
            <label className="text-xs font-semibold text-foreground">Webhook Endpoint URL</label>
            <Input
              value={prefs.webhookUrl}
              onChange={(e) => updatePref("webhookUrl", e.target.value)}
              className="text-xs font-mono bg-background/50"
              placeholder="https://hooks.slack.com/services/..."
            />
          </div>


          <div className="flex items-center justify-between pt-1">
            <div className="flex items-center gap-2">
              <Badge variant="outline" className="text-[10px] font-mono border-emerald-500/30 text-emerald-400">
                <Check className="h-3 w-3 mr-1" /> Active Channel
              </Badge>
              <span className="text-xs text-muted-foreground">Format: JSON Payload</span>
            </div>

            <Button
              size="sm"
              variant="outline"
              disabled={testingWebhook}
              onClick={handleTestWebhook}
              className="gap-1.5 text-xs font-bold"
            >
              <Send className="h-3.5 w-3.5" />
              {testingWebhook ? "Testing..." : "Test Webhook Connection"}
            </Button>
          </div>
        </div>
      </div>
    </div>
  )
}
