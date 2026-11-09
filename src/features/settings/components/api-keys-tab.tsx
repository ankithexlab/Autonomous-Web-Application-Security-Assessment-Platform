import { useState } from "react"
import { Copy, Check, Terminal, AlertCircle } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { toast } from "sonner"
import { useAuthStore } from "@/stores/auth-store"

export function ApiKeysTab() {
  const { token: currentAuthToken } = useAuthStore()
  const [copiedId, setCopiedId] = useState<string | null>(null)

  function handleCopy(text: string, id: string) {
    navigator.clipboard.writeText(text)
    setCopiedId(id)
    toast.success("Copied to clipboard")
    setTimeout(() => setCopiedId(null), 2000)
  }

  const curlAuthExample = `curl -X POST "http://localhost:8000/api/v1/auth/login" \\
  -H "Content-Type: application/json" \\
  -d '{"email": "analyst@example.com", "password": "your_secure_password"}'`

  const curlScanExample = `curl -X POST "http://localhost:8000/api/v1/projects/{project_id}/targets/{target_id}/scans" \\
  -H "Authorization: Bearer <access_token>" \\
  -H "Content-Type: application/json" \\
  -d '{"scan_type": "full"}'`

  return (
    <div className="space-y-6">
      {/* Active Session Bearer Token */}
      <div className="rounded-2xl border border-primary/20 bg-primary/5 p-5 shadow-xs flex flex-col sm:flex-row sm:items-start gap-4">
        <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-primary/10 text-primary border border-primary/20">
          <Terminal className="h-5 w-5" />
        </div>
        <div className="space-y-1.5 flex-1">
          <div className="flex items-center gap-2">
            <h4 className="text-sm font-bold text-foreground">Programmatic API Automation</h4>
            <Badge variant="outline" className="text-[10px] font-mono border-primary/30 text-primary">
              JWT BEARER AUTH
            </Badge>
          </div>
          <p className="text-xs text-muted-foreground leading-relaxed">
            AWASAP secures all REST API endpoints using stateless cryptographic JWT Bearer tokens.
            To integrate AWASAP into CI/CD pipelines, automated scripts, or GitHub Actions, authenticate
            using your service account credentials to obtain an access token.
          </p>
          {currentAuthToken && (
            <div className="pt-2 flex flex-col sm:flex-row items-start sm:items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => handleCopy(currentAuthToken, "current-session")}
                className="h-8 text-xs font-mono font-bold gap-1.5 border-primary/30 text-primary hover:bg-primary/10"
              >
                {copiedId === "current-session" ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                Copy Active Session Bearer Token
              </Button>
              <span className="text-[11px] text-muted-foreground">
                (Valid for current authorized session)
              </span>
            </div>
          )}
        </div>
      </div>

      {/* Programmatic Usage Guides */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Step 1: Authentication */}
        <div className="rounded-2xl border border-border/80 bg-card p-5 shadow-sm space-y-3">
          <div className="flex items-center gap-2">
            <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-primary/10 text-primary font-bold text-xs">
              1
            </div>
            <h4 className="text-sm font-bold text-foreground">Step 1: Obtain Access Token</h4>
          </div>
          <p className="text-xs text-muted-foreground">
            Call <code className="bg-muted px-1 py-0.5 rounded font-mono text-[11px] text-foreground">POST /api/v1/auth/login</code> to
            receive an authorized access token and refresh token pair.
          </p>
          <div className="relative rounded-xl bg-muted/60 p-3 font-mono text-[11px] text-foreground overflow-x-auto border border-border/60">
            <pre className="whitespace-pre">{curlAuthExample}</pre>
            <Button
              variant="ghost"
              size="icon"
              onClick={() => handleCopy(curlAuthExample, "curl-auth")}
              className="absolute top-2 right-2 h-6 w-6 text-muted-foreground hover:text-foreground"
            >
              {copiedId === "curl-auth" ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
            </Button>
          </div>
        </div>

        {/* Step 2: Triggering Scans */}
        <div className="rounded-2xl border border-border/80 bg-card p-5 shadow-sm space-y-3">
          <div className="flex items-center gap-2">
            <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-primary/10 text-primary font-bold text-xs">
              2
            </div>
            <h4 className="text-sm font-bold text-foreground">Step 2: Trigger Assessment Scan</h4>
          </div>
          <p className="text-xs text-muted-foreground">
            Pass the Bearer token in the <code className="bg-muted px-1 py-0.5 rounded font-mono text-[11px] text-foreground">Authorization</code> header
            to create and start security scans.
          </p>
          <div className="relative rounded-xl bg-muted/60 p-3 font-mono text-[11px] text-foreground overflow-x-auto border border-border/60">
            <pre className="whitespace-pre">{curlScanExample}</pre>
            <Button
              variant="ghost"
              size="icon"
              onClick={() => handleCopy(curlScanExample, "curl-scan")}
              className="absolute top-2 right-2 h-6 w-6 text-muted-foreground hover:text-foreground"
            >
              {copiedId === "curl-scan" ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
            </Button>
          </div>
        </div>
      </div>

      {/* Honest Architectural Status Callout */}
      <div className="rounded-2xl border border-border/80 bg-card p-5 shadow-sm flex items-start gap-3">
        <AlertCircle className="h-5 w-5 text-amber-400 shrink-0 mt-0.5" />
        <div className="space-y-1">
          <h4 className="text-sm font-bold text-foreground">Persistent Multi-Key Provisioning</h4>
          <p className="text-xs text-muted-foreground leading-relaxed">
            Persistent, independently revocable machine-to-machine API keys with scoped permission masks (e.g. read-only auditor, CI trigger)
            are scheduled for the Phase 6 security roadmap. All API interactions in AWASAP v0.1 currently use genuine JWT authentication
            governed by user ownership and server-side token revocation.
          </p>
        </div>
      </div>
    </div>
  )
}
