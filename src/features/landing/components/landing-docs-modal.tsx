import { useState } from "react"
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@radix-ui/react-tabs"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { BookOpen, Terminal, Code2, ShieldCheck, Check, Copy } from "lucide-react"

interface LandingDocsModalProps {
  open: boolean
  onClose: () => void
}

export function LandingDocsModal({ open, onClose }: LandingDocsModalProps) {
  const [copiedCmd, setCopiedCmd] = useState(false)

  const cliCommand = "npx awasap-cli scan --target https://api.acmecorp.com --type full --format pdf"

  function handleCopy() {
    navigator.clipboard.writeText(cliCommand)
    setCopiedCmd(true)
    setTimeout(() => setCopiedCmd(false), 2000)
  }

  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="sm:max-w-2xl max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <div className="flex items-center gap-2">
            <BookOpen className="h-5 w-5 text-primary" />
            <DialogTitle>AWASAP Platform Documentation</DialogTitle>
          </div>
          <DialogDescription>
            Quickstart guide, CLI scanner commands, and architecture reference.
          </DialogDescription>
        </DialogHeader>

        <Tabs defaultValue="quickstart" className="space-y-4">
          <TabsList className="flex gap-1 rounded-lg border border-border bg-muted/30 p-1">
            <TabsTrigger
              value="quickstart"
              className="flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium text-muted-foreground data-[state=active]:bg-background data-[state=active]:text-foreground"
            >
              <Terminal className="h-3.5 w-3.5" />
              CLI Quickstart
            </TabsTrigger>
            <TabsTrigger
              value="api"
              className="flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium text-muted-foreground data-[state=active]:bg-background data-[state=active]:text-foreground"
            >
              <Code2 className="h-3.5 w-3.5" />
              API Reference
            </TabsTrigger>
            <TabsTrigger
              value="standards"
              className="flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium text-muted-foreground data-[state=active]:bg-background data-[state=active]:text-foreground"
            >
              <ShieldCheck className="h-3.5 w-3.5" />
              OWASP & Compliance
            </TabsTrigger>
          </TabsList>

          {/* Quickstart Tab */}
          <TabsContent value="quickstart" className="space-y-4">
            <div className="rounded-xl border border-border bg-card p-4 space-y-3">
              <h4 className="text-xs font-semibold text-foreground">
                Run Automated Scan via Terminal
              </h4>
              <p className="text-xs text-muted-foreground leading-relaxed">
                Execute an end-to-end vulnerability assessment from any CI/CD pipeline or command-line environment using the official AWASAP CLI package.
              </p>

              <div className="relative rounded-lg bg-[oklch(0.12_0.005_285.82)] p-3 font-mono text-xs text-emerald-400">
                <div className="flex items-center justify-between">
                  <span className="truncate pr-8">{cliCommand}</span>
                  <Button
                    variant="ghost"
                    size="icon-xs"
                    onClick={handleCopy}
                    className="text-muted-foreground hover:text-foreground shrink-0"
                  >
                    {copiedCmd ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                  </Button>
                </div>
              </div>
            </div>

            <div className="space-y-2">
              <h4 className="text-xs font-semibold text-foreground">Key Capabilities</h4>
              <div className="grid grid-cols-2 gap-2 text-xs">
                <div className="rounded border border-border p-2.5">
                  <span className="font-semibold text-foreground block">Zero Configuration</span>
                  <span className="text-[11px] text-muted-foreground">Auto-detects web app stack and API endpoints.</span>
                </div>
                <div className="rounded border border-border p-2.5">
                  <span className="font-semibold text-foreground block">CI/CD Pipeline Integration</span>
                  <span className="text-[11px] text-muted-foreground">GitHub Actions, GitLab CI, Jenkins support.</span>
                </div>
              </div>
            </div>
          </TabsContent>

          {/* API Tab */}
          <TabsContent value="api" className="space-y-3">
            <div className="rounded-xl border border-border bg-card p-4 space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-mono text-xs text-primary font-bold">POST /api/v1/scans/launch</span>
                <Badge variant="outline" className="text-[10px]">JSON</Badge>
              </div>
              <p className="text-xs text-muted-foreground">
                Programmatically trigger automated DAST scans and subscribe to real-time status webhooks.
              </p>
              <pre className="rounded bg-[oklch(0.12_0.005_285.82)] p-3 font-mono text-[11px] text-emerald-400 overflow-x-auto">
{`{
  "targetUrl": "https://api.acmecorp.com",
  "type": "full",
  "modules": ["sqli", "xss", "auth", "headers"],
  "notifyEmail": "secops@acmecorp.com"
}`}
              </pre>
            </div>
          </TabsContent>

          {/* Standards Tab */}
          <TabsContent value="standards" className="space-y-3">
            <div className="rounded-xl border border-border bg-card p-4 space-y-2 text-xs">
              <h4 className="font-semibold text-foreground">Compliance Framework Alignment</h4>
              <p className="text-muted-foreground leading-relaxed">
                AWASAP assessment engines automatically map discovered vulnerabilities to standard industry frameworks including OWASP Top 10 (2021), OWASP API Top 10 (2023), CWE, and CVSS v3.1 scoring formulas.
              </p>
            </div>
          </TabsContent>
        </Tabs>
      </DialogContent>
    </Dialog>
  )
}
