import { useState, useEffect } from "react"
import { useNavigate } from "react-router"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@radix-ui/react-tabs"
import {
  Sparkles,
  CheckCircle2,
  FileCode,
  BookOpen,
  Copy,
  Check,
  Shield,
  ExternalLink,
  Code2,
  AlertTriangle,
} from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Separator } from "@/components/ui/separator"
import { toast } from "sonner"
import { aiService, type AIAnalysisResponse, type AIRemediationResponse } from "@/services/ai.service"
import { findingsService } from "@/services/findings.service"
import { SeverityBadge } from "@/features/dashboard/components/severity-badge"
import { ROUTES } from "@/constants"
import { formatRelativeTime } from "@/utils"
import type { Finding } from "@/types"

interface FindingDetailViewProps {
  finding: Finding
}

export function FindingDetailView({ finding }: FindingDetailViewProps) {
  const navigate = useNavigate()
  const [copiedVector, setCopiedVector] = useState(false)
  const [copiedCodeIndex, setCopiedCodeIndex] = useState<number | null>(null)
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [aiResult, setAiResult] = useState<AIAnalysisResponse | null>(null)
  const [isGeneratingRemediation, setIsGeneratingRemediation] = useState(false)
  const [remediationData, setRemediationData] = useState<AIRemediationResponse | null>(null)
  const [currentStatus, setCurrentStatus] = useState<string>(finding.status)
  const [isUpdatingStatus, setIsUpdatingStatus] = useState(false)

  // Initialize cached AI analysis or remediation if already present on finding
  useEffect(() => {
    if (finding.aiExplanationJson) {
      try {
        setAiResult(JSON.parse(finding.aiExplanationJson))
      } catch {
        // ignore json error
      }
    }
    if (finding.aiRemediationJson) {
      try {
        setRemediationData(JSON.parse(finding.aiRemediationJson))
      } catch {
        // ignore json error
      }
    }
  }, [finding.aiExplanationJson, finding.aiRemediationJson])

  async function handleMarkResolved() {
    setIsUpdatingStatus(true)
    try {
      await findingsService.updateStatus(finding.id, "resolved")
      setCurrentStatus("resolved")
      toast.success("Vulnerability finding marked as resolved")
      window.dispatchEvent(
        new CustomEvent("awsap:finding_updated", {
          detail: { findingId: finding.id, status: "resolved" },
        }),
      )
    } catch {
      toast.error("Failed to update finding status")
    } finally {
      setIsUpdatingStatus(false)
    }
  }

  function handleAskSentinel() {
    navigate(`${ROUTES.AI_ASSISTANT}?findingId=${finding.id}&title=${encodeURIComponent(finding.title)}`)
  }

  async function handleAnalyzeFinding() {
    setIsAnalyzing(true)
    try {
      const res = await aiService.analyzeFinding(finding.id)
      setAiResult(res)
      toast.success("AI Security Analysis generated")
    } catch {
      toast.error("Failed to generate AI analysis")
    } finally {
      setIsAnalyzing(false)
    }
  }

  async function handleGenerateRemediation() {
    setIsGeneratingRemediation(true)
    try {
      const res = await aiService.getRemediation(finding.id)
      setRemediationData(res)
      toast.success("AI Remediation plan generated")
    } catch {
      toast.error("Failed to generate remediation plan")
    } finally {
      setIsGeneratingRemediation(false)
    }
  }

  function handleCopyVector() {
    if (finding.cvss?.vector) {
      navigator.clipboard.writeText(finding.cvss.vector)
      setCopiedVector(true)
      toast.success("CVSS Vector string copied")
      setTimeout(() => setCopiedVector(false), 2000)
    }
  }

  function handleCopyCode(code: string, index: number) {
    navigator.clipboard.writeText(code)
    setCopiedCodeIndex(index)
    toast.success("Code snippet copied to clipboard")
    setTimeout(() => setCopiedCodeIndex(null), 2000)
  }

  return (
    <div className="space-y-5 text-foreground">
      {/* Top Banner & Main Metadata */}
      <div className="rounded-2xl border border-border/80 bg-card p-5 shadow-sm space-y-4">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
          <div className="space-y-1.5 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <SeverityBadge severity={finding.severity} />
              {finding.cweId && (
                <Badge variant="outline" className="font-mono text-xs">
                  {finding.cweId}
                </Badge>
              )}
              <Badge variant="secondary" className="text-xs font-semibold">
                {finding.category}
              </Badge>
              <span className="text-xs text-muted-foreground">
                Discovered {formatRelativeTime(new Date(finding.createdAt))}
              </span>
            </div>

            <h2 className="text-xl font-extrabold tracking-tight text-foreground">
              {finding.title}
            </h2>

            <div className="flex items-center gap-2 font-mono text-xs text-primary">
              {finding.httpMethod && (
                <span className="rounded bg-primary/10 px-1.5 py-0.5 font-bold uppercase">
                  {finding.httpMethod}
                </span>
              )}
              <span className="underline decoration-primary/40 truncate">
                {finding.affectedUrl}
              </span>
            </div>
          </div>

          {/* Quick Actions */}
          <div className="flex items-center gap-2 shrink-0 flex-wrap">
            <Button
              size="sm"
              variant="outline"
              onClick={handleAskSentinel}
              className="gap-1.5 text-xs border-violet-500/30 text-violet-400 hover:bg-violet-500/10"
            >
              <Sparkles className="h-3.5 w-3.5" />
              Ask Sentinel AI
            </Button>
            {currentStatus !== "resolved" ? (
              <Button
                size="sm"
                disabled={isUpdatingStatus}
                onClick={handleMarkResolved}
                className="gap-1 text-xs bg-emerald-600 hover:bg-emerald-500"
              >
                <CheckCircle2 className="h-3.5 w-3.5" />
                {isUpdatingStatus ? "Updating..." : "Mark Resolved"}
              </Button>
            ) : (
              <Badge variant="outline" className="border-emerald-500/30 text-emerald-400 bg-emerald-500/10 text-xs px-2.5 py-1">
                Resolved
              </Badge>
            )}
          </div>
        </div>

        <Separator />

        {/* Core Metrics Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
          <div className="rounded-xl bg-muted/30 p-3 border border-border/40">
            <span className="text-muted-foreground font-medium">CVSS Score</span>
            <div className="mt-1 flex items-baseline gap-1">
              <span className="text-xl font-extrabold font-mono text-foreground">
                {finding.cvssScore !== undefined ? finding.cvssScore.toFixed(1) : "N/A"}
              </span>
              <span className="text-[10px] text-muted-foreground">/ 10.0</span>
            </div>
          </div>

          <div className="rounded-xl bg-muted/30 p-3 border border-border/40">
            <span className="text-muted-foreground font-medium">Affected Parameter</span>
            <p className="mt-1 font-mono font-bold text-foreground truncate">
              {finding.affectedParameter || "None / Global"}
            </p>
          </div>

          <div className="rounded-xl bg-muted/30 p-3 border border-border/40">
            <span className="text-muted-foreground font-medium">CWE Name</span>
            <p className="mt-1 font-bold text-foreground truncate">
              {finding.cweName || "Custom Security Audit"}
            </p>
          </div>

          <div className="rounded-xl bg-muted/30 p-3 border border-border/40">
            <span className="text-muted-foreground font-medium">Assignee</span>
            <p className="mt-1 font-bold text-foreground">
              {finding.assignee || "Unassigned"}
            </p>
          </div>
        </div>
      </div>

      {/* Tabs Layout */}
      <Tabs defaultValue="ai" className="space-y-4">
        <TabsList className="flex gap-1.5 rounded-xl border border-border/80 bg-muted/40 p-1.5">
          <TabsTrigger
            value="ai"
            className="flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-bold text-muted-foreground transition-all data-[state=active]:bg-card data-[state=active]:text-primary data-[state=active]:shadow-xs"
          >
            <Sparkles className="h-3.5 w-3.5 text-violet-400" />
            AI Explanation & Risk
          </TabsTrigger>
          <TabsTrigger
            value="cvss"
            className="flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-bold text-muted-foreground transition-all data-[state=active]:bg-card data-[state=active]:text-primary data-[state=active]:shadow-xs"
          >
            <Shield className="h-3.5 w-3.5 text-blue-400" />
            CVSS & OWASP Mapping
          </TabsTrigger>
          <TabsTrigger
            value="remediation"
            className="flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-bold text-muted-foreground transition-all data-[state=active]:bg-card data-[state=active]:text-primary data-[state=active]:shadow-xs"
          >
            <FileCode className="h-3.5 w-3.5 text-emerald-400" />
            Recommendation & Fix Code
          </TabsTrigger>
          <TabsTrigger
            value="evidence"
            className="flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-bold text-muted-foreground transition-all data-[state=active]:bg-card data-[state=active]:text-primary data-[state=active]:shadow-xs"
          >
            <BookOpen className="h-3.5 w-3.5 text-amber-400" />
            Proof of Concept Payload
          </TabsTrigger>
        </TabsList>

        {/* ── TAB 1: AI EXPLANATION ── */}
        <TabsContent value="ai">
          <div className="rounded-2xl border border-violet-500/20 bg-card p-5 space-y-4 shadow-sm">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-violet-400">
                <Sparkles className="h-4 w-4" />
                <h3 className="text-sm font-bold">AI Security Assistant Analysis</h3>
              </div>
              <Button
                size="sm"
                variant="outline"
                disabled={isAnalyzing}
                onClick={handleAnalyzeFinding}
                className="gap-1.5 text-xs border-violet-500/30 text-violet-400 hover:bg-violet-500/10"
              >
                <Sparkles className="h-3.5 w-3.5" />
                {isAnalyzing ? "Analyzing..." : "Generate AI Security Analysis"}
              </Button>
            </div>

            {aiResult ? (
              <div className="space-y-4 text-xs leading-relaxed">
                <div className="rounded-xl bg-violet-500/5 p-4 border border-violet-500/15">
                  <span className="font-bold text-foreground block mb-1">Executive Summary</span>
                  <p className="text-muted-foreground">{aiResult.summary}</p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  <div className="rounded-xl bg-muted/20 p-4 border border-border/50">
                    <span className="font-bold text-foreground block mb-1">Risk & Exploit Scenario</span>
                    <p className="text-muted-foreground">{aiResult.risk_explanation}</p>
                  </div>

                  <div className="rounded-xl bg-muted/20 p-4 border border-border/50">
                    <span className="font-bold text-foreground block mb-1">Business Impact</span>
                    <p className="text-muted-foreground">{aiResult.impact}</p>
                  </div>
                </div>

                {aiResult.secure_code_example && (
                  <div className="rounded-xl bg-muted/30 p-4 border border-border/60">
                    <span className="font-bold text-foreground block mb-2">Secure Code Implementation Example</span>
                    <pre className="p-3 bg-black/50 rounded-lg text-[11px] font-mono overflow-x-auto text-emerald-400">
                      <code>{aiResult.secure_code_example}</code>
                    </pre>
                  </div>
                )}
              </div>
            ) : finding.aiExplanation ? (
              <div className="space-y-4 text-xs leading-relaxed">
                <div className="rounded-xl bg-violet-500/5 p-4 border border-violet-500/15">
                  <span className="font-bold text-foreground block mb-1">Executive Summary</span>
                  <p className="text-muted-foreground">{finding.aiExplanation.summary}</p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  <div className="rounded-xl bg-muted/20 p-4 border border-border/50">
                    <span className="font-bold text-foreground block mb-1">Exploit Attack Scenario</span>
                    <p className="text-muted-foreground">{finding.aiExplanation.exploitScenario}</p>
                  </div>

                  <div className="rounded-xl bg-muted/20 p-4 border border-border/50">
                    <span className="font-bold text-foreground block mb-1">Business Impact & Compliance Risk</span>
                    <p className="text-muted-foreground">{finding.aiExplanation.businessRisk}</p>
                  </div>
                </div>
              </div>
            ) : (
              <p className="text-xs text-muted-foreground">Click 'Generate AI Security Analysis' to perform deep AI risk assessment.</p>
            )}
          </div>
        </TabsContent>

        {/* ── TAB 2: CVSS & OWASP ── */}
        <TabsContent value="cvss">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* CVSS Metrics Breakdown */}
            <div className="rounded-2xl border border-border/80 bg-card p-5 space-y-4 shadow-sm">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-bold text-foreground">CVSS v3.1 Metric Breakdown</h3>
                {finding.cvssScore && (
                  <Badge variant="outline" className="font-mono text-xs">
                    Score: {finding.cvssScore.toFixed(1)}
                  </Badge>
                )}
              </div>

              {finding.cvss ? (
                <>
                  <div className="flex items-center justify-between rounded-xl bg-muted/40 px-3 py-2 border border-border/40 font-mono text-xs">
                    <span className="text-muted-foreground truncate max-w-[260px]">
                      {finding.cvss.vector}
                    </span>
                    <Button variant="ghost" size="icon" onClick={handleCopyVector} className="h-6 w-6">
                      {copiedVector ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                    </Button>
                  </div>

                  <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                    {[
                      { label: "Attack Vector (AV)", val: finding.cvss.attackVector },
                      { label: "Attack Complexity (AC)", val: finding.cvss.attackComplexity },
                      { label: "Privileges Required (PR)", val: finding.cvss.privilegesRequired },
                      { label: "User Interaction (UI)", val: finding.cvss.userInteraction },
                      { label: "Confidentiality (C)", val: finding.cvss.confidentialityImpact },
                      { label: "Integrity (I)", val: finding.cvss.integrityImpact },
                    ].map((item) => (
                      <div key={item.label} className="rounded-lg border border-border/50 p-2.5 bg-muted/20">
                        <span className="text-[10px] text-muted-foreground block">{item.label}</span>
                        <span className="font-bold text-foreground">{item.val}</span>
                      </div>
                    ))}
                  </div>
                </>
              ) : (
                <p className="text-xs text-muted-foreground">CVSS metric details not specified.</p>
              )}
            </div>

            {/* OWASP & Security Standards */}
            <div className="rounded-2xl border border-border/80 bg-card p-5 space-y-4 shadow-sm">
              <h3 className="text-sm font-bold text-foreground">OWASP & Compliance Category Mapping</h3>
              {finding.owasp && finding.owasp.length > 0 ? (
                <div className="space-y-2.5">
                  {finding.owasp.map((o) => (
                    <div key={o.id} className="flex items-center gap-3 rounded-xl border border-primary/20 bg-primary/[0.04] p-3.5">
                      <span className="rounded-lg bg-primary/15 px-2.5 py-1 font-mono text-xs font-extrabold text-primary">
                        {o.id}
                      </span>
                      <div>
                        <p className="text-xs font-bold text-foreground">{o.name}</p>
                        <p className="text-[10px] text-muted-foreground">{o.category} ({o.year})</p>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-xs text-muted-foreground">No explicit OWASP category mappings recorded.</p>
              )}
            </div>
          </div>
        </TabsContent>

        {/* ── TAB 3: RECOMMENDATION & REMEDIATION ── */}
        <TabsContent value="remediation">
          <div className="rounded-2xl border border-border/80 bg-card p-5 space-y-5 shadow-sm">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-bold text-foreground flex items-center gap-2">
                  <Code2 className="h-4 w-4 text-emerald-400" />
                  Developer Remediation Guidelines
                </h3>
                <p className="text-xs text-muted-foreground mt-1 leading-relaxed">
                  {finding.remediation}
                </p>
              </div>
              <Button
                size="sm"
                variant="outline"
                disabled={isGeneratingRemediation}
                onClick={handleGenerateRemediation}
                className="gap-1.5 text-xs border-emerald-500/30 text-emerald-400 hover:bg-emerald-500/10"
              >
                <Code2 className="h-3.5 w-3.5" />
                {isGeneratingRemediation ? "Generating..." : "Generate AI Remediation Plan"}
              </Button>
            </div>

            {/* Human-in-the-Loop Review Disclaimer */}
            <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-3.5 flex items-start gap-3 text-xs text-amber-300">
              <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" />
              <div>
                <span className="font-bold block mb-0.5">Developer Review Notice</span>
                <p className="text-[11px] opacity-90">
                  AI-generated remediation advice and code examples are advisory only. Developers must manually review, test, and verify all code changes before applying them to production environments.
                </p>
              </div>
            </div>

            {remediationData && (
              <div className="space-y-4 text-xs">
                <div className="rounded-xl bg-emerald-500/5 p-4 border border-emerald-500/20 space-y-2">
                  <span className="font-bold text-emerald-400 block text-xs">Recommended Security Fix</span>
                  <p className="text-muted-foreground">{remediationData.recommended_fix}</p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  <div className="rounded-xl bg-muted/20 p-4 border border-border/50">
                    <span className="font-bold text-foreground block mb-1">Root Cause</span>
                    <p className="text-muted-foreground">{remediationData.root_cause}</p>
                  </div>

                  <div className="rounded-xl bg-muted/20 p-4 border border-border/50">
                    <span className="font-bold text-foreground block mb-1">Affected Component</span>
                    <p className="text-muted-foreground">{remediationData.affected_component || "Application Server / Headers"}</p>
                  </div>
                </div>

                <div className="space-y-2">
                  <span className="font-bold text-foreground block text-xs">Implementation Steps</span>
                  <ul className="list-disc list-inside space-y-1 text-muted-foreground pl-1">
                    {remediationData.implementation_steps.map((step, i) => (
                      <li key={i}>{step}</li>
                    ))}
                  </ul>
                </div>

                {remediationData.secure_code_example && (
                  <div className="rounded-xl bg-black/50 p-4 border border-white/10 space-y-2 font-mono">
                    <span className="font-bold text-emerald-400 block text-xs font-sans">Secure Code Fix Example</span>
                    <pre className="overflow-x-auto text-[11px] text-emerald-300">
                      <code>{remediationData.secure_code_example}</code>
                    </pre>
                  </div>
                )}

                {remediationData.secure_configuration_example && (
                  <div className="rounded-xl bg-black/50 p-4 border border-white/10 space-y-2 font-mono">
                    <span className="font-bold text-cyan-400 block text-xs font-sans">Secure Server Configuration Example</span>
                    <pre className="overflow-x-auto text-[11px] text-cyan-300">
                      <code>{remediationData.secure_configuration_example}</code>
                    </pre>
                  </div>
                )}
              </div>
            )}

            {finding.remediationSteps && finding.remediationSteps.length > 0 && (
              <div className="space-y-4">
                <h4 className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
                  Step-by-Step Code Fix Guide
                </h4>

                {finding.remediationSteps.map((step, idx) => (
                  <div key={step.order} className="rounded-xl border border-border/60 p-4 bg-muted/20 space-y-2.5">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="flex h-6 w-6 items-center justify-center rounded-full bg-emerald-500/15 font-mono text-xs font-bold text-emerald-400">
                          {step.order}
                        </span>
                        <h5 className="text-xs font-bold text-foreground">{step.title}</h5>
                      </div>
                      {step.language && (
                        <Badge variant="outline" className="font-mono text-[10px] uppercase">
                          {step.language}
                        </Badge>
                      )}
                    </div>

                    <p className="text-xs text-muted-foreground">{step.description}</p>

                    {step.codeExample && (
                      <div className="relative overflow-hidden rounded-xl bg-[oklch(0.12_0.005_285.82)] border border-white/10 p-3.5 font-mono text-xs">
                        <button
                          type="button"
                          onClick={() => handleCopyCode(step.codeExample!, idx)}
                          className="absolute right-3 top-3 rounded bg-white/10 p-1 text-muted-foreground hover:text-white transition-colors"
                          title="Copy Code"
                        >
                          {copiedCodeIndex === idx ? (
                            <Check className="h-3.5 w-3.5 text-emerald-400" />
                          ) : (
                            <Copy className="h-3.5 w-3.5" />
                          )}
                        </button>
                        <pre className="overflow-x-auto text-emerald-300">
                          <code>{step.codeExample}</code>
                        </pre>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}

            {/* References */}
            {finding.references && finding.references.length > 0 && (
              <div className="pt-2">
                <span className="text-xs font-bold text-muted-foreground uppercase tracking-wider">
                  Developer Security References
                </span>
                <div className="mt-2 space-y-1">
                  {finding.references.map((refUrl) => (
                    <a
                      key={refUrl}
                      href={refUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center gap-1.5 text-xs text-primary hover:underline font-mono"
                    >
                      <ExternalLink className="h-3 w-3" />
                      {refUrl}
                    </a>
                  ))}
                </div>
              </div>
            )}
          </div>
        </TabsContent>

        {/* ── TAB 4: PROOF OF CONCEPT / EVIDENCE ── */}
        <TabsContent value="evidence">
          <div className="rounded-2xl border border-border/80 bg-card p-5 space-y-4 shadow-sm">
            <h3 className="text-sm font-bold text-foreground flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-amber-400" />
              Raw Request / Fuzz Payload Evidence
            </h3>

            {finding.evidence ? (
              <div className="relative overflow-hidden rounded-xl bg-[oklch(0.12_0.005_285.82)] p-4 font-mono text-xs border border-white/10">
                <pre className="overflow-x-auto text-amber-300 whitespace-pre-wrap leading-relaxed">
                  <code>{finding.evidence}</code>
                </pre>
              </div>
            ) : (
              <p className="text-xs text-muted-foreground">No raw HTTP request evidence recorded for this item.</p>
            )}
          </div>
        </TabsContent>
      </Tabs>
    </div>
  )
}
