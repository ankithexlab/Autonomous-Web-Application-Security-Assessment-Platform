import { motion } from "framer-motion"
import { useNavigate } from "react-router"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { ROUTES } from "@/constants"
import {
  Shield,
  FileText,
  Sparkles,
  CheckCircle2,
  AlertTriangle,
  ArrowRight,
  Activity,
  Lock,
} from "lucide-react"

interface LandingHeroProps {
  onOpenDocs: () => void
}

export function LandingHero({ onOpenDocs }: LandingHeroProps) {
  const navigate = useNavigate()

  return (
    <section className="relative overflow-hidden pt-12 pb-20 md:pt-20 md:pb-28">
      {/* Background glow graphics */}
      <div className="pointer-events-none absolute left-1/2 top-0 -z-10 h-[500px] w-[800px] -translate-x-1/2 rounded-full bg-gradient-to-b from-primary/20 via-primary/5 to-transparent blur-3xl" />
      <div className="pointer-events-none absolute right-0 top-1/3 -z-10 h-72 w-72 rounded-full bg-emerald-500/10 blur-3xl" />

      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="flex flex-col items-center text-center space-y-6">
          {/* Release Badge */}
          <motion.div
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4 }}
          >
            <Badge
              variant="outline"
              className="gap-2 rounded-full border-primary/30 bg-primary/10 px-4 py-1.5 text-xs text-primary backdrop-blur-md hover:bg-primary/15 transition-colors cursor-pointer"
              onClick={() => navigate(ROUTES.DASHBOARD)}
            >
              <Sparkles className="h-3.5 w-3.5" />
              <span>Sentinel AI 3.5 Security Engine Active</span>
              <span className="h-1.5 w-1.5 rounded-full bg-primary animate-pulse" />
            </Badge>
          </motion.div>

          {/* Main Title */}
          <motion.h1
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.1 }}
            className="max-w-4xl text-4xl font-extrabold tracking-tight text-foreground sm:text-5xl md:text-6xl leading-[1.15]"
          >
            Autonomous Web Application Security Assessment Platform{" "}
            <span className="bg-gradient-to-r from-primary via-blue-400 to-emerald-400 bg-clip-text text-transparent">
              (AWASAP)
            </span>
          </motion.h1>

          {/* Tagline */}
          <motion.p
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.2 }}
            className="max-w-2xl text-base text-muted-foreground sm:text-lg md:text-xl leading-relaxed"
          >
            Proactively discover, analyze, and remediate web & API vulnerabilities with automated DAST/SAST engines, real-time threat telemetry, and AI-driven security posture reports.
          </motion.p>

          {/* CTA Buttons */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.3 }}
            className="flex flex-col sm:flex-row items-center justify-center gap-4 pt-2 w-full sm:w-auto"
          >
            <Button
              size="lg"
              onClick={() => navigate(ROUTES.DASHBOARD)}
              className="w-full sm:w-auto gap-2.5 px-8 text-sm font-bold shadow-xl shadow-primary/25 hover:shadow-primary/40 transition-all"
            >
              <Shield className="h-4 w-4" />
              Start Free Assessment
              <ArrowRight className="h-4 w-4 ml-1" />
            </Button>

            <Button
              size="lg"
              variant="outline"
              onClick={onOpenDocs}
              className="w-full sm:w-auto gap-2.5 px-7 text-sm font-semibold border-border/80 hover:bg-muted/40"
            >
              <FileText className="h-4 w-4 text-muted-foreground" />
              View Documentation
            </Button>
          </motion.div>

          {/* Quick Metrics Pills */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.6, delay: 0.4 }}
            className="flex flex-wrap items-center justify-center gap-6 pt-4 text-xs text-muted-foreground"
          >
            <div className="flex items-center gap-1.5">
              <CheckCircle2 className="h-4 w-4 text-emerald-400" />
              <span>OWASP Top 10 Coverage</span>
            </div>
            <div className="flex items-center gap-1.5">
              <CheckCircle2 className="h-4 w-4 text-emerald-400" />
              <span>Zero Backend Integration Required</span>
            </div>
            <div className="flex items-center gap-1.5">
              <CheckCircle2 className="h-4 w-4 text-emerald-400" />
              <span>Instant Executive PDF Reports</span>
            </div>
          </motion.div>
        </div>

        {/* Hero Interactive App Mockup Preview */}
        <motion.div
          initial={{ opacity: 0, y: 40 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.7, delay: 0.5 }}
          className="mt-14 overflow-hidden rounded-2xl border border-border/60 bg-card/90 shadow-2xl shadow-black/50 backdrop-blur-xl"
        >
          {/* Top Mockup Window Header */}
          <div className="flex items-center justify-between border-b border-border/60 bg-muted/40 px-4 py-3">
            <div className="flex items-center gap-2">
              <div className="h-3 w-3 rounded-full bg-red-500/80" />
              <div className="h-3 w-3 rounded-full bg-amber-500/80" />
              <div className="h-3 w-3 rounded-full bg-emerald-500/80" />
              <span className="ml-2 font-mono text-xs text-muted-foreground">
                https://app.acmecorp.com — AWASAP Live Telemetry
              </span>
            </div>
            <div className="flex items-center gap-2">
              <Badge variant="outline" className="text-[10px] gap-1 text-emerald-400 bg-emerald-500/10 border-emerald-500/30">
                <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
                Live Assessment
              </Badge>
            </div>
          </div>

          {/* Inner Preview Content */}
          <div className="p-6 grid grid-cols-1 lg:grid-cols-3 gap-5">
            {/* Column 1: Live Status */}
            <div className="rounded-xl border border-border/50 bg-background/60 p-4 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                  Security Score
                </span>
                <Badge className="bg-emerald-500/20 text-emerald-400 border-emerald-500/30">
                  Grade A-
                </Badge>
              </div>
              <div className="flex items-baseline gap-2">
                <span className="text-3xl font-bold text-foreground">94</span>
                <span className="text-xs text-muted-foreground">/ 100</span>
              </div>
              <div className="h-2 w-full overflow-hidden rounded-full bg-muted">
                <div className="h-full w-[94%] bg-gradient-to-r from-emerald-500 to-teal-400 rounded-full" />
              </div>
              <div className="pt-2 flex items-center justify-between text-xs text-muted-foreground">
                <span>Targets Analyzed: 7</span>
                <span className="text-emerald-400 font-semibold">+4.2% this week</span>
              </div>
            </div>

            {/* Column 2: Active Modules */}
            <div className="rounded-xl border border-border/50 bg-background/60 p-4 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                  Active Multi-Engine Scanner
                </span>
                <Activity className="h-4 w-4 text-blue-400" />
              </div>
              <div className="space-y-2">
                {[
                  { name: "Reconnaissance & Web Crawler", progress: 100, status: "Done" },
                  { name: "SQL Injection & XSS Engine", progress: 78, status: "78%" },
                  { name: "Sentinel AI Risk Analyzer", progress: 45, status: "45%" },
                ].map((m) => (
                  <div key={m.name} className="space-y-1">
                    <div className="flex items-center justify-between text-[11px]">
                      <span className="font-medium text-foreground">{m.name}</span>
                      <span className="text-primary font-mono">{m.status}</span>
                    </div>
                    <div className="h-1.5 w-full rounded-full bg-muted overflow-hidden">
                      <div
                        className="h-full bg-primary rounded-full"
                        style={{ width: `${m.progress}%` }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Column 3: Real-Time Alerts */}
            <div className="rounded-xl border border-border/50 bg-background/60 p-4 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                  Real-Time Findings
                </span>
                <Badge variant="destructive" className="text-[10px]">
                  1 Critical
                </Badge>
              </div>

              <div className="space-y-2">
                <div className="flex items-start gap-2.5 rounded-lg border border-red-500/20 bg-red-500/10 p-2.5 text-xs">
                  <AlertTriangle className="h-4 w-4 text-red-400 shrink-0 mt-0.5" />
                  <div>
                    <span className="font-semibold text-red-400 block">SQL Injection Detected</span>
                    <span className="text-[10px] text-muted-foreground font-mono">POST /api/v2/users/search</span>
                  </div>
                </div>
                <div className="flex items-start gap-2.5 rounded-lg border border-amber-500/20 bg-amber-500/10 p-2.5 text-xs">
                  <Lock className="h-4 w-4 text-amber-400 shrink-0 mt-0.5" />
                  <div>
                    <span className="font-semibold text-amber-400 block">Missing CSP Header</span>
                    <span className="text-[10px] text-muted-foreground font-mono">https://app.acmecorp.com</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </motion.div>
      </div>
    </section>
  )
}
