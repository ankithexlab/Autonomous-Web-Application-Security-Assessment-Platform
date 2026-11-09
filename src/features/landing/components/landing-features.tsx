import { motion } from "framer-motion"
import {
  Sparkles,
  ShieldCheck,
  BarChart3,
  FileText,
  CheckCircle2,
} from "lucide-react"

const features = [
  {
    id: "ai-analysis",
    title: "AI Analysis & Remediation",
    category: "Neural Intelligence",
    icon: Sparkles,
    color: "text-violet-400",
    bg: "bg-violet-500/10 border-violet-500/20",
    description:
      "Sentinel AI correlates raw vulnerability evidence, generates neural threat explanations, and provides syntax-highlighted code patches tailored to your stack.",
    highlights: [
      "Natural language threat summaries",
      "Tailored Express/Nginx patch snippets",
      "Interactive AI Security Assistant",
    ],
  },
  {
    id: "vulnerability-assessment",
    title: "Vulnerability Assessment",
    category: "Multi-Engine Assessment",
    icon: ShieldCheck,
    color: "text-blue-400",
    bg: "bg-blue-500/10 border-blue-500/20",
    description:
      "Comprehensive DAST and SAST scanning across web applications, REST/GraphQL APIs, and network boundaries targeting OWASP Top 10 risks.",
    highlights: [
      "OWASP Top 10 & API Security Top 10",
      "SQLi, XSS, BOLA & CSRF detection",
      "Deep web crawler & endpoint mapper",
    ],
  },
  {
    id: "risk-prioritization",
    title: "Risk Prioritization & Scoring",
    category: "CVSS v3.1 Telemetry",
    icon: BarChart3,
    color: "text-amber-400",
    bg: "bg-amber-500/10 border-amber-500/20",
    description:
      "Prioritize what matters most. Automated CVSS v3.1 vector calculations, attack vector analysis, and business impact assessment eliminate false positives.",
    highlights: [
      "Full CVSS v3.1 vector breakdown",
      "Attack complexity & scope rating",
      "Contextual business impact score",
    ],
  },
  {
    id: "executive-reports",
    title: "Compliance & Executive Reports",
    category: "Audit Readiness",
    icon: FileText,
    color: "text-emerald-400",
    bg: "bg-emerald-500/10 border-emerald-500/20",
    description:
      "One-click audit reports mapped directly to SOC 2, PCI-DSS 4.0, and ISO 27001 standards. Export instantly to PDF, HTML, JSON, or CSV.",
    highlights: [
      "Letter grade security posture ratings",
      "Interactive Recharts trend diagrams",
      "Export in PDF, HTML, JSON, & CSV",
    ],
  },
]

export function LandingFeatures() {
  return (
    <section id="features" className="py-20 border-t border-border/40 bg-card/30">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="text-center space-y-3 mb-16">
          <span className="text-xs font-bold uppercase tracking-widest text-primary">
            Platform Capabilities
          </span>
          <h2 className="text-3xl font-extrabold tracking-tight text-foreground sm:text-4xl">
            Enterprise Security Infrastructure Powered by AI
          </h2>
          <p className="max-w-2xl mx-auto text-sm text-muted-foreground">
            AWASAP combines automated multi-engine scanning with neural threat intelligence to deliver continuous, end-to-end vulnerability coverage.
          </p>
        </div>

        {/* Feature Cards 2x2 Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
          {features.map((feature, index) => {
            const Icon = feature.icon
            return (
              <motion.div
                key={feature.id}
                initial={{ opacity: 0, y: 24 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.4, delay: index * 0.1 }}
                className="group relative flex flex-col justify-between rounded-2xl border border-border/60 bg-card p-7 transition-all hover:border-primary/40 hover:shadow-xl hover:shadow-primary/5"
              >
                <div>
                  <div className="flex items-center justify-between mb-5">
                    <div
                      className={`flex h-12 w-12 items-center justify-center rounded-xl border ${feature.bg}`}
                    >
                      <Icon className={`h-6 w-6 ${feature.color}`} />
                    </div>
                    <span className="rounded-full bg-muted/60 px-3 py-1 text-[11px] font-semibold text-muted-foreground">
                      {feature.category}
                    </span>
                  </div>

                  <h3 className="text-xl font-bold text-foreground group-hover:text-primary transition-colors">
                    {feature.title}
                  </h3>

                  <p className="mt-3 text-sm text-muted-foreground leading-relaxed">
                    {feature.description}
                  </p>
                </div>

                <div className="mt-6 pt-5 border-t border-border/40 space-y-2">
                  {feature.highlights.map((item) => (
                    <div key={item} className="flex items-center gap-2.5 text-xs text-foreground/90 font-medium">
                      <CheckCircle2 className="h-4 w-4 text-primary shrink-0" />
                      <span>{item}</span>
                    </div>
                  ))}
                </div>
              </motion.div>
            )
          })}
        </div>
      </div>
    </section>
  )
}
