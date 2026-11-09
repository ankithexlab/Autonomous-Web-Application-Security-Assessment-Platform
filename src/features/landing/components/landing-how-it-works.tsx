import { motion } from "framer-motion"
import { Crosshair, Play, Sparkles, FileCheck2, ArrowRight } from "lucide-react"

const steps = [
  {
    step: "01",
    title: "Define Target & Scope",
    icon: Crosshair,
    description:
      "Input target URLs, web apps, REST/GraphQL APIs, or CIDR network ranges. Set inclusion/exclusion rules and verify target ownership.",
  },
  {
    step: "02",
    title: "Autonomous Scan Execution",
    icon: Play,
    description:
      "Launch multi-module assessments (Recon, Crawler, SQLi, XSS, Headers, SSL) running concurrently with real-time log telemetry.",
  },
  {
    step: "03",
    title: "AI Analysis & CVSS Scoring",
    icon: Sparkles,
    description:
      "Sentinel AI correlates raw HTTP evidence, computes exact CVSS v3.1 vectors, and filters out false positives automatically.",
  },
  {
    step: "04",
    title: "Remediation & Executive Export",
    icon: FileCheck2,
    description:
      "Review syntax-highlighted code patches, interact with the AI assistant, and export audit-ready PDF/HTML/JSON reports.",
  },
]

export function LandingHowItWorks() {
  return (
    <section id="how-it-works" className="py-20 border-t border-border/40">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="text-center space-y-3 mb-16">
          <span className="text-xs font-bold uppercase tracking-widest text-primary">
            Simple 4-Step Workflow
          </span>
          <h2 className="text-3xl font-extrabold tracking-tight text-foreground sm:text-4xl">
            How AWASAP Delivers Continuous Security
          </h2>
          <p className="max-w-2xl mx-auto text-sm text-muted-foreground">
            From initial target discovery to automated remediation, experience a frictionless security workflow.
          </p>
        </div>

        {/* 4 Steps Timeline Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {steps.map((item, index) => {
            const Icon = item.icon
            return (
              <motion.div
                key={item.step}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.4, delay: index * 0.1 }}
                className="relative flex flex-col justify-between rounded-2xl border border-border/60 bg-card p-6 shadow-sm hover:border-primary/40 transition-colors"
              >
                <div>
                  <div className="flex items-center justify-between mb-4">
                    <span className="font-mono text-2xl font-extrabold text-primary/40">
                      {item.step}
                    </span>
                    <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-primary/10 text-primary">
                      <Icon className="h-5 w-5" />
                    </div>
                  </div>

                  <h3 className="text-base font-bold text-foreground mb-2">
                    {item.title}
                  </h3>

                  <p className="text-xs text-muted-foreground leading-relaxed">
                    {item.description}
                  </p>
                </div>

                {index < steps.length - 1 && (
                  <div className="hidden lg:block absolute -right-3 top-1/2 -translate-y-1/2 z-10 text-muted-foreground/30">
                    <ArrowRight className="h-5 w-5" />
                  </div>
                )}
              </motion.div>
            )
          })}
        </div>
      </div>
    </section>
  )
}
