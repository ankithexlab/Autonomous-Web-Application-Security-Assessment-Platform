import { motion } from "framer-motion"
import { Globe, Server, Cpu, Sparkles, FileText, Database, ShieldAlert, Activity } from "lucide-react"

const layers = [
  {
    id: "targets",
    name: "Target Scope Layer",
    color: "border-blue-500/30 bg-blue-500/5 text-blue-400",
    badgeBg: "bg-blue-500/10 text-blue-400",
    items: [
      { name: "Web Applications (SPA/SSR)", icon: Globe },
      { name: "REST & GraphQL APIs", icon: Server },
      { name: "DMZ & Internal Networks", icon: Database },
    ],
  },
  {
    id: "scanner-core",
    name: "Multi-Engine Assessment Core",
    color: "border-primary/30 bg-primary/5 text-primary",
    badgeBg: "bg-primary/10 text-primary",
    items: [
      { name: "Web Crawler & Parameter Mapper", icon: Cpu },
      { name: "SQLi, XSS & BOLA DAST Modules", icon: ShieldAlert },
      { name: "Port Scanner & SSL/TLS Analyzer", icon: Activity },
    ],
  },
  {
    id: "intelligence",
    name: "AI & Telemetry Intelligence",
    color: "border-violet-500/30 bg-violet-500/5 text-violet-400",
    badgeBg: "bg-violet-500/10 text-violet-400",
    items: [
      { name: "Sentinel AI 3.5 Neural Engine", icon: Sparkles },
      { name: "CVSS v3.1 & OWASP Mapping", icon: Cpu },
      { name: "Real-Time Terminal Log Ticker", icon: Server },
    ],
  },
  {
    id: "output",
    name: "Reporting & Operations Layer",
    color: "border-emerald-500/30 bg-emerald-500/5 text-emerald-400",
    badgeBg: "bg-emerald-500/10 text-emerald-400",
    items: [
      { name: "Executive PDF & HTML Reports", icon: FileText },
      { name: "Interactive Threat Dashboard", icon: Activity },
      { name: "Developer Code Fix Snippets", icon: Cpu },
    ],
  },
]

export function LandingArchitecture() {
  return (
    <section id="architecture" className="py-20 border-t border-border/40 bg-card/30">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="text-center space-y-3 mb-16">
          <span className="text-xs font-bold uppercase tracking-widest text-primary">
            Platform Architecture
          </span>
          <h2 className="text-3xl font-extrabold tracking-tight text-foreground sm:text-4xl">
            Decoupled Modular Architecture Overview
          </h2>
          <p className="max-w-2xl mx-auto text-sm text-muted-foreground">
            Built from the ground up for high throughput, asynchronous execution, and sub-second threat correlation.
          </p>
        </div>

        {/* Architecture Flow Diagram */}
        <div className="space-y-4 max-w-4xl mx-auto">
          {layers.map((layer, index) => (
            <motion.div
              key={layer.id}
              initial={{ opacity: 0, scale: 0.97 }}
              whileInView={{ opacity: 1, scale: 1 }}
              viewport={{ once: true }}
              transition={{ duration: 0.4, delay: index * 0.1 }}
              className={`rounded-xl border p-5 transition-all ${layer.color}`}
            >
              <div className="flex items-center justify-between mb-3">
                <span className={`rounded-full px-3 py-1 text-[11px] font-bold uppercase tracking-wider ${layer.badgeBg}`}>
                  Layer 0{index + 1} — {layer.name}
                </span>
                <span className="text-xs font-mono opacity-70">
                  Subsystem {index + 1}.0
                </span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                {layer.items.map((item) => {
                  const Icon = item.icon
                  return (
                    <div
                      key={item.name}
                      className="flex items-center gap-2.5 rounded-lg border border-border/50 bg-background/80 p-3 shadow-xs"
                    >
                      <Icon className="h-4 w-4 shrink-0" />
                      <span className="text-xs font-semibold text-foreground truncate">
                        {item.name}
                      </span>
                    </div>
                  )
                })}
              </div>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  )
}
