import { motion } from "framer-motion"
import { Badge } from "@/components/ui/badge"
import { ShieldCheck, Code } from "lucide-react"

const techCategories = [
  {
    title: "Frontend & UI Architecture",
    icon: Code,
    description: "Modern, type-safe, ultra-fast client interface built with modern web technologies.",
    techs: [
      { name: "React 19", version: "v19.2", desc: "Core UI Framework" },
      { name: "TypeScript", version: "v6.0", desc: "Strict Type Safety" },
      { name: "Vite 8", version: "v8.1", desc: "Sub-Second HMR & Bundling" },
      { name: "Tailwind CSS v4", version: "v4.3", desc: "Dark-First Theme System" },
      { name: "Framer Motion", version: "v12.4", desc: "Smooth Micro-Animations" },
      { name: "Recharts", version: "v3.10", desc: "Data Visualization Engine" },
      { name: "Radix UI Primitives", version: "v1.6", desc: "Accessible UI Components" },
    ],
  },
  {
    title: "Security Standards & Compliance",
    icon: ShieldCheck,
    description: "Built strictly according to global cybersecurity frameworks and standards.",
    techs: [
      { name: "OWASP Top 10", version: "2021", desc: "Web Risk Standard" },
      { name: "OWASP API Top 10", version: "2023", desc: "API Security Standard" },
      { name: "CVSS Vector Calculator", version: "v3.1", desc: "Common Vulnerability Scoring" },
      { name: "CWE Dictionary", version: "2026", desc: "Common Weakness Enumeration" },
      { name: "SOC 2 Type II", version: "Audit", desc: "Trust Services Criteria" },
      { name: "PCI-DSS Standard", version: "v4.0", desc: "Payment Card Industry Data Security" },
    ],
  },
]

export function LandingTechStack() {
  return (
    <section id="tech-stack" className="py-20 border-t border-border/40">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="text-center space-y-3 mb-16">
          <span className="text-xs font-bold uppercase tracking-widest text-primary">
            Technology Stack & Standards
          </span>
          <h2 className="text-3xl font-extrabold tracking-tight text-foreground sm:text-4xl">
            Built with Modern, Battle-Tested Technologies
          </h2>
          <p className="max-w-2xl mx-auto text-sm text-muted-foreground">
            Leveraging state-of-the-art web frameworks and industry-standard security specifications.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
          {techCategories.map((category, index) => {
            const Icon = category.icon
            return (
              <motion.div
                key={category.title}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.4, delay: index * 0.1 }}
                className="rounded-2xl border border-border/60 bg-card p-6 flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-center gap-3 mb-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-primary/10 text-primary">
                      <Icon className="h-5 w-5" />
                    </div>
                    <div>
                      <h3 className="text-lg font-bold text-foreground">
                        {category.title}
                      </h3>
                      <p className="text-xs text-muted-foreground">
                        {category.description}
                      </p>
                    </div>
                  </div>

                  <div className="mt-5 grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                    {category.techs.map((tech) => (
                      <div
                        key={tech.name}
                        className="flex items-center justify-between rounded-lg border border-border/50 bg-background/60 p-2.5"
                      >
                        <div>
                          <span className="text-xs font-semibold text-foreground block">
                            {tech.name}
                          </span>
                          <span className="text-[10px] text-muted-foreground block">
                            {tech.desc}
                          </span>
                        </div>
                        <Badge variant="outline" className="text-[10px] font-mono shrink-0">
                          {tech.version}
                        </Badge>
                      </div>
                    ))}
                  </div>
                </div>
              </motion.div>
            )
          })}
        </div>
      </div>
    </section>
  )
}
