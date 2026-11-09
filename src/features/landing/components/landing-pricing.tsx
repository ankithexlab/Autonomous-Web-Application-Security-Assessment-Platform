import { useState } from "react"
import { motion } from "framer-motion"
import { Check, Shield, Zap, Building } from "lucide-react"
import { Button } from "@/components/ui/button"
import { useNavigate } from "react-router"
import { ROUTES } from "@/constants"

const tiers = [
  {
    name: "Community",
    id: "community",
    priceMonthly: "$0",
    priceAnnual: "$0",
    description: "Essential DAST scanning & vulnerability detection for developers.",
    icon: Shield,
    features: [
      "Up to 5 Target URLs",
      "Full OWASP Top 10 DAST Scans",
      "AI Remediation Snippets",
      "Standard PDF & HTML Reports",
      "Community Slack Support",
    ],
    cta: "Get Started Free",
    popular: false,
  },
  {
    name: "Professional",
    id: "pro",
    priceMonthly: "$79",
    priceAnnual: "$65",
    description: "Advanced autonomous security auditing for fast-growing engineering teams.",
    icon: Zap,
    features: [
      "Unlimited Target Web Apps & APIs",
      "Continuous Autonomous Scanning",
      "Interactive AI Remediation Copilot",
      "Custom Executive & Compliance Reports",
      "CI/CD Pipeline Integration (GitHub Actions)",
      "Priority 24/7 Support",
    ],
    cta: "Start 14-Day Free Trial",
    popular: true,
  },
  {
    name: "Enterprise",
    id: "enterprise",
    priceMonthly: "Custom",
    priceAnnual: "Custom",
    description: "Dedicated security orchestration for enterprise compliance & multi-cloud.",
    icon: Building,
    features: [
      "Unlimited Scans & Microservices",
      "Dedicated Air-Gapped Scanner Agents",
      "Custom OWASP & CWE Rule Engine",
      "SOC2, ISO 27001 & HIPAA Compliance Mappings",
      "Dedicated Security Architect",
      "SLA & Custom On-Premise Deployment",
    ],
    cta: "Contact Security Team",
    popular: false,
  },
]

export function LandingPricing() {
  const [annual, setAnnual] = useState(true)
  const navigate = useNavigate()

  return (
    <section id="pricing" className="relative py-24 bg-card/30 border-y border-border/40">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="text-center max-w-3xl mx-auto space-y-4">
          <span className="inline-flex items-center rounded-full bg-primary/10 px-3 py-1 text-xs font-semibold text-primary border border-primary/20">
            Flexible Security Plans
          </span>
          <h2 className="text-3xl font-extrabold tracking-tight sm:text-4xl text-foreground">
            Enterprise Security at Open Source Accessibility
          </h2>
          <p className="text-muted-foreground text-base">
            Choose the plan tailored to your team's security assessment scale.
          </p>

          {/* Billing Toggle */}
          <div className="pt-4 flex items-center justify-center gap-3">
            <span className={`text-xs font-semibold ${!annual ? "text-foreground" : "text-muted-foreground"}`}>
              Monthly Billing
            </span>
            <button
              onClick={() => setAnnual(!annual)}
              className="relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out bg-primary/20 focus:outline-none"
            >
              <span
                className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-primary shadow-lg ring-0 transition duration-200 ease-in-out ${
                  annual ? "translate-x-5" : "translate-x-0"
                }`}
              />
            </button>
            <span className={`text-xs font-semibold flex items-center gap-1.5 ${annual ? "text-foreground" : "text-muted-foreground"}`}>
              Annual Billing
              <span className="rounded-full bg-emerald-500/15 text-emerald-400 text-[10px] px-2 py-0.5 font-bold border border-emerald-500/20">
                Save 20%
              </span>
            </span>
          </div>
        </div>

        {/* Pricing Cards Grid */}
        <div className="mt-16 grid grid-cols-1 gap-8 lg:grid-cols-3">
          {tiers.map((tier, i) => {
            const Icon = tier.icon
            return (
              <motion.div
                key={tier.id}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.4, delay: i * 0.1 }}
                className={`relative flex flex-col justify-between rounded-2xl border p-8 shadow-xl backdrop-blur-xl ${
                  tier.popular
                    ? "border-primary bg-card/90 ring-1 ring-primary/50"
                    : "border-border/60 bg-card/50 hover:border-border"
                }`}
              >
                {tier.popular && (
                  <div className="absolute -top-3 left-1/2 -translate-x-1/2 rounded-full bg-primary px-3 py-1 text-[10px] font-bold uppercase tracking-wider text-primary-foreground shadow-md">
                    Most Popular
                  </div>
                )}

                <div>
                  <div className="flex items-center gap-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-primary/10 border border-primary/20 text-primary">
                      <Icon className="h-5 w-5" />
                    </div>
                    <div>
                      <h3 className="text-lg font-bold text-foreground">{tier.name}</h3>
                      <p className="text-xs text-muted-foreground">{tier.description}</p>
                    </div>
                  </div>

                  <div className="mt-6 flex items-baseline gap-1">
                    <span className="text-4xl font-black text-foreground">
                      {annual ? tier.priceAnnual : tier.priceMonthly}
                    </span>
                    {tier.priceMonthly !== "Custom" && (
                      <span className="text-xs text-muted-foreground font-medium">/ month</span>
                    )}
                  </div>

                  <ul className="mt-8 space-y-3">
                    {tier.features.map((feature) => (
                      <li key={feature} className="flex items-start gap-2.5 text-xs text-muted-foreground">
                        <Check className="h-4 w-4 shrink-0 text-primary mt-0.5" />
                        <span>{feature}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                <div className="mt-8">
                  <Button
                    variant={tier.popular ? "default" : "outline"}
                    onClick={() => navigate(ROUTES.DASHBOARD)}
                    className="w-full font-bold text-xs py-5"
                  >
                    {tier.cta}
                  </Button>
                </div>
              </motion.div>
            )
          })}
        </div>
      </div>
    </section>
  )
}
