import { useState } from "react"
import { motion, AnimatePresence } from "framer-motion"
import { ChevronDown, HelpCircle } from "lucide-react"

const faqs = [
  {
    question: "What is AWASAP and how does autonomous security scanning work?",
    answer: "AWASAP (Autonomous Web Application Security Assessment Platform) is an intelligent DAST platform. It automatically crawls web apps and APIs, executes non-destructive security vulnerability tests (OWASP Top 10, CWEs), and uses an AI Copilot to generate precise remediation code.",
  },
  {
    question: "Is AWASAP safe to run against production applications?",
    answer: "Yes! AWASAP allows configurable scan aggressiveness (Quick, Targeted, Full). You can configure rate-limiting, exclusion paths, custom headers, and safe testing vectors to avoid impacting production uptime.",
  },
  {
    question: "How does the AI Assistant generate remediation steps?",
    answer: "Our built-in AI assistant analyzes the precise HTTP evidence, target technology stack (e.g., Node.js, Python, Java, React), and CWE classification to provide tailored, copy-pasteable code fixes and step-by-step remediation guidance.",
  },
  {
    question: "What compliance standards and report formats are supported?",
    answer: "AWASAP exports Executive Summaries, Technical Deep-Dives, and Compliance reports in PDF, HTML, JSON, and CSV formats mapped directly to OWASP Top 10, CWE, and ISO/SOC2 security frameworks.",
  },
  {
    question: "Can I integrate AWASAP into my CI/CD pipeline?",
    answer: "Absolutely. AWASAP provides standard REST APIs and CLI webhooks to trigger automated vulnerability scans during continuous integration builds (GitHub Actions, GitLab CI, Jenkins).",
  },
]

export function LandingFAQ() {
  const [openIndex, setOpenIndex] = useState<number | null>(0)

  return (
    <section id="faq" className="relative py-24 bg-card/20 border-t border-border/40">
      <div className="mx-auto max-w-4xl px-4 sm:px-6 lg:px-8">
        <div className="text-center space-y-4">
          <span className="inline-flex items-center rounded-full bg-primary/10 px-3 py-1 text-xs font-semibold text-primary border border-primary/20">
            <HelpCircle className="mr-1.5 h-3.5 w-3.5" />
            Frequently Asked Questions
          </span>
          <h2 className="text-3xl font-extrabold tracking-tight sm:text-4xl text-foreground">
            Got Questions? We Have Answers.
          </h2>
          <p className="text-muted-foreground text-base">
            Everything you need to know about the platform, vulnerability scanning, and AI security.
          </p>
        </div>

        <div className="mt-12 space-y-4">
          {faqs.map((faq, index) => {
            const isOpen = openIndex === index
            return (
              <div
                key={faq.question}
                className="rounded-xl border border-border/60 bg-card/60 overflow-hidden shadow-sm transition-colors"
              >
                <button
                  onClick={() => setOpenIndex(isOpen ? null : index)}
                  className="flex w-full items-center justify-between p-5 text-left text-sm font-bold text-foreground hover:text-primary transition-colors"
                >
                  <span>{faq.question}</span>
                  <ChevronDown
                    className={`h-4 w-4 shrink-0 text-muted-foreground transition-transform duration-200 ${
                      isOpen ? "rotate-180 text-primary" : ""
                    }`}
                  />
                </button>

                <AnimatePresence initial={false}>
                  {isOpen && (
                    <motion.div
                      initial={{ height: 0, opacity: 0 }}
                      animate={{ height: "auto", opacity: 1 }}
                      exit={{ height: 0, opacity: 0 }}
                      transition={{ duration: 0.2 }}
                    >
                      <div className="px-5 pb-5 text-xs text-muted-foreground leading-relaxed border-t border-border/30 pt-3">
                        {faq.answer}
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            )
          })}
        </div>
      </div>
    </section>
  )
}
