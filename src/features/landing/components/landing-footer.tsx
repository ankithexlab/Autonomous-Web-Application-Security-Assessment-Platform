import { Logo } from "@/components/common/logo"
import { Shield, Globe, Share2, ExternalLink } from "lucide-react"

interface LandingFooterProps {
  onOpenDocs: () => void
}

export function LandingFooter({ onOpenDocs }: LandingFooterProps) {
  function scrollTo(id: string) {
    const el = document.getElementById(id)
    if (el) el.scrollIntoView({ behavior: "smooth" })
  }

  return (
    <footer className="border-t border-border/40 bg-card/50 pt-16 pb-12">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 space-y-12">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
          {/* Col 1: Brand */}
          <div className="space-y-4 md:col-span-1">
            <div className="flex items-center">
              <Logo />
            </div>
            <p className="text-xs text-muted-foreground leading-relaxed">
              Autonomous Web Application Security Assessment Platform. Empowering teams with automated vulnerability discovery & AI threat intelligence.
            </p>
            <div className="flex items-center gap-3 text-muted-foreground">
              <a href="#" className="hover:text-foreground transition-colors" title="Global Coverage">
                <Globe className="h-4 w-4" />
              </a>
              <a href="#" className="hover:text-foreground transition-colors" title="Share">
                <Share2 className="h-4 w-4" />
              </a>
              <button onClick={onOpenDocs} className="hover:text-foreground transition-colors" title="Documentation">
                <ExternalLink className="h-4 w-4" />
              </button>
            </div>
          </div>

          {/* Col 2: Capabilities */}
          <div className="space-y-3">
            <h4 className="text-xs font-bold uppercase tracking-wider text-foreground">
              Platform
            </h4>
            <ul className="space-y-2 text-xs text-muted-foreground">
              <li>
                <button onClick={() => scrollTo("features")} className="hover:text-foreground transition-colors">
                  AI Risk Analysis
                </button>
              </li>
              <li>
                <button onClick={() => scrollTo("features")} className="hover:text-foreground transition-colors">
                  Vulnerability Assessment
                </button>
              </li>
              <li>
                <button onClick={() => scrollTo("features")} className="hover:text-foreground transition-colors">
                  Risk Prioritization
                </button>
              </li>
              <li>
                <button onClick={() => scrollTo("features")} className="hover:text-foreground transition-colors">
                  Executive Reports
                </button>
              </li>
            </ul>
          </div>

          {/* Col 3: Architecture & Docs */}
          <div className="space-y-3">
            <h4 className="text-xs font-bold uppercase tracking-wider text-foreground">
              Resources
            </h4>
            <ul className="space-y-2 text-xs text-muted-foreground">
              <li>
                <button onClick={() => scrollTo("how-it-works")} className="hover:text-foreground transition-colors">
                  How It Works
                </button>
              </li>
              <li>
                <button onClick={() => scrollTo("architecture")} className="hover:text-foreground transition-colors">
                  Architecture Overview
                </button>
              </li>
              <li>
                <button onClick={() => scrollTo("tech-stack")} className="hover:text-foreground transition-colors">
                  Technology Stack
                </button>
              </li>
              <li>
                <button onClick={onOpenDocs} className="hover:text-foreground transition-colors">
                  Documentation
                </button>
              </li>
            </ul>
          </div>

          {/* Col 4: Standards */}
          <div className="space-y-3">
            <h4 className="text-xs font-bold uppercase tracking-wider text-foreground">
              Standards & Security
            </h4>
            <ul className="space-y-2 text-xs text-muted-foreground">
              <li>OWASP Top 10 (2021)</li>
              <li>OWASP API Security Top 10</li>
              <li>CVSS v3.1 Scoring Engine</li>
              <li>SOC 2 & PCI-DSS Compliance</li>
            </ul>
          </div>
        </div>

        <div className="pt-8 border-t border-border/40 flex flex-col sm:flex-row items-center justify-between gap-4 text-xs text-muted-foreground">
          <div className="flex items-center gap-2">
            <Shield className="h-4 w-4 text-primary" />
            <span>© 2026 AWASAP Platform. All rights reserved.</span>
          </div>
          <div className="flex gap-4">
            <a href="#" className="hover:text-foreground transition-colors">Privacy Policy</a>
            <a href="#" className="hover:text-foreground transition-colors">Terms of Service</a>
            <a href="#" className="hover:text-foreground transition-colors">Security Disclosure</a>
          </div>
        </div>
      </div>
    </footer>
  )
}
