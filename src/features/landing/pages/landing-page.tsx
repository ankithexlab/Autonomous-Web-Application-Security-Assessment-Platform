import { useState } from "react"
import { LandingNavbar } from "../components/landing-navbar"
import { LandingHero } from "../components/landing-hero"
import { LandingFeatures } from "../components/landing-features"
import { LandingHowItWorks } from "../components/landing-how-it-works"
import { LandingArchitecture } from "../components/landing-architecture"
import { LandingTechStack } from "../components/landing-tech-stack"
import { LandingPricing } from "../components/landing-pricing"
import { LandingTestimonials } from "../components/landing-testimonials"
import { LandingFAQ } from "../components/landing-faq"
import { LandingContact } from "../components/landing-contact"
import { LandingFooter } from "../components/landing-footer"
import { LandingDocsModal } from "../components/landing-docs-modal"

export function LandingPage() {
  const [docsModalOpen, setDocsModalOpen] = useState(false)

  return (
    <div className="min-h-screen bg-background text-foreground selection:bg-primary selection:text-primary-foreground">
      {/* Sticky Navigation Bar */}
      <LandingNavbar onOpenDocs={() => setDocsModalOpen(true)} />

      {/* Main Landing Sections */}
      <main>
        <LandingHero onOpenDocs={() => setDocsModalOpen(true)} />
        <LandingFeatures />
        <LandingHowItWorks />
        <LandingArchitecture />
        <LandingTechStack />
        <LandingPricing />
        <LandingTestimonials />
        <LandingFAQ />
        <LandingContact />
      </main>

      {/* Footer */}
      <LandingFooter onOpenDocs={() => setDocsModalOpen(true)} />

      {/* Documentation Modal */}
      <LandingDocsModal
        open={docsModalOpen}
        onClose={() => setDocsModalOpen(false)}
      />
    </div>
  )
}
