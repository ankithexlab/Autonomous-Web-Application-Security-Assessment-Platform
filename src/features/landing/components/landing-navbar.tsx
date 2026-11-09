import { useState } from "react"
import { Link, useNavigate } from "react-router"
import { Logo } from "@/components/common/logo"
import { Button } from "@/components/ui/button"
import { ROUTES } from "@/constants"
import { Shield, ExternalLink, Menu, X } from "lucide-react"

interface LandingNavbarProps {
  onOpenDocs: () => void
}

export function LandingNavbar({ onOpenDocs }: LandingNavbarProps) {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)
  const navigate = useNavigate()

  function scrollToSection(id: string) {
    setMobileMenuOpen(false)
    const element = document.getElementById(id)
    if (element) {
      element.scrollIntoView({ behavior: "smooth" })
    }
  }

  return (
    <header className="sticky top-0 z-50 w-full border-b border-border/40 bg-background/80 backdrop-blur-xl">
      <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-4 sm:px-6 lg:px-8">
        {/* Logo */}
        <Link to={ROUTES.HOME} className="flex items-center group">
          <Logo className="transition-transform group-hover:scale-105" />
        </Link>

        {/* Desktop Nav Links */}
        <nav className="hidden md:flex items-center gap-6 text-sm font-medium text-muted-foreground">
          <button
            onClick={() => scrollToSection("features")}
            className="transition-colors hover:text-foreground cursor-pointer"
          >
            Features
          </button>
          <button
            onClick={() => scrollToSection("how-it-works")}
            className="transition-colors hover:text-foreground cursor-pointer"
          >
            How It Works
          </button>

          <button
            onClick={() => scrollToSection("pricing")}
            className="transition-colors hover:text-foreground cursor-pointer"
          >
            Pricing
          </button>
          <button
            onClick={() => scrollToSection("testimonials")}
            className="transition-colors hover:text-foreground cursor-pointer"
          >
            Testimonials
          </button>
          <button
            onClick={() => scrollToSection("faq")}
            className="transition-colors hover:text-foreground cursor-pointer"
          >
            FAQ
          </button>
          <button
            onClick={() => scrollToSection("contact")}
            className="transition-colors hover:text-foreground cursor-pointer"
          >
            Contact
          </button>
          <button
            onClick={onOpenDocs}
            className="flex items-center gap-1 transition-colors hover:text-foreground cursor-pointer"
          >
            <span>Docs</span>
            <ExternalLink className="h-3 w-3 opacity-70" />
          </button>
        </nav>

        {/* Desktop CTA Buttons */}
        <div className="hidden md:flex items-center gap-3">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => navigate(ROUTES.AUTH.LOGIN)}
            className="text-xs font-semibold"
          >
            Sign In
          </Button>
          <Button
            size="sm"
            onClick={() => navigate(ROUTES.DASHBOARD)}
            className="gap-2 text-xs font-semibold shadow-lg shadow-primary/20"
          >
            <Shield className="h-3.5 w-3.5" />
            Start Free Assessment
          </Button>
        </div>

        {/* Mobile menu trigger */}
        <button
          onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
          className="md:hidden rounded-lg p-2 text-muted-foreground hover:bg-muted"
        >
          {mobileMenuOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
        </button>
      </div>

      {/* Mobile Dropdown */}
      {mobileMenuOpen && (
        <div className="md:hidden border-b border-border bg-background/95 px-4 pt-2 pb-4 space-y-3">
          <button
            onClick={() => scrollToSection("features")}
            className="block w-full text-left py-2 text-sm font-medium text-muted-foreground hover:text-foreground"
          >
            Features
          </button>
          <button
            onClick={() => scrollToSection("how-it-works")}
            className="block w-full text-left py-2 text-sm font-medium text-muted-foreground hover:text-foreground"
          >
            How It Works
          </button>

          <button
            onClick={() => scrollToSection("pricing")}
            className="block w-full text-left py-2 text-sm font-medium text-muted-foreground hover:text-foreground"
          >
            Pricing
          </button>
          <button
            onClick={() => scrollToSection("testimonials")}
            className="block w-full text-left py-2 text-sm font-medium text-muted-foreground hover:text-foreground"
          >
            Testimonials
          </button>
          <button
            onClick={() => scrollToSection("faq")}
            className="block w-full text-left py-2 text-sm font-medium text-muted-foreground hover:text-foreground"
          >
            FAQ
          </button>
          <button
            onClick={() => scrollToSection("contact")}
            className="block w-full text-left py-2 text-sm font-medium text-muted-foreground hover:text-foreground"
          >
            Contact
          </button>
          <button
            onClick={() => {
              setMobileMenuOpen(false)
              onOpenDocs()
            }}
            className="block w-full text-left py-2 text-sm font-medium text-muted-foreground hover:text-foreground"
          >
            Documentation
          </button>
          <div className="pt-2 flex flex-col gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => navigate(ROUTES.AUTH.LOGIN)}
              className="w-full"
            >
              Sign In
            </Button>
            <Button
              size="sm"
              onClick={() => navigate(ROUTES.DASHBOARD)}
              className="w-full gap-2"
            >
              <Shield className="h-3.5 w-3.5" />
              Start Free Assessment
            </Button>
          </div>
        </div>
      )}
    </header>
  )
}
