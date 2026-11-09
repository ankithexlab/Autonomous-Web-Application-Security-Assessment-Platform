import { useState } from "react"
import { motion } from "framer-motion"
import { Mail, MessageSquare, Send, ShieldCheck, CheckCircle2 } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { toast } from "sonner"

export function LandingContact() {
  const [submitted, setSubmitted] = useState(false)
  const [formData, setFormData] = useState({
    name: "",
    email: "",
    company: "",
    message: "",
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!formData.name || !formData.email) {
      toast.error("Please fill in required fields")
      return
    }

    setSubmitted(true)
    toast.success("Request Submitted!", {
      description: "Our security architecture team will contact you shortly.",
    })
  }

  return (
    <section id="contact" className="relative py-24 bg-background">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
          {/* Left Column: Info & CTA */}
          <div className="space-y-6">
            <span className="inline-flex items-center rounded-full bg-primary/10 px-3 py-1 text-xs font-semibold text-primary border border-primary/20">
              <Mail className="mr-1.5 h-3.5 w-3.5" />
              Get in Touch
            </span>
            <h2 className="text-3xl font-extrabold tracking-tight sm:text-4xl text-foreground">
              Ready to Secure Your Web Platform?
            </h2>
            <p className="text-muted-foreground text-base leading-relaxed">
              Schedule a personalized walkthrough with our cybersecurity engineers or request an enterprise assessment trial.
            </p>

            <div className="space-y-4 pt-4">
              <div className="flex items-start gap-3">
                <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary border border-primary/20">
                  <ShieldCheck className="h-5 w-5" />
                </div>
                <div>
                  <h4 className="text-sm font-bold text-foreground">1-on-1 Security Consultation</h4>
                  <p className="text-xs text-muted-foreground">Architectural recommendations tailored to your stack.</p>
                </div>
              </div>

              <div className="flex items-start gap-3">
                <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                  <MessageSquare className="h-5 w-5" />
                </div>
                <div>
                  <h4 className="text-sm font-bold text-foreground">Fast Response SLA</h4>
                  <p className="text-xs text-muted-foreground">Our team responds within 2 hours during business schedules.</p>
                </div>
              </div>
            </div>
          </div>

          {/* Right Column: Contact Form */}
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.4 }}
            className="rounded-2xl border border-border/60 bg-card/80 p-8 shadow-2xl backdrop-blur-xl relative"
          >
            {submitted ? (
              <div className="py-12 text-center space-y-4">
                <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
                  <CheckCircle2 className="h-8 w-8" />
                </div>
                <h3 className="text-xl font-bold text-foreground">Thank You!</h3>
                <p className="text-xs text-muted-foreground max-w-sm mx-auto">
                  We've received your request and will reach out to <span className="text-foreground font-semibold">{formData.email}</span> shortly.
                </p>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setSubmitted(false)}
                  className="mt-4 text-xs font-semibold"
                >
                  Send Another Message
                </Button>
              </div>
            ) : (
              <form onSubmit={handleSubmit} className="space-y-4">
                <h3 className="text-lg font-bold text-foreground">Request Security Demo</h3>
                <p className="text-xs text-muted-foreground">Fill in your details below to connect with an engineer.</p>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-2">
                  <div className="space-y-1.5">
                    <label className="text-xs font-semibold text-foreground">Full Name *</label>
                    <Input
                      required
                      placeholder="Jane Doe"
                      value={formData.name}
                      onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                      className="bg-background/50 text-xs h-10"
                    />
                  </div>
                  <div className="space-y-1.5">
                    <label className="text-xs font-semibold text-foreground">Work Email *</label>
                    <Input
                      required
                      type="email"
                      placeholder="jane@company.com"
                      value={formData.email}
                      onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                      className="bg-background/50 text-xs h-10"
                    />
                  </div>
                </div>

                <div className="space-y-1.5">
                  <label className="text-xs font-semibold text-foreground">Company Name</label>
                  <Input
                    placeholder="Acme Security Inc."
                    value={formData.company}
                    onChange={(e) => setFormData({ ...formData, company: e.target.value })}
                    className="bg-background/50 text-xs h-10"
                  />
                </div>

                <div className="space-y-1.5">
                  <label className="text-xs font-semibold text-foreground">Message / Assessment Details</label>
                  <textarea
                    rows={4}
                    placeholder="Tell us about your target application scope..."
                    value={formData.message}
                    onChange={(e) => setFormData({ ...formData, message: e.target.value })}
                    className="w-full rounded-md border border-input bg-background/50 p-3 text-xs text-foreground placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                  />
                </div>

                <Button type="submit" className="w-full font-bold text-xs py-5 gap-2 shadow-lg shadow-primary/20">
                  <Send className="h-3.5 w-3.5" />
                  Submit Demo Request
                </Button>
              </form>
            )}
          </motion.div>
        </div>
      </div>
    </section>
  )
}
