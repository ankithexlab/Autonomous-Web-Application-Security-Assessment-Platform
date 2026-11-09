import { motion } from "framer-motion"
import { Star, Quote, ShieldCheck } from "lucide-react"

const testimonials = [
  {
    quote: "AWASAP reduced our web vulnerability triage time by 80%. The AI explanation and copy-paste remediation code saved our engineering team weeks.",
    author: "Elena Rostova",
    role: "Head of Cybersecurity",
    company: "FinTech Global",
    avatar: "https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=150&auto=format&fit=crop&q=80",
  },
  {
    quote: "The autonomous DAST engine identified critical SQL Injection and XSS flaws before our SOC2 audit. An indispensable security tool for modern DevOps.",
    author: "Marcus Chen",
    role: "Lead DevSecOps Engineer",
    company: "CloudScale Inc",
    avatar: "https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=150&auto=format&fit=crop&q=80",
  },
  {
    quote: "Integrating AWASAP into our CI/CD workflow ensures every microservice is continuously audited for OWASP Top 10 vulnerabilities automatically.",
    author: "Sarah Jenkins",
    role: "VP of Product Engineering",
    company: "CyberShield Systems",
    avatar: "https://images.unsplash.com/photo-1573496359142-b8d87734a5a2?w=150&auto=format&fit=crop&q=80",
  },
]

export function LandingTestimonials() {
  return (
    <section id="testimonials" className="relative py-24 bg-background">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="text-center max-w-3xl mx-auto space-y-4">
          <span className="inline-flex items-center rounded-full bg-emerald-500/10 px-3 py-1 text-xs font-semibold text-emerald-400 border border-emerald-500/20">
            <ShieldCheck className="mr-1.5 h-3.5 w-3.5" />
            Trusted by Security Teams
          </span>
          <h2 className="text-3xl font-extrabold tracking-tight sm:text-4xl text-foreground">
            Empowering DevSecOps Around the Globe
          </h2>
          <p className="text-muted-foreground text-base">
            See how security leaders rely on AWASAP for autonomous web security assessment.
          </p>
        </div>

        <div className="mt-16 grid grid-cols-1 gap-8 md:grid-cols-3">
          {testimonials.map((item, i) => (
            <motion.div
              key={item.author}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.4, delay: i * 0.1 }}
              className="flex flex-col justify-between rounded-2xl border border-border/60 bg-card/60 p-8 shadow-lg backdrop-blur-xl relative"
            >
              <Quote className="absolute top-6 right-6 h-8 w-8 text-primary/10" />
              <div>
                <div className="flex items-center gap-1 text-amber-400">
                  {[...Array(5)].map((_, idx) => (
                    <Star key={idx} className="h-4 w-4 fill-amber-400" />
                  ))}
                </div>
                <p className="mt-6 text-sm text-foreground/90 leading-relaxed italic">
                  "{item.quote}"
                </p>
              </div>

              <div className="mt-8 flex items-center gap-4 pt-6 border-t border-border/40">
                <img
                  src={item.avatar}
                  alt={item.author}
                  className="h-11 w-11 rounded-full object-cover border border-primary/20"
                />
                <div>
                  <h4 className="text-sm font-bold text-foreground">{item.author}</h4>
                  <p className="text-xs text-muted-foreground">{item.role} • <span className="text-primary font-medium">{item.company}</span></p>
                </div>
              </div>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  )
}
