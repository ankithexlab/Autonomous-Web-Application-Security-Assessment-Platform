import { useState } from "react"
import { Moon, Sun, Monitor, Palette, Sparkles, Check } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { toast } from "sonner"
import { cn } from "@/utils"
import { useTheme } from "@/app/providers/theme-provider"

export function ThemeSettingsTab() {
  const { theme, setTheme } = useTheme()
  const [themeMode, setThemeMode] = useState<"dark" | "light" | "system">(theme)
  const [accentColor, setAccentColor] = useState("emerald")
  const [compactMode, setCompactMode] = useState(false)
  const [reducedMotion, setReducedMotion] = useState(false)

  function handleSelectTheme(mode: "dark" | "light" | "system") {
    setThemeMode(mode)
    if (mode === "system") {
      const isDark = window.matchMedia("(prefers-color-scheme: dark)").matches
      setTheme(isDark ? "dark" : "light")
    } else {
      setTheme(mode)
    }
    toast.success(`Theme mode set to ${mode.toUpperCase()}`)
  }


  function handleSelectAccent(color: string) {
    setAccentColor(color)
    toast.success(`Accent color scheme updated`)
  }

  const themes = [
    {
      id: "dark" as const,
      title: "Cyber Dark (Default)",
      desc: "High-contrast dark mode tailored for security operations centers",
      icon: Moon,
      color: "bg-[oklch(0.14_0.005_285.82)] text-white border-primary/40",
    },
    {
      id: "light" as const,
      title: "Clean Light",
      desc: "Bright, high-legibility light theme for daytime auditing",
      icon: Sun,
      color: "bg-white text-slate-900 border-slate-300",
    },
    {
      id: "system" as const,
      title: "System Preference",
      desc: "Automatically sync theme with your operating system settings",
      icon: Monitor,
      color: "bg-card text-foreground border-border",
    },
  ]

  const accents = [
    { id: "emerald", name: "Cyber Green", hex: "#10b981", class: "bg-emerald-500" },
    { id: "blue", name: "Electric Blue", hex: "#3b82f6", class: "bg-blue-500" },
    { id: "indigo", name: "Deep Indigo", hex: "#6366f1", class: "bg-indigo-500" },
    { id: "violet", name: "Neon Violet", hex: "#8b5cf6", class: "bg-violet-500" },
    { id: "amber", name: "Warning Amber", hex: "#f59e0b", class: "bg-amber-500" },
  ]

  return (
    <div className="space-y-6">
      {/* Theme Mode Selection Grid */}
      <div className="rounded-2xl border border-border/80 bg-card p-6 space-y-4 shadow-sm">
        <div>
          <h3 className="text-sm font-bold text-foreground flex items-center gap-2">
            <Sparkles className="h-4 w-4 text-primary" />
            Appearance Mode
          </h3>
          <p className="text-xs text-muted-foreground mt-0.5">
            Select your preferred visual layout theme for the security console
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {themes.map((item) => {
            const Icon = item.icon
            const isSelected = themeMode === item.id

            return (
              <div
                key={item.id}
                onClick={() => handleSelectTheme(item.id)}
                className={cn(
                  "cursor-pointer rounded-2xl border p-4 transition-all shadow-xs flex flex-col justify-between space-y-3",
                  isSelected
                    ? "border-primary bg-primary/[0.04] ring-1 ring-primary/40"
                    : "border-border/80 bg-card hover:border-primary/40",
                )}
              >
                <div className="flex items-center justify-between">
                  <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-primary/10 text-primary">
                    <Icon className="h-4.5 w-4.5" />
                  </div>
                  {isSelected && (
                    <Badge variant="default" className="text-[10px] font-mono gap-1">
                      <Check className="h-3 w-3" /> Active
                    </Badge>
                  )}
                </div>

                <div>
                  <h4 className="text-xs font-bold text-foreground">{item.title}</h4>
                  <p className="text-[11px] text-muted-foreground mt-1 leading-tight">
                    {item.desc}
                  </p>
                </div>
              </div>
            )
          })}
        </div>
      </div>

      {/* Accent Color Scheme */}
      <div className="rounded-2xl border border-border/80 bg-card p-6 space-y-4 shadow-sm">
        <div>
          <h3 className="text-sm font-bold text-foreground flex items-center gap-2">
            <Palette className="h-4 w-4 text-primary" />
            Accent Palette
          </h3>
          <p className="text-xs text-muted-foreground mt-0.5">
            Customize primary highlight colors for badges, gauges, and interactive buttons
          </p>
        </div>

        <div className="flex items-center gap-3 flex-wrap">
          {accents.map((acc) => {
            const isSelected = accentColor === acc.id
            return (
              <button
                key={acc.id}
                type="button"
                onClick={() => handleSelectAccent(acc.id)}
                className={cn(
                  "flex items-center gap-2 rounded-xl border px-3 py-2 text-xs font-bold transition-all",
                  isSelected
                    ? "border-primary bg-primary/10 text-foreground ring-1 ring-primary/40"
                    : "border-border bg-card text-muted-foreground hover:text-foreground",
                )}
              >
                <span className={cn("h-3.5 w-3.5 rounded-full", acc.class)} />
                <span>{acc.name}</span>
                {isSelected && <Check className="h-3.5 w-3.5 text-primary ml-1" />}
              </button>
            )
          })}
        </div>
      </div>

      {/* Accessibility & Interface Toggles */}
      <div className="rounded-2xl border border-border/80 bg-card p-6 space-y-4 shadow-sm">
        <h3 className="text-sm font-bold text-foreground">Interface & Density Preferences</h3>

        <div className="divide-y divide-border/40">
          <div className="flex items-center justify-between py-3">
            <div>
              <p className="text-xs font-bold text-foreground">Compact Density Layout</p>
              <p className="text-[11px] text-muted-foreground">Reduce table padding to fit more findings per screen</p>
            </div>
            <input
              type="checkbox"
              checked={compactMode}
              onChange={(e) => {
                setCompactMode(e.target.checked)
                toast.success(`Compact mode ${e.target.checked ? "enabled" : "disabled"}`)
              }}
              className="h-4 w-4 rounded border-border text-primary focus:ring-primary/40"
            />
          </div>

          <div className="flex items-center justify-between py-3">
            <div>
              <p className="text-xs font-bold text-foreground">Reduced Animation & Motion</p>
              <p className="text-[11px] text-muted-foreground">Minimize Framer Motion transitions for sensitive displays</p>
            </div>
            <input
              type="checkbox"
              checked={reducedMotion}
              onChange={(e) => {
                setReducedMotion(e.target.checked)
                toast.success(`Reduced motion ${e.target.checked ? "enabled" : "disabled"}`)
              }}
              className="h-4 w-4 rounded border-border text-primary focus:ring-primary/40"
            />
          </div>
        </div>
      </div>
    </div>
  )
}
