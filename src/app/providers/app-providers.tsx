import type { ReactNode } from "react"
import { ThemeProvider } from "./theme-provider"
import { QueryProvider } from "./query-provider"
import { TooltipProvider } from "@/components/ui/tooltip"
import { Toaster } from "sonner"

export function AppProviders({ children }: { children: ReactNode }) {
  return (
    <ThemeProvider>
      <QueryProvider>
        <TooltipProvider delayDuration={300}>
          {children}
          <Toaster
            position="bottom-right"
            toastOptions={{
              className: "bg-card text-card-foreground border-border",
            }}
          />
        </TooltipProvider>
      </QueryProvider>
    </ThemeProvider>
  )
}
