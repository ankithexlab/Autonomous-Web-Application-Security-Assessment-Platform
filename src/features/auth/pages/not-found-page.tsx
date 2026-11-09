import { Link } from "react-router"
import { ShieldOff } from "lucide-react"
import { Button } from "@/components/ui/button"
import { ROUTES } from "@/constants"

export function NotFoundPage() {
  return (
    <div className="flex min-h-screen flex-col items-center justify-center gap-6 bg-background text-center">
      <div className="flex h-20 w-20 items-center justify-center rounded-full bg-muted">
        <ShieldOff className="h-10 w-10 text-muted-foreground" />
      </div>
      <div className="space-y-2">
        <h1 className="text-4xl font-bold text-foreground">404</h1>
        <p className="text-lg text-muted-foreground">
          Page not found. This route doesn&apos;t exist.
        </p>
      </div>
      <Button asChild>
        <Link to={ROUTES.DASHBOARD}>Back to Dashboard</Link>
      </Button>
    </div>
  )
}
