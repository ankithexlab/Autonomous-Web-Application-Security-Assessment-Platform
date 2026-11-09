import { useNavigate } from "react-router"
import { User, LogOut, Settings } from "lucide-react"
import { toast } from "sonner"
import { ROUTES } from "@/constants"
import { useAuthStore } from "@/stores/auth-store"
import { Button } from "@/components/ui/button"
import { Avatar, AvatarFallback } from "@/components/ui/avatar"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { ThemeToggle } from "@/components/common/theme-toggle"
import { MobileNav } from "./mobile-nav"
import { Breadcrumb } from "./breadcrumb"
import { NotificationPanel } from "./notification-panel"
import { CommandSearch } from "./command-search"

interface TopNavProps {
  title?: string
}

export function TopNav({ title }: TopNavProps) {
  const navigate = useNavigate()
  const user = useAuthStore((s) => s.user)
  const logout = useAuthStore((s) => s.logout)

  const handleLogout = () => {
    logout()
    toast.success("Signed out", {
      description: "You have been signed out successfully.",
    })
    navigate(ROUTES.AUTH.LOGIN)
  }

  const initials = user?.name
    ? user.name
        .split(" ")
        .map((n) => n[0])
        .join("")
        .toUpperCase()
        .slice(0, 2)
    : null

  return (
    <header className="flex h-16 shrink-0 items-center justify-between border-b border-border bg-background px-4 lg:px-6 select-none">
      {/* Left: Breadcrumb / Title */}
      <div className="flex items-center gap-4">
        <div className="flex flex-col gap-0.5">
          <Breadcrumb />
          {title && (
            <h1 className="text-base font-bold text-foreground tracking-tight sm:text-lg">
              {title}
            </h1>
          )}
        </div>
      </div>

      {/* Right: Actions */}
      <div className="flex items-center gap-2">
        {/* Command / Global Search */}
        <CommandSearch />

        {/* Notifications Panel */}
        <NotificationPanel />

        {/* Theme Toggle */}
        <ThemeToggle />

        {/* User Menu */}
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              variant="ghost"
              aria-label="User Account Menu"
              className="ml-1 h-9 w-9 rounded-full p-0"
            >
              <Avatar className="h-8 w-8">
                <AvatarFallback className="bg-primary/10 text-xs font-bold text-primary border border-primary/20">
                  {initials ?? <User className="h-4 w-4" />}
                </AvatarFallback>
              </Avatar>
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-56">
            {user && (
              <>
                <DropdownMenuLabel className="font-normal">
                  <div className="flex flex-col space-y-1">
                    <p className="text-sm font-bold text-foreground">{user.name}</p>
                    <p className="text-xs text-muted-foreground font-mono truncate">
                      {user.email}
                    </p>
                  </div>
                </DropdownMenuLabel>
                <DropdownMenuSeparator />
              </>
            )}
            <DropdownMenuItem onClick={() => navigate(ROUTES.SETTINGS)}>
              <Settings className="mr-2 h-4 w-4" />
              Platform Settings
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem
              onClick={handleLogout}
              className="text-destructive focus:text-destructive font-semibold cursor-pointer"
            >
              <LogOut className="mr-2 h-4 w-4" />
              Log out
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
        <MobileNav />
      </div>
    </header>
  )
}
