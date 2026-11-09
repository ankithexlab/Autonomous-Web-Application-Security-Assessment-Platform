import { useEffect, useState } from "react"
import { Bell, ShieldAlert, CheckCircle2, Info, AlertTriangle } from "lucide-react"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { dashboardService, type NotificationItem } from "@/services/dashboard.service"

export function NotificationPanel() {
  const [notifications, setNotifications] = useState<NotificationItem[]>([])

  useEffect(() => {
    // Use the dedicated GET /dashboard/notifications endpoint (Phase 2 endpoint)
    dashboardService
      .getNotifications()
      .then((items) => {
        // Backend returns timestamps as ISO strings; convert for display
        const normalised: NotificationItem[] = items.map((n) => ({
          ...n,
          timestamp: n.timestamp
            ? new Date(n.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
            : "Recently",
        }))
        setNotifications(normalised)
      })
      .catch(() => {
        // Silently fail — notifications are non-critical UI
        setNotifications([])
      })
  }, [])

  const unreadCount = notifications.filter((n) => !n.read).length

  const markAllAsRead = () => {
    setNotifications((prev) => prev.map((n) => ({ ...n, read: true })))
  }

  const getIcon = (type: NotificationItem["type"]) => {
    switch (type) {
      case "critical":
        return <ShieldAlert className="h-4 w-4 text-red-400" />
      case "warning":
        return <AlertTriangle className="h-4 w-4 text-amber-400" />
      case "success":
        return <CheckCircle2 className="h-4 w-4 text-emerald-400" />
      default:
        return <Info className="h-4 w-4 text-blue-400" />
    }
  }

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          variant="ghost"
          size="icon"
          aria-label="Security Notifications"
          className="relative h-9 w-9 text-muted-foreground hover:text-foreground"
        >
          <Bell className="h-4 w-4" />
          {unreadCount > 0 && (
            <span className="absolute right-1.5 top-1.5 flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-primary opacity-75" />
              <span className="relative inline-flex h-2 w-2 rounded-full bg-primary" />
            </span>
          )}
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-80 sm:w-96 p-0">
        <div className="flex items-center justify-between border-b border-border px-4 py-3">
          <div className="flex items-center gap-2">
            <h3 className="text-sm font-bold text-foreground">Notifications</h3>
            {unreadCount > 0 && (
              <span className="rounded-full bg-primary/15 px-2 py-0.5 text-[10px] font-bold text-primary">
                {unreadCount} new
              </span>
            )}
          </div>
          {unreadCount > 0 && (
            <button
              onClick={markAllAsRead}
              className="text-xs text-muted-foreground hover:text-primary transition-colors font-medium"
            >
              Mark all read
            </button>
          )}
        </div>

        <div className="max-h-[360px] overflow-y-auto divide-y divide-border/50">
          {notifications.length === 0 ? (
            <div className="p-6 text-center text-sm text-muted-foreground">
              No notifications
            </div>
          ) : (
            notifications.map((item) => (
              <div
                key={item.id}
                className={`flex items-start gap-3 p-3.5 transition-colors ${
                  item.read ? "bg-card" : "bg-primary/5"
                } hover:bg-muted/50`}
              >
                <div className="mt-0.5 shrink-0">{getIcon(item.type)}</div>
                <div className="flex-1 space-y-1">
                  <div className="flex items-center justify-between">
                    <p className="text-xs font-bold text-foreground">{item.title}</p>
                    <span className="text-[10px] text-muted-foreground">{item.timestamp}</span>
                  </div>
                  <p className="text-xs text-muted-foreground leading-relaxed">
                    {item.message}
                  </p>
                </div>
              </div>
            ))
          )}
        </div>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
