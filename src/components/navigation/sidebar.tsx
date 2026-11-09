import { NavLink, useLocation } from "react-router"
import { motion } from "framer-motion"
import { PanelLeftClose, PanelLeft } from "lucide-react"
import { cn } from "@/utils"
import { NAVIGATION, SIDEBAR_WIDTH, SIDEBAR_COLLAPSED_WIDTH } from "@/constants"
import { useSidebarStore } from "@/stores/sidebar-store"
import { Logo } from "@/components/common/logo"
import { Button } from "@/components/ui/button"
import { Separator } from "@/components/ui/separator"
import { ScrollArea } from "@/components/ui/scroll-area"
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip"

export function Sidebar() {
  const { isCollapsed, toggle } = useSidebarStore()
  const location = useLocation()

  return (
    <motion.aside
      initial={false}
      animate={{ width: isCollapsed ? SIDEBAR_COLLAPSED_WIDTH : SIDEBAR_WIDTH }}
      transition={{ duration: 0.2, ease: "easeInOut" }}
      className="relative hidden h-screen flex-col border-r border-sidebar-border bg-sidebar lg:flex"
    >
      {/* Logo */}
      <div
        className={cn(
          "flex h-16 shrink-0 items-center border-b border-sidebar-border",
          isCollapsed ? "justify-center px-2" : "px-5",
        )}
      >
        <Logo collapsed={isCollapsed} />
      </div>

      {/* Navigation */}
      <ScrollArea className="flex-1 py-3">
        <nav className={cn("flex flex-col gap-1", isCollapsed ? "px-2" : "px-3")}>
          {NAVIGATION.map((group, groupIndex) => (
            <div key={group.label}>
              {groupIndex > 0 && <Separator className="my-3 bg-sidebar-border" />}

              {!isCollapsed && (
                <span className="mb-1.5 block px-3 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
                  {group.label}
                </span>
              )}

              {group.items.map((item) => {
                const isActive = location.pathname === item.href
                const Icon = item.icon

                const linkContent = (
                  <NavLink
                    key={item.href}
                    to={item.href}
                    className={cn(
                      "group relative flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors",
                      isCollapsed && "justify-center px-0",
                      isActive
                        ? "bg-sidebar-accent text-sidebar-accent-foreground"
                        : "text-muted-foreground hover:bg-sidebar-accent/50 hover:text-sidebar-foreground",
                    )}
                  >
                    {isActive && (
                      <motion.div
                        layoutId="sidebar-active"
                        className="absolute inset-0 rounded-md bg-sidebar-accent"
                        transition={{ duration: 0.2 }}
                      />
                    )}
                    <Icon
                      className={cn(
                        "relative z-10 h-4.5 w-4.5 shrink-0",
                        isActive ? "text-primary" : "text-muted-foreground group-hover:text-sidebar-foreground",
                      )}
                    />
                    {!isCollapsed && (
                      <span className="relative z-10 truncate">{item.title}</span>
                    )}
                    {!isCollapsed && item.badge != null && (
                      <span className="relative z-10 ml-auto rounded-full bg-primary/10 px-2 py-0.5 text-[10px] font-semibold text-primary">
                        {item.badge}
                      </span>
                    )}
                  </NavLink>
                )

                if (isCollapsed) {
                  return (
                    <Tooltip key={item.href}>
                      <TooltipTrigger asChild>{linkContent}</TooltipTrigger>
                      <TooltipContent side="right" sideOffset={12}>
                        {item.title}
                      </TooltipContent>
                    </Tooltip>
                  )
                }

                return <div key={item.href}>{linkContent}</div>
              })}
            </div>
          ))}
        </nav>
      </ScrollArea>

      {/* Collapse Toggle */}
      <div
        className={cn(
          "flex shrink-0 border-t border-sidebar-border p-3",
          isCollapsed ? "justify-center" : "justify-start",
        )}
      >
        <Tooltip>
          <TooltipTrigger asChild>
            <Button
              variant="ghost"
              size="icon"
              onClick={toggle}
              className="h-8 w-8 text-muted-foreground hover:text-foreground"
            >
              {isCollapsed ? (
                <PanelLeft className="h-4 w-4" />
              ) : (
                <PanelLeftClose className="h-4 w-4" />
              )}
            </Button>
          </TooltipTrigger>
          <TooltipContent side={isCollapsed ? "right" : "top"}>
            {isCollapsed ? "Expand sidebar" : "Collapse sidebar"}
          </TooltipContent>
        </Tooltip>
      </div>
    </motion.aside>
  )
}
