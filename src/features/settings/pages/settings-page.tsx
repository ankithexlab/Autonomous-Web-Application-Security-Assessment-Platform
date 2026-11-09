import { useState } from "react"
import { motion } from "framer-motion"
import { User, Palette, Bell, Key, Building2, ShieldCheck } from "lucide-react"

/* ── Settings Sub-Tabs ── */
import { ProfileSettingsTab } from "../components/profile-settings-tab"
import { ThemeSettingsTab } from "../components/theme-settings-tab"
import { NotificationSettingsTab } from "../components/notification-settings-tab"
import { ApiKeysTab } from "../components/api-keys-tab"
import { AccountSettingsTab } from "../components/account-settings-tab"
import { SecuritySettingsTab } from "../components/security-settings-tab"

type SettingsTab = "profile" | "theme" | "notifications" | "apikeys" | "account" | "security"

export function SettingsPage() {
  const [activeTab, setActiveTab] = useState<SettingsTab>("profile")

  const tabs = [
    { id: "profile" as const, label: "Profile", icon: User },
    { id: "theme" as const, label: "Theme & Appearance", icon: Palette },
    { id: "notifications" as const, label: "Notifications & Alerts", icon: Bell },
    { id: "apikeys" as const, label: "API Keys", icon: Key },
    { id: "account" as const, label: "Account & Workspace", icon: Building2 },
    { id: "security" as const, label: "Security & 2FA", icon: ShieldCheck },
  ]

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <motion.div
        initial={{ opacity: 0, y: -8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
      >
        <h1 className="text-2xl font-extrabold tracking-tight text-foreground">
          Platform Settings & Preferences
        </h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Manage user profiles, console appearance themes, notification webhooks, API tokens, workspace configurations, and multi-factor authentication
        </p>
      </motion.div>

      {/* Tabs Navigation Bar */}
      <div className="flex overflow-x-auto gap-1.5 rounded-2xl border border-border/80 bg-muted/40 p-1.5 scrollbar-none">
        {tabs.map((tab) => {
          const Icon = tab.icon
          const isActive = activeTab === tab.id
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 rounded-xl px-4 py-2 text-xs font-bold transition-all whitespace-nowrap select-none ${
                isActive
                  ? "bg-card text-primary shadow-xs ring-1 ring-border"
                  : "text-muted-foreground hover:bg-card/50 hover:text-foreground"
              }`}
            >
              <Icon className={`h-4 w-4 ${isActive ? "text-primary" : "text-muted-foreground"}`} />
              <span>{tab.label}</span>
            </button>
          )
        })}
      </div>

      {/* Active Tab Panel */}
      <motion.div
        key={activeTab}
        initial={{ opacity: 0, y: 6 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.25 }}
      >
        {activeTab === "profile" && <ProfileSettingsTab />}
        {activeTab === "theme" && <ThemeSettingsTab />}
        {activeTab === "notifications" && <NotificationSettingsTab />}
        {activeTab === "apikeys" && <ApiKeysTab />}
        {activeTab === "account" && <AccountSettingsTab />}
        {activeTab === "security" && <SecuritySettingsTab />}
      </motion.div>
    </div>
  )
}
