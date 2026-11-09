/**
 * Info Gathering Results — visual display for information gathering module results.
 * Shows DNS records, WHOIS data, IP info, tech stack, and directory discoveries.
 */

import { motion } from "framer-motion"
import {
  Globe, Server, Cpu, FolderSearch, Shield, Search,
  CheckCircle2, ChevronRight,
} from "lucide-react"
import type { ModuleResults } from "../data/scanner-modules-data"

const fadeIn = {
  initial: { opacity: 0, y: 10 },
  animate: { opacity: 1, y: 0 },
  transition: { duration: 0.3 },
}

/* ── Severity Badge ── */
function SeverityDot({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    critical: "bg-rose-500",
    high: "bg-orange-500",
    medium: "bg-amber-500",
    low: "bg-blue-400",
    info: "bg-zinc-400",
  }
  return <div className={`h-2 w-2 rounded-full ${colors[severity] || colors.info}`} />
}

/* ── DNS Records Table ── */
function DNSRecordsCard({ data }: { data: ModuleResults["dns"] }) {
  if (!data) return null

  return (
    <motion.div {...fadeIn} className="rounded-xl border border-zinc-800 bg-zinc-900/50 overflow-hidden">
      <div className="flex items-center gap-3 border-b border-zinc-800 px-5 py-3.5 bg-blue-500/5">
        <Globe className="h-4.5 w-4.5 text-blue-400" />
        <h3 className="text-sm font-semibold text-zinc-100">DNS Records</h3>
        <span className="ml-auto text-xs text-zinc-500">{data.hostname}</span>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-zinc-800/50">
              <th className="px-5 py-2.5 text-left text-[11px] font-semibold uppercase tracking-wider text-zinc-500">Type</th>
              <th className="px-5 py-2.5 text-left text-[11px] font-semibold uppercase tracking-wider text-zinc-500">Value</th>
              <th className="px-5 py-2.5 text-left text-[11px] font-semibold uppercase tracking-wider text-zinc-500">Priority</th>
            </tr>
          </thead>
          <tbody>
            {data.records.map((record, i) => (
              <tr key={i} className="border-b border-zinc-800/30 hover:bg-zinc-800/20 transition-colors">
                <td className="px-5 py-2.5">
                  <span className="inline-flex items-center rounded-md bg-blue-500/10 px-2 py-0.5 text-xs font-semibold text-blue-400">
                    {record.type}
                  </span>
                </td>
                <td className="px-5 py-2.5 font-mono text-xs text-zinc-300">{record.value}</td>
                <td className="px-5 py-2.5 text-xs text-zinc-500">{record.priority ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </motion.div>
  )
}

/* ── WHOIS Card ── */
function WHOISCard({ data }: { data: ModuleResults["whois"] }) {
  if (!data) return null

  return (
    <motion.div {...fadeIn} className="rounded-xl border border-zinc-800 bg-zinc-900/50 overflow-hidden">
      <div className="flex items-center gap-3 border-b border-zinc-800 px-5 py-3.5 bg-blue-500/5">
        <Search className="h-4.5 w-4.5 text-blue-400" />
        <h3 className="text-sm font-semibold text-zinc-100">WHOIS Information</h3>
      </div>
      <div className="grid grid-cols-2 gap-x-6 gap-y-4 p-5 sm:grid-cols-3">
        <div>
          <p className="text-[11px] font-medium uppercase tracking-wider text-zinc-500">Registrar</p>
          <p className="mt-1 text-sm font-medium text-zinc-200">{data.registrar}</p>
        </div>
        <div>
          <p className="text-[11px] font-medium uppercase tracking-wider text-zinc-500">Created</p>
          <p className="mt-1 text-sm text-zinc-300">{data.creationDate}</p>
        </div>
        <div>
          <p className="text-[11px] font-medium uppercase tracking-wider text-zinc-500">Expires</p>
          <p className="mt-1 text-sm text-zinc-300">{data.expirationDate}</p>
        </div>
        <div>
          <p className="text-[11px] font-medium uppercase tracking-wider text-zinc-500">Days Until Expiry</p>
          <p className={`mt-1 text-sm font-semibold ${data.daysUntilExpiry < 30 ? "text-rose-400" : "text-emerald-400"}`}>
            {data.daysUntilExpiry} days
          </p>
        </div>
        <div>
          <p className="text-[11px] font-medium uppercase tracking-wider text-zinc-500">Country</p>
          <p className="mt-1 text-sm text-zinc-300">{data.registrantCountry}</p>
        </div>
        <div>
          <p className="text-[11px] font-medium uppercase tracking-wider text-zinc-500">Name Servers</p>
          <div className="mt-1 flex flex-wrap gap-1">
            {data.nameServers.map((ns, i) => (
              <span key={i} className="rounded bg-zinc-800 px-1.5 py-0.5 text-[11px] font-mono text-zinc-400">
                {ns}
              </span>
            ))}
          </div>
        </div>
      </div>
    </motion.div>
  )
}

/* ── IP & Hosting Card ── */
function IPCard({ data }: { data: ModuleResults["ip"] }) {
  if (!data) return null

  return (
    <motion.div {...fadeIn} className="rounded-xl border border-zinc-800 bg-zinc-900/50 overflow-hidden">
      <div className="flex items-center gap-3 border-b border-zinc-800 px-5 py-3.5 bg-blue-500/5">
        <Server className="h-4.5 w-4.5 text-blue-400" />
        <h3 className="text-sm font-semibold text-zinc-100">IP & Hosting</h3>
      </div>
      <div className="grid grid-cols-1 gap-4 p-5 sm:grid-cols-2 lg:grid-cols-3">
        <div>
          <p className="text-[11px] font-medium uppercase tracking-wider text-zinc-500">IPv4 Addresses</p>
          <div className="mt-1.5 space-y-1">
            {data.ipv4.map((ip, i) => (
              <p key={i} className="font-mono text-sm text-zinc-200">{ip}</p>
            ))}
          </div>
        </div>
        {data.ipv6.length > 0 && (
          <div>
            <p className="text-[11px] font-medium uppercase tracking-wider text-zinc-500">IPv6 Addresses</p>
            <div className="mt-1.5 space-y-1">
              {data.ipv6.map((ip, i) => (
                <p key={i} className="font-mono text-xs text-zinc-300 truncate">{ip}</p>
              ))}
            </div>
          </div>
        )}
        <div>
          <p className="text-[11px] font-medium uppercase tracking-wider text-zinc-500">CDN</p>
          <p className="mt-1 text-sm font-medium text-zinc-200">
            {data.cdnDetected ? (
              <span className="inline-flex items-center gap-1.5 rounded-full bg-emerald-500/10 px-2.5 py-0.5 text-emerald-400">
                <Shield className="h-3 w-3" />
                {data.cdnDetected}
              </span>
            ) : (
              <span className="text-zinc-500">Not detected</span>
            )}
          </p>
        </div>
        <div>
          <p className="text-[11px] font-medium uppercase tracking-wider text-zinc-500">Hosting Provider</p>
          <p className="mt-1 text-sm text-zinc-200">{data.hostingProvider || "Unknown"}</p>
        </div>
        <div className="sm:col-span-2">
          <p className="text-[11px] font-medium uppercase tracking-wider text-zinc-500">Reverse DNS</p>
          <div className="mt-1.5 space-y-1">
            {data.reverseDns.map((entry, i) => (
              <p key={i} className="text-xs text-zinc-400">
                <span className="font-mono text-zinc-300">{entry.ip}</span>
                <ChevronRight className="inline h-3 w-3 mx-1" />
                <span className="font-mono">{entry.hostname}</span>
              </p>
            ))}
          </div>
        </div>
      </div>
    </motion.div>
  )
}

/* ── Technology Stack Card ── */
function TechCard({ data }: { data: ModuleResults["technologies"] }) {
  if (!data || data.length === 0) return null

  const grouped: Record<string, typeof data> = {}
  for (const tech of data) {
    const cat = tech.category
    if (!grouped[cat]) grouped[cat] = []
    grouped[cat].push(tech)
  }

  return (
    <motion.div {...fadeIn} className="rounded-xl border border-zinc-800 bg-zinc-900/50 overflow-hidden">
      <div className="flex items-center gap-3 border-b border-zinc-800 px-5 py-3.5 bg-blue-500/5">
        <Cpu className="h-4.5 w-4.5 text-blue-400" />
        <h3 className="text-sm font-semibold text-zinc-100">Technology Stack</h3>
        <span className="ml-auto text-xs text-zinc-500">{data.length} detected</span>
      </div>
      <div className="p-5">
        <div className="flex flex-wrap gap-2">
          {data.map((tech, i) => (
            <div
              key={i}
              className="flex items-center gap-2 rounded-lg border border-zinc-700/50 bg-zinc-800/50 px-3 py-2 transition-colors hover:border-zinc-600"
            >
              <div className="flex flex-col">
                <span className="text-sm font-medium text-zinc-200">
                  {tech.name}
                  {tech.version && (
                    <span className="ml-1.5 text-xs text-zinc-500">v{tech.version}</span>
                  )}
                </span>
                <span className="text-[11px] text-zinc-500">{tech.category}</span>
              </div>
              <span
                className={`rounded-full px-1.5 py-0.5 text-[10px] font-semibold ${
                  tech.confidence === "HIGH"
                    ? "bg-emerald-500/10 text-emerald-400"
                    : "bg-amber-500/10 text-amber-400"
                }`}
              >
                {tech.confidence}
              </span>
            </div>
          ))}
        </div>
      </div>
    </motion.div>
  )
}

/* ── Directory Discovery Card ── */
function DirectoryCard({ data }: { data: ModuleResults["directories"] }) {
  if (!data) return null

  return (
    <motion.div {...fadeIn} className="rounded-xl border border-zinc-800 bg-zinc-900/50 overflow-hidden">
      <div className="flex items-center gap-3 border-b border-zinc-800 px-5 py-3.5 bg-blue-500/5">
        <FolderSearch className="h-4.5 w-4.5 text-blue-400" />
        <h3 className="text-sm font-semibold text-zinc-100">Directory Discovery</h3>
        <span className="ml-auto text-xs text-zinc-500">
          {data.discovered.length} of {data.pathsChecked} paths found
        </span>
      </div>
      {data.discovered.length > 0 ? (
        <div className="divide-y divide-zinc-800/50">
          {data.discovered.map((item, i) => (
            <div key={i} className="flex items-center gap-3 px-5 py-3 hover:bg-zinc-800/20 transition-colors">
              <SeverityDot severity={item.severity} />
              <code className="flex-1 font-mono text-sm text-zinc-300">{item.path}</code>
              <span className="text-xs text-zinc-500">{item.name}</span>
              <span
                className={`rounded px-2 py-0.5 text-xs font-medium ${
                  item.statusCode === 200
                    ? "bg-emerald-500/10 text-emerald-400"
                    : "bg-amber-500/10 text-amber-400"
                }`}
              >
                {item.statusCode}
              </span>
            </div>
          ))}
        </div>
      ) : (
        <div className="flex items-center gap-3 p-5 text-zinc-500">
          <CheckCircle2 className="h-4 w-4 text-emerald-400" />
          <span className="text-sm">No sensitive paths discovered</span>
        </div>
      )}
    </motion.div>
  )
}

/* ── Main Component ── */
export function InfoGatheringResults({ results }: { results?: ModuleResults }) {
  if (!results) {
    return (
      <div className="flex flex-col items-center justify-center rounded-xl border border-dashed border-border py-12 text-center">
        <Server className="h-8 w-8 text-muted-foreground/40" />
        <p className="mt-2 text-sm font-semibold text-foreground">
          No Intelligence Data Collected Yet
        </p>
        <p className="mt-1 text-xs text-muted-foreground max-w-sm">
          Run reconnaissance modules on this target to harvest DNS records, WHOIS data, detected technologies, and endpoint directories.
        </p>
      </div>
    )
  }

  return (
    <div className="space-y-5">
      <DNSRecordsCard data={results.dns} />
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        <WHOISCard data={results.whois} />
        <IPCard data={results.ip} />
      </div>
      <TechCard data={results.technologies} />
      <DirectoryCard data={results.directories} />
    </div>
  )
}
