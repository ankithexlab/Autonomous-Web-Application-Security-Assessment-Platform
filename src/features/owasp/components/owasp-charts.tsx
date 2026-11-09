import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
  Cell,
  PieChart,
  Pie,
} from "recharts"
import { OWASP_CATEGORIES } from "../data/owasp-data"

/* ── Risk Trend Line Chart ── */
interface OWASPRiskTrendChartProps {
  trend?: {
    date: string
    riskScore: number
    criticalFindings: number
    highFindings: number
  }[]
}

export function OWASPRiskTrendChart({ trend: trendProp }: OWASPRiskTrendChartProps) {
  const data = trendProp || []

  return (
    <div className="rounded-xl border border-border bg-card p-5 space-y-4 shadow-xs">
      <div>
        <h3 className="text-sm font-semibold text-foreground">Risk Score Trend</h3>
        <p className="text-xs text-muted-foreground">Monthly OWASP risk index across all categories</p>
      </div>
      <div className="flex gap-4 text-xs">
        <div className="flex items-center gap-1.5">
          <span className="h-2.5 w-2.5 rounded-full bg-violet-500 inline-block" />
          <span className="text-muted-foreground">Risk Score</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="h-2.5 w-2.5 rounded-full bg-red-400 inline-block" />
          <span className="text-muted-foreground">Critical Findings</span>
        </div>
      </div>
      <div className="h-[240px] w-full">
        {data.length === 0 ? (
          <div className="flex h-full items-center justify-center text-xs text-muted-foreground border border-dashed border-border rounded-lg">
            No historical OWASP risk trend data recorded yet
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={data} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="owaspRiskGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#8b5cf6" stopOpacity={0.3} />
                  <stop offset="100%" stopColor="#8b5cf6" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="owaspCritGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#f87171" stopOpacity={0.25} />
                  <stop offset="100%" stopColor="#f87171" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
              <XAxis dataKey="date" axisLine={false} tickLine={false} tick={{ fontSize: 11, fill: "var(--muted-foreground)" }} />
              <YAxis axisLine={false} tickLine={false} tick={{ fontSize: 11, fill: "var(--muted-foreground)" }} />
              <Tooltip
                contentStyle={{ backgroundColor: "var(--card)", border: "1px solid var(--border)", borderRadius: "8px", fontSize: "12px", color: "var(--foreground)" }}
                labelStyle={{ color: "var(--muted-foreground)", fontWeight: 600 }}
              />
              <Area type="monotone" dataKey="riskScore" name="Risk Score" stroke="#8b5cf6" fill="url(#owaspRiskGrad)" strokeWidth={2} />
              <Area type="monotone" dataKey="criticalFindings" name="Critical" stroke="#f87171" fill="url(#owaspCritGrad)" strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  )
}

/* ── Coverage Horizontal Bar Chart ── */
interface OWASPCoverageChartProps {
  categoryBreakdown?: {
    category_id: string
    category_name: string
    short_name: string
    rank: number
    findings_count: number
    critical_count: number
    high_count: number
    compliance_status: string
  }[]
}

export function OWASPCoverageChart({ categoryBreakdown }: OWASPCoverageChartProps) {
  const data = categoryBreakdown && categoryBreakdown.length > 0
    ? categoryBreakdown.map((item) => ({
        name: item.short_name,
        coverage: item.compliance_status === "PASS" ? 100 : item.compliance_status === "WARNING" ? 65 : 25,
        status: item.compliance_status === "PASS" ? "covered" : item.compliance_status === "WARNING" ? "partial" : "uncovered",
      }))
    : OWASP_CATEGORIES.map((cat) => ({
        name: cat.shortName,
        coverage: 0,
        status: "uncovered",
      }))

  const barColor = (status: string) =>
    status === "covered" ? "#10b981" : status === "partial" ? "#f59e0b" : "#ef4444"

  return (
    <div className="rounded-xl border border-border bg-card p-5 space-y-4 shadow-xs">
      <div>
        <h3 className="text-sm font-semibold text-foreground">OWASP Coverage Chart</h3>
        <p className="text-xs text-muted-foreground">Scan coverage % per OWASP Top 10 category</p>
      </div>
      <div className="flex gap-4 text-xs">
        {[{ color: "bg-emerald-500", label: "Covered" }, { color: "bg-amber-500", label: "Partial" }, { color: "bg-red-500", label: "Uncovered" }].map((l) => (
          <div key={l.label} className="flex items-center gap-1.5">
            <span className={`h-2.5 w-2.5 rounded-full inline-block ${l.color}`} />
            <span className="text-muted-foreground">{l.label}</span>
          </div>
        ))}
      </div>
      <div className="h-[260px] w-full">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} layout="vertical" margin={{ top: 4, right: 20, left: 4, bottom: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" horizontal={false} />
            <XAxis type="number" domain={[0, 100]} axisLine={false} tickLine={false} tick={{ fontSize: 11, fill: "var(--muted-foreground)" }} tickFormatter={(v) => `${v}%`} />
            <YAxis dataKey="name" type="category" axisLine={false} tickLine={false} tick={{ fontSize: 10, fill: "var(--muted-foreground)" }} width={80} />
            <Tooltip
              contentStyle={{ backgroundColor: "var(--card)", border: "1px solid var(--border)", borderRadius: "8px", fontSize: "12px" }}
              formatter={(v) => [`${v}%`, "Coverage"]}
            />
            <Bar dataKey="coverage" radius={[0, 4, 4, 0]} maxBarSize={18}>
              {data.map((entry, i) => (
                <Cell key={i} fill={barColor(entry.status)} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}

/* ── Severity Distribution Donut ── */
interface OWASPSeverityChartProps {
  counts?: {
    critical: number
    high: number
    medium: number
    low: number
    info?: number
  }
}

export function OWASPSeverityChart({ counts }: OWASPSeverityChartProps) {
  const data = counts !== undefined
    ? [
        { name: "Critical", value: counts.critical, fill: "#ef4444" },
        { name: "High", value: counts.high, fill: "#f97316" },
        { name: "Medium", value: counts.medium, fill: "#f59e0b" },
        { name: "Low", value: counts.low, fill: "#3b82f6" },
        { name: "Info", value: counts.info ?? 0, fill: "#71717a" },
      ]
    : [
        { name: "Critical", value: 9, fill: "#ef4444" },
        { name: "High", value: 21, fill: "#f97316" },
        { name: "Medium", value: 18, fill: "#f59e0b" },
        { name: "Low", value: 7, fill: "#3b82f6" },
        { name: "Info", value: 2, fill: "#71717a" },
      ]
  const total = data.reduce((s, d) => s + d.value, 0)

  return (
    <div className="rounded-xl border border-border bg-card p-5 space-y-4 shadow-xs">
      <div>
        <h3 className="text-sm font-semibold text-foreground">Severity Distribution</h3>
        <p className="text-xs text-muted-foreground">Open findings by severity level</p>
      </div>
      <div className="flex items-center gap-4">
        <div className="relative h-[160px] w-[160px] shrink-0">
          <ResponsiveContainer width={160} height={160}>
            <PieChart>
              <Pie data={data} cx="50%" cy="50%" innerRadius={48} outerRadius={72} paddingAngle={3} dataKey="value" strokeWidth={0}>
                {data.map((entry, i) => <Cell key={i} fill={entry.fill} />)}
              </Pie>
              <Tooltip
                contentStyle={{ backgroundColor: "var(--card)", border: "1px solid var(--border)", borderRadius: "8px", fontSize: "12px" }}
              />
            </PieChart>
          </ResponsiveContainer>
          <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
            <span className="text-2xl font-bold text-foreground">{total}</span>
            <span className="text-[10px] text-muted-foreground">Total</span>
          </div>
        </div>
        <div className="flex-1 space-y-2">
          {data.map((d) => (
            <div key={d.name} className="flex items-center justify-between text-xs">
              <div className="flex items-center gap-2">
                <span className="h-2.5 w-2.5 rounded-full shrink-0" style={{ backgroundColor: d.fill }} />
                <span className="text-muted-foreground">{d.name}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="font-semibold text-foreground">{d.value}</span>
                <span className="text-[10px] text-muted-foreground">
                  {total > 0 ? Math.round((d.value / total) * 100) : 0}%
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

