import { useState } from "react"
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts"
import { Activity } from "lucide-react"

interface ThreatTrendChartProps {
  data?: {
    period: string
    velocity: number
    exploitsPrevented: number
    activeThreats: number
  }[]
}

export function ThreatTrendChart({ data: dataProp }: ThreatTrendChartProps) {
  const [timeframe, setTimeframe] = useState<"weekly" | "monthly">("weekly")

  const chartData = dataProp || []
  const totalThreats = chartData.reduce((acc, d) => acc + (d.activeThreats || 0), 0)

  return (
    <div className="rounded-xl border border-border bg-card p-5 space-y-4 shadow-sm">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div className="flex items-center gap-2">
            <h3 className="text-sm font-semibold text-foreground flex items-center gap-2">
              <Activity className="h-4 w-4 text-violet-400" />
              Threat Velocity & Attack Trend
            </h3>
            {dataProp !== undefined && totalThreats === 0 && (
              <span className="text-[11px] font-medium text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 px-2 py-0.5 rounded-md">
                0 Active Threats
              </span>
            )}
          </div>
          <p className="text-xs text-muted-foreground">
            Inbound attack attempts vs automated exploits blocked
          </p>
        </div>

        {/* Timeframe selector */}
        <div className="flex items-center gap-1 rounded-lg border border-border bg-muted/30 p-1 text-xs">
          <button
            onClick={() => setTimeframe("weekly")}
            className={`rounded-md px-2.5 py-1 font-medium transition-colors ${
              timeframe === "weekly"
                ? "bg-background text-foreground shadow-xs"
                : "text-muted-foreground hover:text-foreground"
            }`}
          >
            Weekly
          </button>
          <button
            onClick={() => setTimeframe("monthly")}
            className={`rounded-md px-2.5 py-1 font-medium transition-colors ${
              timeframe === "monthly"
                ? "bg-background text-foreground shadow-xs"
                : "text-muted-foreground hover:text-foreground"
            }`}
          >
            Monthly
          </button>
        </div>
      </div>

      {/* Legend */}
      <div className="flex flex-wrap gap-4 text-xs">
        <div className="flex items-center gap-1.5">
          <span className="inline-block h-2.5 w-2.5 rounded-full bg-violet-500" />
          <span className="text-muted-foreground">Exploits Blocked</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="inline-block h-2.5 w-2.5 rounded-full bg-red-400" />
          <span className="text-muted-foreground">Attack Velocity Index</span>
        </div>
      </div>

      {/* Chart */}
      <div className="h-[260px] w-full">
        {chartData.length === 0 ? (
          <div className="flex h-full items-center justify-center text-xs text-muted-foreground border border-dashed border-border rounded-lg">
            No threat telemetry data recorded for this period
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart
              data={chartData}
              margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
            >
              <defs>
                <linearGradient id="gradExploits" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#8b5cf6" stopOpacity={0.35} />
                  <stop offset="100%" stopColor="#8b5cf6" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="gradVelocity" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#f87171" stopOpacity={0.3} />
                  <stop offset="100%" stopColor="#f87171" stopOpacity={0} />
                </linearGradient>
              </defs>

              <CartesianGrid
                strokeDasharray="3 3"
                stroke="var(--border)"
                vertical={false}
              />
              <XAxis
                dataKey="period"
                axisLine={false}
                tickLine={false}
                tick={{ fontSize: 12, fill: "var(--muted-foreground)" }}
              />
              <YAxis
                axisLine={false}
                tickLine={false}
                tick={{ fontSize: 12, fill: "var(--muted-foreground)" }}
              />
              <Tooltip
                contentStyle={{
                  backgroundColor: "var(--card)",
                  border: "1px solid var(--border)",
                  borderRadius: "8px",
                  fontSize: "12px",
                  color: "var(--foreground)",
                }}
                itemStyle={{ color: "var(--foreground)" }}
                labelStyle={{ color: "var(--muted-foreground)", fontWeight: 600 }}
              />
              <Area
                type="monotone"
                dataKey="exploitsPrevented"
                name="Exploits Blocked"
                stroke="#8b5cf6"
                fill="url(#gradExploits)"
                strokeWidth={2}
              />
              <Area
                type="monotone"
                dataKey="velocity"
                name="Attack Velocity"
                stroke="#f87171"
                fill="url(#gradVelocity)"
                strokeWidth={2}
              />
            </AreaChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  )
}
