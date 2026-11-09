import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Tooltip,
} from "recharts"
const DEFAULT_DISTRIBUTION: { severity: "critical" | "high" | "medium" | "low"; count: number; fill: string }[] = [
  { severity: "critical", count: 0, fill: "var(--chart-5)" },
  { severity: "high", count: 0, fill: "var(--chart-3)" },
  { severity: "medium", count: 0, fill: "var(--chart-4)" },
  { severity: "low", count: 0, fill: "var(--chart-2)" },
]

interface SeverityDistributionChartProps {
  distribution?: { severity: "critical" | "high" | "medium" | "low"; count: number; fill: string }[]
}

export function SeverityDistributionChart({ distribution }: SeverityDistributionChartProps) {
  const chartData = distribution && distribution.length > 0 ? distribution : DEFAULT_DISTRIBUTION
  const total = chartData.reduce((acc: number, d: { count: number }) => acc + d.count, 0)
  return (
    <div className="rounded-xl border border-border bg-card p-5">
      <div className="mb-5">
        <h3 className="text-sm font-semibold text-foreground">
          Severity Distribution
        </h3>
        <p className="text-xs text-muted-foreground">
          Open findings by severity level
        </p>
      </div>

      <div className="flex items-center gap-6">
        {/* Donut chart */}
        <div className="relative h-[160px] w-[160px] shrink-0">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={chartData}
                cx="50%"
                cy="50%"
                innerRadius={50}
                outerRadius={72}
                paddingAngle={3}
                dataKey="count"
                strokeWidth={0}
              >
                {chartData.map((entry) => (
                  <Cell key={entry.severity} fill={entry.fill} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{
                  backgroundColor: "var(--card)",
                  border: "1px solid var(--border)",
                  borderRadius: "8px",
                  fontSize: "12px",
                  color: "var(--foreground)",
                }}
                formatter={(value, name) => [
                  value,
                  String(name).charAt(0).toUpperCase() + String(name).slice(1),
                ]}
              />
            </PieChart>
          </ResponsiveContainer>
          {/* Center label */}
          <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
            <span className="text-2xl font-bold text-foreground">{total}</span>
            <span className="text-[10px] text-muted-foreground">Total</span>
          </div>
        </div>

        {/* Legend */}
        <div className="flex flex-1 flex-col gap-2.5">
          {chartData.map((item) => (
            <div key={item.severity} className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span
                  className="h-2.5 w-2.5 rounded-full"
                  style={{ backgroundColor: item.fill }}
                />
                <span className="text-xs capitalize text-muted-foreground">
                  {item.severity}
                </span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-semibold text-foreground">
                  {item.count}
                </span>
                <span className="text-[10px] text-muted-foreground">
                  {total > 0 ? Math.round((item.count / total) * 100) : 0}%
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
