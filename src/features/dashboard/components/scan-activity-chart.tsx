import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts"
const DEFAULT_WEEK = [
  { day: "Mon", completed: 0, failed: 0 },
  { day: "Tue", completed: 0, failed: 0 },
  { day: "Wed", completed: 0, failed: 0 },
  { day: "Thu", completed: 0, failed: 0 },
  { day: "Fri", completed: 0, failed: 0 },
  { day: "Sat", completed: 0, failed: 0 },
  { day: "Sun", completed: 0, failed: 0 },
]

interface ScanActivityChartProps {
  data?: {
    day: string
    completed: number
    failed: number
  }[]
}

export function ScanActivityChart({ data: dataProp }: ScanActivityChartProps) {
  const chartData = dataProp !== undefined && dataProp.length > 0 ? dataProp : DEFAULT_WEEK
  const totalScans = chartData.reduce((acc, d) => acc + (d.completed || 0) + (d.failed || 0), 0)

  return (
    <div className="rounded-xl border border-border bg-card p-5">
      <div className="mb-5 flex flex-wrap items-center justify-between gap-2">
        <div>
          <h3 className="text-sm font-semibold text-foreground">
            Scan Activity
          </h3>
          <p className="text-xs text-muted-foreground">
            Scans completed vs failed this week
          </p>
        </div>
        {dataProp !== undefined && totalScans === 0 && (
          <span className="text-[11px] font-medium text-muted-foreground bg-muted/40 border border-border px-2 py-0.5 rounded-md">
            No Recent Scans (0 This Week)
          </span>
        )}
      </div>

      {/* Legend */}
      <div className="mb-4 flex gap-4">
        <div className="flex items-center gap-1.5 text-xs">
          <span className="inline-block h-2.5 w-2.5 rounded-sm bg-[var(--chart-1)]" />
          <span className="text-muted-foreground">Completed</span>
        </div>
        <div className="flex items-center gap-1.5 text-xs">
          <span className="inline-block h-2.5 w-2.5 rounded-sm bg-[var(--chart-5)]" />
          <span className="text-muted-foreground">Failed</span>
        </div>
      </div>

      <div className="h-[220px] w-full">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart
            data={chartData}
            margin={{ top: 4, right: 4, left: -20, bottom: 0 }}
          >
            <CartesianGrid
              strokeDasharray="3 3"
              stroke="var(--border)"
              vertical={false}
            />
            <XAxis
              dataKey="day"
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
              cursor={{ fill: "var(--accent)", opacity: 0.3 }}
            />
            <Bar
              dataKey="completed"
              fill="var(--chart-1)"
              radius={[4, 4, 0, 0]}
              maxBarSize={32}
            />
            <Bar
              dataKey="failed"
              fill="var(--chart-5)"
              radius={[4, 4, 0, 0]}
              maxBarSize={32}
            />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}
