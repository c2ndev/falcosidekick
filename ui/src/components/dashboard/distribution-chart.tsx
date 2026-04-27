import { useMemo } from "react"

import { EmptyState } from "@/components/common/empty-state"
import { LoadingSkeleton } from "@/components/common/loading-skeleton"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { useEventsCountBy } from "@/hooks/use-events"
import { formatNumber, truncate } from "@/lib/format"
import { cn } from "@/lib/utils"

const BAR_PALETTE: readonly string[] = [
  "bg-sky-500",
  "bg-violet-500",
  "bg-emerald-500",
  "bg-amber-500",
  "bg-rose-500",
  "bg-cyan-500",
  "bg-fuchsia-500",
  "bg-lime-500",
  "bg-indigo-500",
  "bg-orange-500",
] as const

const DOT_PALETTE: readonly string[] = [
  "bg-sky-500/60",
  "bg-violet-500/60",
  "bg-emerald-500/60",
  "bg-amber-500/60",
  "bg-rose-500/60",
  "bg-cyan-500/60",
  "bg-fuchsia-500/60",
  "bg-lime-500/60",
  "bg-indigo-500/60",
  "bg-orange-500/60",
] as const

interface Props {
  title: string
  groupby: "rule" | "source" | "tags" | "hostname"
  limit?: number
  className?: string
}

export function DistributionChart({ title, groupby, limit = 7, className }: Props) {
  const { data, isPending, isError } = useEventsCountBy(groupby, { since: "24h" })

  const { rows, max, grandTotal } = useMemo(() => {
    const entries = data
      ? Object.entries(data)
          .map(([name, count]) => ({ name, count }))
          .sort((a, b) => b.count - a.count)
      : []
    const top = entries.slice(0, limit)
    return {
      rows: top,
      max: top.reduce((acc, r) => Math.max(acc, r.count), 0) || 1,
      grandTotal: entries.reduce((acc, r) => acc + r.count, 0),
    }
  }, [data, limit])

  return (
    <Card className={className}>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-3">
        <CardTitle className="text-base">{title}</CardTitle>
        {grandTotal > 0 && (
          <span className="text-xs tabular-nums text-muted-foreground">
            {formatNumber(grandTotal)} events · last 24h
          </span>
        )}
      </CardHeader>
      <CardContent>
        {isPending ? (
          <LoadingSkeleton lines={6} />
        ) : isError ? (
          <EmptyState title="Unable to load distribution" />
        ) : rows.length === 0 ? (
          <EmptyState title="No data in the last 24h" />
        ) : (
          <ol className="space-y-2">
            {rows.map((r, idx) => {
              const pct = Math.max(0.02, r.count / max)
              const barClass = BAR_PALETTE[idx % BAR_PALETTE.length]
              const dotClass = DOT_PALETTE[idx % DOT_PALETTE.length]
              return (
                <li key={r.name} className="group">
                  <div className="flex items-baseline justify-between gap-3 text-sm">
                    <div className="flex min-w-0 items-center gap-2">
                      <span className="inline-flex w-5 shrink-0 justify-end text-[11px] tabular-nums text-muted-foreground">
                        {idx + 1}
                      </span>
                      <span className={cn("size-2 shrink-0 rounded-full", dotClass)} aria-hidden />
                      <span className="truncate text-foreground" title={r.name || "(empty)"}>
                        {truncate(r.name || "(empty)", 42)}
                      </span>
                    </div>
                    <span className="shrink-0 text-xs tabular-nums text-muted-foreground">
                      {formatNumber(r.count)}
                    </span>
                  </div>
                  <div className="ml-9 mt-1 h-1.5 overflow-hidden rounded-full bg-muted" aria-hidden>
                    <div
                      className={cn("h-full rounded-full transition-all", barClass)}
                      style={{ width: `${pct * 100}%` }}
                    />
                  </div>
                </li>
              )
            })}
          </ol>
        )}
      </CardContent>
    </Card>
  )
}
