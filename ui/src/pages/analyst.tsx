import { AlertTriangle, RefreshCw } from "lucide-react"
import { useMemo } from "react"
import { useNavigate, useSearchParams } from "react-router"

import { ThreatFiltersBar } from "@/components/analyst/threat-filters"
import {
  DEFAULT_THREAT_SORT,
  ThreatTable,
  type ThreatSort,
  type ThreatSortField,
} from "@/components/analyst/threat-table"
import { EmptyState } from "@/components/common/empty-state"
import { LoadingSkeleton } from "@/components/common/loading-skeleton"
import { PageHeader } from "@/components/common/page-header"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { useThreats } from "@/hooks/use-threats"
import { filterThreats, sortThreats, type ThreatFilters } from "@/lib/analyst/filter"
import type { ThreatSeverity } from "@/lib/analyst/types"
import { formatAbsoluteTime, formatNumber } from "@/lib/format"
import { cn } from "@/lib/utils"

type Window = "1h" | "6h" | "24h" | "168h"

const WINDOW_OPTIONS: Array<{ label: string; value: Window }> = [
  { label: "Last 1h", value: "1h" },
  { label: "Last 6h", value: "6h" },
  { label: "Last 24h", value: "24h" },
  { label: "Last 7d", value: "168h" },
]

const DEFAULT_WINDOW: Window = "24h"
const VALID_WINDOWS = new Set<string>(WINDOW_OPTIONS.map((o) => o.value))
const VALID_SEVERITIES = new Set<ThreatSeverity>(["low", "med", "high", "critical"])
const VALID_SORT_FIELDS = new Set<ThreatSortField>([
  "severity",
  "pattern",
  "entity",
  "events",
  "confidence",
  "first",
  "last",
])

function csv(value: string | null): string[] {
  if (!value) return []
  return value.split(",").map((s) => s.trim()).filter(Boolean)
}

function setOrDelete(params: URLSearchParams, key: string, value: string) {
  if (value) params.set(key, value)
  else params.delete(key)
}

export function AnalystPage() {
  const [params, setParams] = useSearchParams()
  const navigate = useNavigate()

  const rawSince = params.get("since") ?? DEFAULT_WINDOW
  const window: Window = (VALID_WINDOWS.has(rawSince) ? rawSince : DEFAULT_WINDOW) as Window

  const filters = useMemo<ThreatFilters>(
    () => ({
      severity: csv(params.get("severity")).filter((s): s is ThreatSeverity =>
        VALID_SEVERITIES.has(s as ThreatSeverity),
      ),
      patterns: csv(params.get("patterns")),
      query: params.get("q") ?? "",
    }),
    [params],
  )

  const sort = useMemo<ThreatSort>(() => {
    const rawSortField = params.get("sort") ?? DEFAULT_THREAT_SORT.field
    return {
      field: VALID_SORT_FIELDS.has(rawSortField as ThreatSortField)
        ? (rawSortField as ThreatSortField)
        : DEFAULT_THREAT_SORT.field,
      desc: params.get("dir") !== "asc",
    }
  }, [params])

  const { threats, eventCount, isPending, isFetching, isError, refetch, updatedAt } = useThreats({
    since: window,
  })

  const visible = useMemo(
    () => sortThreats(filterThreats(threats, filters), sort),
    [threats, filters, sort],
  )

  const windowLabel = WINDOW_OPTIONS.find((o) => o.value === window)?.label ?? window

  function writeParams(mutator: (next: URLSearchParams) => void) {
    const next = new URLSearchParams(params)
    mutator(next)
    setParams(next, { replace: true })
  }

  function changeWindow(next: Window) {
    writeParams((p) => {
      if (next === DEFAULT_WINDOW) p.delete("since")
      else p.set("since", next)
    })
  }

  function changeFilters(next: ThreatFilters) {
    writeParams((p) => {
      setOrDelete(p, "severity", next.severity.join(","))
      setOrDelete(p, "patterns", next.patterns.join(","))
      setOrDelete(p, "q", next.query.trim())
    })
  }

  function changeSort(next: ThreatSort) {
    writeParams((p) => {
      if (next.field === DEFAULT_THREAT_SORT.field && next.desc === DEFAULT_THREAT_SORT.desc) {
        p.delete("sort")
        p.delete("dir")
      } else {
        p.set("sort", next.field)
        p.set("dir", next.desc ? "desc" : "asc")
      }
    })
  }

  function openThreat(id: string) {
    // Forward the full current search string so Back returns to the same list state
    // (window + severity + patterns + q + sort + dir). The detail page only reads
    // 'since' today; the rest travels through untouched for the return trip.
    const qs = new URLSearchParams(params)
    if (!qs.has("since")) qs.set("since", window)
    navigate(`/analyst/threats/${encodeURIComponent(id)}?${qs.toString()}`)
  }

  return (
    <div className="flex h-full min-h-0 flex-col gap-4">
      <PageHeader
        title="Analyst"
        description="Client-side correlation across recent events. Experimental — patterns are heuristics, not detections."
        actions={
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={refetch}
              disabled={isFetching}
              aria-label="Refresh threats"
            >
              <RefreshCw
                className={cn("mr-1.5 size-3.5", isFetching && "animate-spin")}
                aria-hidden
              />
              Refresh
            </Button>
            <Select value={window} onValueChange={(v) => changeWindow(v as Window)}>
              <SelectTrigger className="h-9 w-36" aria-label="Time window">
                <SelectValue />
              </SelectTrigger>
              <SelectContent align="end">
                {WINDOW_OPTIONS.map((o) => (
                  <SelectItem key={o.value} value={o.value}>
                    {o.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        }
      />

      <Card className="shrink-0 border-dashed bg-muted/30">
        <CardContent className="flex items-start gap-3 py-3 text-[12px] text-muted-foreground">
          <AlertTriangle className="mt-0.5 size-4 shrink-0 text-priority-warning" aria-hidden />
          <div className="flex-1">
            <span className="font-medium text-foreground">Heuristic correlation.</span>{" "}
            Threats are computed in the browser from {formatNumber(eventCount)} events in{" "}
            {windowLabel.toLowerCase()}. Expect false positives — always cross-check with the raw
            event stream. Auto-refresh is disabled on this page; use{" "}
            <span className="font-medium text-foreground">Refresh</span> to recompute.
            {updatedAt > 0 && (
              <span className="ml-2 text-[11px]">
                · last refresh {formatAbsoluteTime(updatedAt)}
              </span>
            )}
          </div>
        </CardContent>
      </Card>

      <ThreatFiltersBar threats={threats} value={filters} onChange={changeFilters} />

      <div className="flex min-h-0 flex-1 flex-col">
        {isPending ? (
          <LoadingSkeleton lines={8} />
        ) : isError ? (
          <EmptyState title="Unable to load events" />
        ) : threats.length === 0 ? (
          <EmptyState
            title="No correlated threats"
            description={`Nothing stood out across ${formatNumber(eventCount)} events in ${windowLabel.toLowerCase()}.`}
          />
        ) : visible.length === 0 ? (
          <EmptyState
            title="No matches"
            description={`${threats.length} threats total — current filters exclude all of them.`}
          />
        ) : (
          <div className="min-h-0 flex-1 overflow-auto pr-1">
            <div className="mb-2 text-[11px] text-muted-foreground">
              Showing {visible.length} of {threats.length} threats
            </div>
            <ThreatTable
              threats={visible}
              selectedId={null}
              onSelect={openThreat}
              sort={sort}
              onSortChange={changeSort}
            />
          </div>
        )}
      </div>
    </div>
  )
}

export default AnalystPage
