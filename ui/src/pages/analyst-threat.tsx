import { ArrowLeft, PanelRightClose, PanelRightOpen, RefreshCw } from "lucide-react"
import { useMemo, useState } from "react"
import { Link, useParams, useSearchParams } from "react-router"

import { SeverityBadge } from "@/components/analyst/severity-badge"
import { ThreatEventList } from "@/components/analyst/threat-event-list"
import { ThreatEdgeLegend, ThreatGraph } from "@/components/analyst/threat-graph"
import { EmptyState } from "@/components/common/empty-state"
import { LoadingSkeleton } from "@/components/common/loading-skeleton"
import { PageHeader } from "@/components/common/page-header"
import { EventDetailDrawer } from "@/components/events/event-detail-drawer"
import { Button } from "@/components/ui/button"
import { useThreats } from "@/hooks/use-threats"
import type { Event } from "@/lib/types"
import { formatAbsoluteTime } from "@/lib/format"
import { cn } from "@/lib/utils"

type Window = "1h" | "6h" | "24h" | "168h"

const VALID_WINDOWS = new Set<Window>(["1h", "6h", "24h", "168h"])
const DEFAULT_WINDOW: Window = "24h"

export function AnalystThreatPage() {
  const params = useParams<{ threatId: string }>()
  const [search] = useSearchParams()
  const rawSince = search.get("since") ?? DEFAULT_WINDOW
  const window: Window = (VALID_WINDOWS.has(rawSince as Window) ? rawSince : DEFAULT_WINDOW) as Window

  const threatId = params.threatId ? decodeURIComponent(params.threatId) : null

  const { threats, isPending, isFetching, isError, refetch, updatedAt } = useThreats({
    since: window,
  })

  const threat = useMemo(
    () => threats.find((t) => t.id === threatId) ?? null,
    [threats, threatId],
  )

  const [focusEventUuid, setFocusEventUuid] = useState<string | null>(null)
  const [drawerEvent, setDrawerEvent] = useState<Event | null>(null)
  const [eventsPanelOpen, setEventsPanelOpen] = useState(false)

  function openEvent(uuid: string) {
    const evt = threat?.events.find((e) => e.uuid === uuid) ?? null
    setFocusEventUuid(uuid)
    setDrawerEvent(evt)
  }

  // Round-trip the entire incoming search string (filters, sort, window, etc.)
  // so Back returns the user to the list state they left.
  const backQs = search.toString()
  const backHref = `/analyst${backQs ? `?${backQs}` : ""}`

  if (isPending) {
    return (
      <div className="flex h-full min-h-0 flex-col gap-4">
        <BackHeader backHref={backHref} />
        <LoadingSkeleton lines={10} />
      </div>
    )
  }

  if (isError) {
    return (
      <div className="flex h-full min-h-0 flex-col gap-4">
        <BackHeader backHref={backHref} />
        <EmptyState title="Unable to load events" />
      </div>
    )
  }

  if (!threat) {
    return (
      <div className="flex h-full min-h-0 flex-col gap-4">
        <BackHeader backHref={backHref} />
        <EmptyState
          title="Threat not found"
          description={
            threats.length === 0
              ? "The analyst data may have been refreshed. Go back and reopen the threat."
              : "This threat is no longer in the current correlation result."
          }
        />
      </div>
    )
  }

  return (
    <div className="flex h-full min-h-0 flex-col gap-4">
      <div className="flex items-center justify-start">
        <Button asChild variant="ghost" size="sm" className="-ml-2">
          <Link to={backHref}>
            <ArrowLeft className="mr-1.5 size-3.5" aria-hidden />
            Back to threats
          </Link>
        </Button>
      </div>
      <PageHeader
        title={threat.patternName}
        description={threat.patternDescription}
        actions={
          <div className="flex items-center gap-2">
            <Button
              size="sm"
              onClick={() => setEventsPanelOpen((v) => !v)}
              aria-label={eventsPanelOpen ? "Hide events panel" : "Show events panel"}
              aria-pressed={eventsPanelOpen}
              className="border border-brand bg-brand text-brand-foreground hover:bg-brand/90 focus-visible:ring-brand/40"
            >
              {eventsPanelOpen ? (
                <PanelRightClose className="mr-1.5 size-3.5" aria-hidden />
              ) : (
                <PanelRightOpen className="mr-1.5 size-3.5" aria-hidden />
              )}
              {eventsPanelOpen ? "Hide events" : "Show events"}
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={refetch}
              disabled={isFetching}
              aria-label="Refresh threat data"
            >
              <RefreshCw
                className={cn("mr-1.5 size-3.5", isFetching && "animate-spin")}
                aria-hidden
              />
              Refresh
            </Button>
          </div>
        }
      />

      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 rounded-md border bg-card px-4 py-3 text-[12px]">
        <SeverityBadge severity={threat.severity} />
        <span className="text-muted-foreground">
          entity{" "}
          <span className="font-mono text-foreground/90">{threat.entityLabel}</span>
        </span>
        <span className="text-muted-foreground">
          {threat.events.length} events
        </span>
        <span className="text-muted-foreground">
          confidence {Math.round(threat.confidence * 100)}%
        </span>
        <span className="text-muted-foreground">
          first{" "}
          <span className="font-mono text-foreground/90">
            {formatAbsoluteTime(threat.firstTime)}
          </span>
        </span>
        <span className="text-muted-foreground">
          last{" "}
          <span className="font-mono text-foreground/90">
            {formatAbsoluteTime(threat.lastTime)}
          </span>
        </span>
        {updatedAt > 0 && (
          <span className="ml-auto text-[11px] text-muted-foreground">
            last refresh {formatAbsoluteTime(updatedAt)}
          </span>
        )}
      </div>

      <div className="rounded-md border bg-muted/30 px-4 py-3 text-[12px] text-foreground/80">
        {threat.reason}
        <ThreatEdgeLegend className="mt-2" />
      </div>

      <div
        className={cn(
          "grid min-h-0 flex-1 grid-cols-1 gap-4",
          eventsPanelOpen ? "lg:grid-cols-5" : "lg:grid-cols-1",
        )}
      >
        <div
          className={cn(
            "relative min-h-[400px] rounded-md border bg-card",
            eventsPanelOpen ? "lg:col-span-3" : "lg:col-span-1",
          )}
        >
          <ThreatGraph
            threat={threat}
            highlightUuid={focusEventUuid}
            onSelectEvent={openEvent}
            className="h-full"
          />
        </div>
        {eventsPanelOpen && (
          <div className="flex min-h-0 flex-col rounded-md border bg-card lg:col-span-2">
            <div className="flex items-center justify-between border-b px-4 py-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">
              <span>Events</span>
              <span className="font-mono normal-case tabular-nums text-[11px]">
                {threat.events.length}
              </span>
            </div>
            <div className="min-h-0 flex-1 overflow-y-auto px-3 py-3">
              <ThreatEventList
                events={threat.events}
                activeUuid={focusEventUuid}
                onSelect={openEvent}
              />
            </div>
          </div>
        )}
      </div>

      <EventDetailDrawer
        event={drawerEvent}
        open={drawerEvent !== null}
        onClose={() => setDrawerEvent(null)}
      />
    </div>
  )
}

function BackHeader({ backHref }: { backHref: string }) {
  return (
    <>
      <div className="flex items-center justify-start">
        <Button asChild variant="ghost" size="sm" className="-ml-2">
          <Link to={backHref}>
            <ArrowLeft className="mr-1.5 size-3.5" aria-hidden />
            Back to threats
          </Link>
        </Button>
      </div>
      <PageHeader title="Threat" />
    </>
  )
}

export default AnalystThreatPage
