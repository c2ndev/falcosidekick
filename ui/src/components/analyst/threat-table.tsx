import { ArrowDown, ArrowUp, ArrowUpDown } from "lucide-react"

import type { Threat } from "@/lib/analyst/types"
import { formatAbsoluteTime, formatNumber } from "@/lib/format"
import { cn } from "@/lib/utils"

import { SeverityBadge } from "./severity-badge"

export type ThreatSortField =
  | "severity"
  | "pattern"
  | "entity"
  | "events"
  | "confidence"
  | "first"
  | "last"

export interface ThreatSort {
  field: ThreatSortField
  desc: boolean
}

export const DEFAULT_THREAT_SORT: ThreatSort = { field: "severity", desc: true }

interface ThreatTableProps {
  threats: readonly Threat[]
  selectedId?: string | null
  onSelect: (id: string) => void
  sort: ThreatSort
  onSortChange: (next: ThreatSort) => void
}

export function ThreatTable({
  threats,
  selectedId,
  onSelect,
  sort,
  onSortChange,
}: ThreatTableProps) {
  function toggle(field: ThreatSortField) {
    if (sort.field === field) {
      onSortChange({ field, desc: !sort.desc })
    } else {
      onSortChange({ field, desc: defaultDescFor(field) })
    }
  }

  return (
    <div className="overflow-hidden rounded-md border">
      <table className="w-full border-collapse text-sm">
        <thead className="bg-muted/40 text-left text-xs font-medium uppercase tracking-wide text-muted-foreground">
          <tr>
            <SortHeader sort={sort} field="severity" onToggle={toggle}>
              Severity
            </SortHeader>
            <SortHeader sort={sort} field="pattern" onToggle={toggle}>
              Pattern
            </SortHeader>
            <SortHeader sort={sort} field="entity" onToggle={toggle}>
              Entity
            </SortHeader>
            <SortHeader sort={sort} field="events" onToggle={toggle} align="right">
              Events
            </SortHeader>
            <SortHeader sort={sort} field="confidence" onToggle={toggle} align="right">
              Confidence
            </SortHeader>
            <SortHeader sort={sort} field="first" onToggle={toggle}>
              First seen
            </SortHeader>
            <SortHeader sort={sort} field="last" onToggle={toggle}>
              Last seen
            </SortHeader>
          </tr>
        </thead>
        <tbody>
          {threats.map((t) => {
            const active = t.id === selectedId
            return (
              <tr
                key={t.id}
                onClick={() => onSelect(t.id)}
                className={cn(
                  "cursor-pointer border-t transition-colors hover:bg-muted/30",
                  active && "bg-brand/10 hover:bg-brand/15",
                )}
                aria-selected={active}
              >
                <td className="px-3 py-2 align-top">
                  <SeverityBadge severity={t.severity} />
                </td>
                <td className="px-3 py-2 align-top">
                  <div className="font-medium">{t.patternName}</div>
                  <div className="text-[11px] text-muted-foreground">{t.reason}</div>
                </td>
                <td className="px-3 py-2 align-top font-mono text-[12px]">{t.entityLabel}</td>
                <td className="px-3 py-2 text-right align-top tabular-nums">
                  {formatNumber(t.events.length)}
                </td>
                <td className="px-3 py-2 text-right align-top tabular-nums">
                  {Math.round(t.confidence * 100)}%
                </td>
                <td className="px-3 py-2 align-top text-[12px] text-muted-foreground">
                  {formatAbsoluteTime(t.firstTime)}
                </td>
                <td className="px-3 py-2 align-top text-[12px] text-muted-foreground">
                  {formatAbsoluteTime(t.lastTime)}
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

function SortHeader({
  sort,
  field,
  onToggle,
  align,
  children,
}: {
  sort: ThreatSort
  field: ThreatSortField
  onToggle: (field: ThreatSortField) => void
  align?: "left" | "right"
  children: React.ReactNode
}) {
  const active = sort.field === field
  const Icon = !active ? ArrowUpDown : sort.desc ? ArrowDown : ArrowUp
  return (
    <th
      className={cn("px-3 py-2", align === "right" ? "text-right" : "text-left")}
      aria-sort={active ? (sort.desc ? "descending" : "ascending") : "none"}
    >
      <button
        type="button"
        onClick={() => onToggle(field)}
        className={cn(
          "inline-flex items-center gap-1 hover:text-foreground focus-visible:outline-none",
          active && "text-foreground",
          align === "right" && "flex-row-reverse",
        )}
      >
        <span>{children}</span>
        <Icon className="size-3" aria-hidden />
      </button>
    </th>
  )
}

function defaultDescFor(field: ThreatSortField): boolean {
  return field === "entity" || field === "pattern" ? false : true
}
