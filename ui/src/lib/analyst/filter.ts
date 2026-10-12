import type { Threat, ThreatSeverity } from "./types"
import { severityOrder } from "./types"

import type { ThreatSort, ThreatSortField } from "@/components/analyst/threat-table"

export interface ThreatFilters {
  severity: readonly ThreatSeverity[]
  patterns: readonly string[]
  query: string
}

export const EMPTY_FILTERS: ThreatFilters = {
  severity: [],
  patterns: [],
  query: "",
}

export function filterThreats(
  threats: readonly Threat[],
  filters: ThreatFilters,
): Threat[] {
  const sevSet = new Set(filters.severity)
  const pidSet = new Set(filters.patterns)
  const q = filters.query.trim().toLowerCase()
  return threats.filter((t) => {
    if (sevSet.size > 0 && !sevSet.has(t.severity)) return false
    if (pidSet.size > 0 && !pidSet.has(t.patternId)) return false
    if (q && !matchesQuery(t, q)) return false
    return true
  })
}

function matchesQuery(t: Threat, q: string): boolean {
  if (t.entityLabel.toLowerCase().includes(q)) return true
  if (t.patternName.toLowerCase().includes(q)) return true
  if (t.reason.toLowerCase().includes(q)) return true
  for (const e of t.events) {
    if (e.rule && e.rule.toLowerCase().includes(q)) return true
    if (e.hostname && e.hostname.toLowerCase().includes(q)) return true
  }
  return false
}

export function sortThreats(
  threats: readonly Threat[],
  sort: ThreatSort,
): Threat[] {
  const copy = [...threats]
  const dir = sort.desc ? -1 : 1
  copy.sort((a, b) => comparator(sort.field, a, b) * dir)
  return copy
}

function comparator(field: ThreatSortField, a: Threat, b: Threat): number {
  switch (field) {
    case "severity":
      return severityOrder(a.severity) - severityOrder(b.severity)
    case "pattern":
      return a.patternName.localeCompare(b.patternName)
    case "entity":
      return a.entityLabel.localeCompare(b.entityLabel)
    case "events":
      return a.events.length - b.events.length
    case "confidence":
      return a.confidence - b.confidence
    case "first":
      return Date.parse(a.firstTime) - Date.parse(b.firstTime)
    case "last":
      return Date.parse(a.lastTime) - Date.parse(b.lastTime)
  }
}
