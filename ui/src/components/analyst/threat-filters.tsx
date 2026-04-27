import { Search, X } from "lucide-react"

import {
  MultiSelectFilter,
  type MultiSelectOption,
} from "@/components/events/multi-select-filter"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import type { ThreatFilters } from "@/lib/analyst/filter"
import type { Threat, ThreatSeverity } from "@/lib/analyst/types"
import { cn } from "@/lib/utils"

const SEVERITY_OPTIONS: readonly MultiSelectOption[] = [
  { value: "critical", label: "Critical" },
  { value: "high", label: "High" },
  { value: "med", label: "Medium" },
  { value: "low", label: "Low" },
]

interface ThreatFiltersBarProps {
  threats: readonly Threat[]
  value: ThreatFilters
  onChange: (next: ThreatFilters) => void
  className?: string
}

export function ThreatFiltersBar({
  threats,
  value,
  onChange,
  className,
}: ThreatFiltersBarProps) {
  const patternCounts = new Map<string, { name: string; count: number }>()
  for (const t of threats) {
    const entry = patternCounts.get(t.patternId)
    if (entry) entry.count++
    else patternCounts.set(t.patternId, { name: t.patternName, count: 1 })
  }
  const patternOptions: MultiSelectOption[] = Array.from(patternCounts.entries())
    .sort((a, b) => b[1].count - a[1].count)
    .map(([id, { name, count }]) => ({
      value: id,
      label: name,
      hint: String(count),
    }))

  const hasAny =
    value.severity.length > 0 || value.patterns.length > 0 || value.query.trim() !== ""

  function clearAll() {
    onChange({ severity: [], patterns: [], query: "" })
  }

  return (
    <div className={cn("flex flex-wrap items-center gap-2", className)}>
      <div className="relative min-w-64 flex-1">
        <Search
          className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground"
          aria-hidden
        />
        <Input
          className="pl-8"
          placeholder="Search entity, rule, reason…"
          value={value.query}
          onChange={(e) => onChange({ ...value, query: e.target.value })}
          aria-label="Filter threats by entity, rule, or reason"
        />
      </div>

      <MultiSelectFilter
        label="Severity"
        placeholder="Severity"
        options={SEVERITY_OPTIONS}
        values={value.severity}
        onChange={(vals) =>
          onChange({ ...value, severity: vals as ThreatSeverity[] })
        }
      />

      <MultiSelectFilter
        label="Pattern"
        placeholder="Pattern"
        options={patternOptions}
        values={value.patterns}
        onChange={(vals) => onChange({ ...value, patterns: vals })}
      />

      {hasAny && (
        <Button variant="ghost" size="sm" onClick={clearAll} aria-label="Clear analyst filters">
          <X className="mr-1 size-3.5" aria-hidden />
          Clear
        </Button>
      )}
    </div>
  )
}
