import type { ThreatSeverity } from "@/lib/analyst/types"
import { cn } from "@/lib/utils"

const TOKEN: Record<ThreatSeverity, string> = {
  low: "bg-priority-info/15 text-priority-info border-priority-info/30",
  med: "bg-priority-warning/15 text-priority-warning border-priority-warning/30",
  high: "bg-priority-error/15 text-priority-error border-priority-error/30",
  critical: "bg-priority-critical/15 text-priority-critical border-priority-critical/30",
}

const LABEL: Record<ThreatSeverity, string> = {
  low: "LOW",
  med: "MED",
  high: "HIGH",
  critical: "CRIT",
}

interface SeverityBadgeProps {
  severity: ThreatSeverity
  className?: string
}

export function SeverityBadge({ severity, className }: SeverityBadgeProps) {
  return (
    <span
      aria-label={`severity ${severity}`}
      className={cn(
        "inline-flex items-center rounded border px-1.5 py-0.5 font-mono text-[11px] font-semibold uppercase tracking-wide",
        TOKEN[severity],
        className,
      )}
    >
      {LABEL[severity]}
    </span>
  )
}
