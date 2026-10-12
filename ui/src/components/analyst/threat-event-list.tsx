import { PriorityBadge } from "@/components/common/priority-badge"
import { outputField } from "@/lib/analyst/phases"
import { formatAbsoluteTime } from "@/lib/format"
import type { Event } from "@/lib/types"
import { cn } from "@/lib/utils"

interface ThreatEventListProps {
  events: readonly Event[]
  activeUuid?: string | null
  onSelect?: (uuid: string) => void
}

const HIGHLIGHT_FIELDS: ReadonlyArray<{ label: string; keys: string[] }> = [
  { label: "user", keys: ["user.name", "user"] },
  { label: "container", keys: ["container.id", "container.name"] },
  { label: "process", keys: ["proc.name", "proc.cmdline"] },
  { label: "fd", keys: ["fd.name"] },
]

export function ThreatEventList({ events, activeUuid, onSelect }: ThreatEventListProps) {
  const sorted = [...events].sort((a, b) => Date.parse(a.time) - Date.parse(b.time))
  return (
    <ul className="flex flex-col gap-2">
      {sorted.map((evt, i) => {
        const active = evt.uuid === activeUuid
        const fields: Array<{ label: string; value: string }> = []
        for (const f of HIGHLIGHT_FIELDS) {
          const v = outputField(evt, ...f.keys)
          if (v) fields.push({ label: f.label, value: v })
        }
        return (
          <li key={evt.uuid}>
            <button
              type="button"
              onClick={() => onSelect?.(evt.uuid)}
              className={cn(
                "w-full rounded-md border bg-card px-3 py-2 text-left text-sm transition-colors",
                "hover:border-brand/40 hover:bg-brand/5",
                active && "border-brand bg-brand/10",
              )}
            >
              <div className="flex items-start justify-between gap-2">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-[10px] text-muted-foreground tabular-nums">
                    #{i + 1}
                  </span>
                  <PriorityBadge priority={evt.priority} />
                </div>
                <span className="text-[10px] text-muted-foreground">
                  {formatAbsoluteTime(evt.time)}
                </span>
              </div>
              <div className="mt-1 truncate font-medium" title={evt.rule}>
                {evt.rule}
              </div>
              <div className="mt-0.5 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-[11px] text-muted-foreground">
                {evt.hostname && (
                  <span>
                    host <span className="font-mono text-foreground/80">{evt.hostname}</span>
                  </span>
                )}
                {evt.source && (
                  <span>
                    source <span className="font-mono text-foreground/80">{evt.source}</span>
                  </span>
                )}
                {fields.map((f) => (
                  <span key={f.label}>
                    {f.label}{" "}
                    <span className="font-mono text-foreground/80" title={f.value}>
                      {f.value.length > 28 ? `${f.value.slice(0, 28)}…` : f.value}
                    </span>
                  </span>
                ))}
              </div>
              <p className="mt-1 line-clamp-2 text-[11px] text-muted-foreground">{evt.output}</p>
            </button>
          </li>
        )
      })}
    </ul>
  )
}
