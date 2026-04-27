import {
  BaseEdge,
  EdgeLabelRenderer,
  getBezierPath,
  getSmoothStepPath,
  type EdgeProps,
} from "@xyflow/react"
import { Clock, Link2, TrendingUp } from "lucide-react"

import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import { getRoundedOrthogonalPath } from "@/lib/analyst/edge-path"
import type { ThreatEdgeKind } from "@/lib/analyst/types"
import { cn } from "@/lib/utils"

export type CorrelationEdgePathType = "orthogonal" | "smoothstep" | "bezier"

export interface CorrelationEdgeData {
  kind: ThreatEdgeKind
  label?: string
  detail?: string
  tooltip?: string
  pathType?: CorrelationEdgePathType
  [key: string]: unknown
}

const KIND_STYLE: Record<
  ThreatEdgeKind,
  {
    stroke: string
    dash?: string
    label: string
    icon: typeof Clock
    chipClass: string
    iconClass: string
  }
> = {
  temporal: {
    stroke: "var(--muted-foreground)",
    label: "time",
    icon: Clock,
    chipClass: "border-muted-foreground/40 bg-background text-foreground",
    iconClass: "text-muted-foreground",
  },
  escalation: {
    stroke: "oklch(0.65 0.22 30)",
    label: "escalation",
    icon: TrendingUp,
    chipClass:
      "border-[oklch(0.65_0.22_30_/_0.5)] bg-[oklch(0.65_0.22_30_/_0.08)] text-foreground",
    iconClass: "text-[oklch(0.65_0.22_30)]",
  },
  "shared-entity": {
    stroke: "var(--brand)",
    dash: "4 3",
    label: "shared",
    icon: Link2,
    chipClass: "border-brand/50 bg-brand/10 text-foreground",
    iconClass: "text-brand",
  },
}

export function CorrelationEdge({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  style,
  markerEnd,
  data,
}: EdgeProps) {
  const edgeData = (data as CorrelationEdgeData | undefined) ?? { kind: "temporal" }
  const kind = edgeData.kind ?? "temporal"
  const s = KIND_STYLE[kind]
  const Icon = s.icon

  const pathArgs = {
    sourceX,
    sourceY,
    targetX,
    targetY,
    sourcePosition,
    targetPosition,
  }
  let edgePath: string
  let labelX: number
  let labelY: number
  if (edgeData.pathType === "orthogonal") {
    ;[edgePath, labelX, labelY] = getRoundedOrthogonalPath({
      ...pathArgs,
      borderRadius: 12,
    })
  } else if (edgeData.pathType === "bezier") {
    ;[edgePath, labelX, labelY] = getBezierPath(pathArgs)
  } else {
    ;[edgePath, labelX, labelY] = getSmoothStepPath({ ...pathArgs, borderRadius: 12 })
  }

  return (
    <>
      <BaseEdge id={id} path={edgePath} style={style} markerEnd={markerEnd} />
      <EdgeLabelRenderer>
        <div
          className="pointer-events-auto absolute z-10"
          style={{
            transform: `translate(-50%, -50%) translate(${labelX}px, ${labelY}px)`,
          }}
        >
          <Tooltip>
            <TooltipTrigger asChild>
              <div
                className={cn(
                  "flex items-start gap-1.5 rounded-md border px-2 py-1 text-[10px] shadow-sm",
                  "max-w-[260px] cursor-default select-none",
                  s.chipClass,
                )}
              >
                <Icon className={cn("mt-0.5 size-3 shrink-0", s.iconClass)} aria-hidden />
                <div className="flex min-w-0 flex-col leading-tight">
                  <span
                    className={cn(
                      "break-words text-[9px] font-semibold uppercase tracking-wider",
                      s.iconClass,
                    )}
                  >
                    {edgeData.label ?? s.label}
                  </span>
                  {edgeData.detail && (
                    <span className="truncate font-mono text-[10px] text-muted-foreground">
                      {edgeData.detail}
                    </span>
                  )}
                </div>
              </div>
            </TooltipTrigger>
            {edgeData.tooltip && (
              <TooltipContent side="top" className="max-w-sm text-xs">
                {edgeData.tooltip}
              </TooltipContent>
            )}
          </Tooltip>
        </div>
      </EdgeLabelRenderer>
    </>
  )
}

export const CORRELATION_EDGE_KIND: Record<ThreatEdgeKind, { stroke: string; dash?: string }> = {
  temporal: { stroke: KIND_STYLE.temporal.stroke },
  escalation: { stroke: KIND_STYLE.escalation.stroke },
  "shared-entity": {
    stroke: KIND_STYLE["shared-entity"].stroke,
    dash: KIND_STYLE["shared-entity"].dash,
  },
}
