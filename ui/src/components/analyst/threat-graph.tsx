import {
  Background,
  Controls,
  Handle,
  MarkerType,
  Position,
  ReactFlow,
  ReactFlowProvider,
  useEdgesState,
  useNodesState,
  useReactFlow,
  type Edge,
  type EdgeTypes,
  type Node,
  type NodeProps,
} from "@xyflow/react"
import { useEffect, useState } from "react"

import {
  CORRELATION_EDGE_KIND,
  CorrelationEdge,
  type CorrelationEdgeData,
} from "@/components/analyst/correlation-edge"
import { PriorityBadge } from "@/components/common/priority-badge"
import { layoutThreatGraph } from "@/lib/analyst/layout"
import type { Threat, ThreatEdgeKind } from "@/lib/analyst/types"
import { formatAbsoluteTime } from "@/lib/format"
import type { Event } from "@/lib/types"
import { cn } from "@/lib/utils"

import "@xyflow/react/dist/style.css"

interface ThreatGraphProps {
  threat: Threat
  highlightUuid?: string | null
  onSelectEvent?: (uuid: string) => void
  className?: string
}

type EventNodeData = {
  event: Event
  isFirst: boolean
  isLast: boolean
  highlighted: boolean
  onSelect?: () => void
}

type FlowNode = Node<EventNodeData, "event">
type FlowEdge = Edge

const NODE_WIDTH = 270
const NODE_HEIGHT = 96

const EDGE_TYPES: EdgeTypes = { correlation: CorrelationEdge }

function EventNode({ data }: NodeProps<FlowNode>) {
  const { event, isFirst, isLast, highlighted, onSelect } = data
  return (
    <div
      role={onSelect ? "button" : undefined}
      tabIndex={onSelect ? 0 : undefined}
      onClick={onSelect}
      onKeyDown={(e) => {
        if (onSelect && (e.key === "Enter" || e.key === " ")) {
          e.preventDefault()
          onSelect()
        }
      }}
      className={cn(
        "flex flex-col gap-1 rounded-md border bg-card px-3 py-2 shadow-sm transition-shadow",
        "hover:shadow-md",
        isFirst && "border-brand",
        isLast && "border-priority-error",
        highlighted && "ring-2 ring-brand ring-offset-1",
      )}
      style={{ width: NODE_WIDTH }}
    >
      <Handle id="t-target" type="target" position={Position.Top} style={{ opacity: 0 }} />
      <Handle id="t-source" type="source" position={Position.Top} style={{ opacity: 0 }} />
      <Handle id="l-target" type="target" position={Position.Left} style={{ opacity: 0 }} />
      <Handle id="l-source" type="source" position={Position.Left} style={{ opacity: 0 }} />
      <div className="flex items-center justify-between gap-2">
        <PriorityBadge priority={event.priority} />
        <span className="truncate text-[10px] text-muted-foreground">
          {formatAbsoluteTime(event.time)}
        </span>
      </div>
      <div className="truncate text-[12px] font-medium" title={event.rule}>
        {event.rule}
      </div>
      {event.hostname && (
        <div className="truncate text-[10px] font-mono text-muted-foreground">
          {event.hostname}
        </div>
      )}
      <Handle id="r-target" type="target" position={Position.Right} style={{ opacity: 0 }} />
      <Handle id="r-source" type="source" position={Position.Right} style={{ opacity: 0 }} />
      <Handle id="b-target" type="target" position={Position.Bottom} style={{ opacity: 0 }} />
      <Handle id="b-source" type="source" position={Position.Bottom} style={{ opacity: 0 }} />
    </div>
  )
}

const NODE_TYPES = { event: EventNode }

const SIDE_ID: Record<Position, string> = {
  [Position.Top]: "t",
  [Position.Right]: "r",
  [Position.Bottom]: "b",
  [Position.Left]: "l",
}

function sourceHandleId(side: Position): string {
  return `${SIDE_ID[side]}-source`
}

function targetHandleId(side: Position): string {
  return `${SIDE_ID[side]}-target`
}

const MAX_GRAPH_EVENTS = 20

function ThreatGraphInner({
  threat,
  highlightUuid,
  onSelectEvent,
  className,
}: ThreatGraphProps) {
  const [nodes, setNodes, onNodesChange] = useNodesState<FlowNode>([])
  const [edges, setEdges, onEdgesChange] = useEdgesState<FlowEdge>([])
  const [layoutKey, setLayoutKey] = useState<string | null>(null)
  const { fitView } = useReactFlow()
  const oversize = threat.events.length > MAX_GRAPH_EVENTS
  const layoutReady = layoutKey === threat.id

  useEffect(() => {
    if (oversize) return
    let cancelled = false

    const sortedEvents = [...threat.events].sort(
      (a, b) => Date.parse(a.time) - Date.parse(b.time),
    )

    layoutThreatGraph(threat, NODE_WIDTH, NODE_HEIGHT).then((layout) => {
      if (cancelled) return

      const nodePositions = new Map(layout.nodes.map((n) => [n.id, n]))
      const edgePositions = new Map(
        layout.edges.map((e) => [e.id, e] as const),
      )

      const flowNodes: FlowNode[] = sortedEvents.map((evt, i) => {
        const pos = nodePositions.get(evt.uuid) ?? { x: 0, y: 0 }
        return {
          id: evt.uuid,
          type: "event",
          position: { x: pos.x, y: pos.y },
          data: {
            event: evt,
            isFirst: i === 0,
            isLast: i === sortedEvents.length - 1,
            highlighted: evt.uuid === highlightUuid,
            onSelect: onSelectEvent ? () => onSelectEvent(evt.uuid) : undefined,
          },
          draggable: true,
        }
      })

      const flowEdges: FlowEdge[] = threat.edges.map((e, i) => {
        const style = CORRELATION_EDGE_KIND[e.kind]
        const id = `e-${i}-${e.from}-${e.to}`
        const handles = edgePositions.get(id)
        const edgeData: CorrelationEdgeData = {
          kind: e.kind,
          label: e.label,
          detail: e.detail,
          tooltip: e.tooltip,
          pathType: layout.pathType,
        }
        return {
          id,
          source: e.from,
          target: e.to,
          sourceHandle: handles
            ? sourceHandleId(handles.sourcePosition)
            : sourceHandleId(Position.Right),
          targetHandle: handles
            ? targetHandleId(handles.targetPosition)
            : targetHandleId(Position.Left),
          type: "correlation",
          animated: e.kind === "escalation",
          data: edgeData,
          style: {
            stroke: style.stroke,
            strokeWidth: 1.5,
            strokeDasharray: style.dash,
          },
          markerEnd: { type: MarkerType.ArrowClosed, color: style.stroke },
        }
      })

      setNodes(flowNodes)
      setEdges(flowEdges)
      setLayoutKey(threat.id)
      requestAnimationFrame(() => {
        fitView({ padding: 0.25, duration: 0 })
      })
    })

    return () => {
      cancelled = true
    }
  }, [threat, highlightUuid, onSelectEvent, setNodes, setEdges, fitView, oversize])

  if (oversize) {
    return (
      <div
        className={cn(
          "flex h-full w-full items-center justify-center rounded-md border border-dashed bg-muted/30 p-6 text-center",
          className,
        )}
      >
        <div className="max-w-md space-y-2 text-sm text-muted-foreground">
          <p className="font-medium text-foreground">
            {threat.events.length} events — too many to visualize as a graph.
          </p>
          <p>
            See the Events panel on the right for the full chronological list.
            Any graph with more than {MAX_GRAPH_EVENTS} nodes becomes illegible;
            the correlation reason is already summarized above.
          </p>
        </div>
      </div>
    )
  }

  return (
    <div
      className={cn(
        "analyst-graph h-full w-full",
        !layoutReady && "opacity-0 transition-opacity",
        layoutReady && "opacity-100 transition-opacity",
        className,
      )}
    >
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={NODE_TYPES}
        edgeTypes={EDGE_TYPES}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        fitView
        fitViewOptions={{ padding: 0.25 }}
        minZoom={0.15}
        maxZoom={1.5}
        proOptions={{ hideAttribution: true }}
        defaultEdgeOptions={{ type: "correlation" }}
        nodesFocusable={false}
        edgesFocusable={false}
      >
        <Background gap={16} size={1} />
        <Controls position="bottom-right" showInteractive={false} />
      </ReactFlow>
    </div>
  )
}

export function ThreatGraph(props: ThreatGraphProps) {
  return (
    <ReactFlowProvider>
      <ThreatGraphInner {...props} />
    </ReactFlowProvider>
  )
}

interface EdgeLegendItem {
  kind: ThreatEdgeKind
  label: string
  description: string
}

export const THREAT_EDGE_LEGEND: readonly EdgeLegendItem[] = [
  { kind: "temporal", label: "time", description: "temporal sequence between two events" },
  { kind: "escalation", label: "escalation", description: "priority rises from one event to the next" },
  {
    kind: "shared-entity",
    label: "shared",
    description: "same user, container, host or rule ties the two events together",
  },
]

export function ThreatEdgeLegend({ className }: { className?: string }) {
  return (
    <ul
      className={cn(
        "flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-muted-foreground",
        className,
      )}
    >
      {THREAT_EDGE_LEGEND.map((item) => {
        const style = CORRELATION_EDGE_KIND[item.kind]
        return (
          <li key={item.kind} className="flex items-center gap-1.5">
            <span
              aria-hidden
              className="inline-block h-[2px] w-6 rounded"
              style={{
                background: style.stroke,
                ...(style.dash
                  ? {
                      backgroundImage: `repeating-linear-gradient(to right, ${style.stroke} 0 4px, transparent 4px 7px)`,
                      background: "transparent",
                      borderTop: `2px dashed ${style.stroke}`,
                      height: 0,
                    }
                  : {}),
              }}
            />
            <span className="font-medium text-foreground/80">{item.label}</span>
            <span>{item.description}</span>
          </li>
        )
      })}
    </ul>
  )
}
