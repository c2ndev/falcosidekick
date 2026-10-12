import { Position } from "@xyflow/react"

import type { Threat } from "./types"

export interface PositionedNode {
  id: string
  x: number
  y: number
}

export type LayoutPathType = "orthogonal" | "smoothstep" | "bezier"

export interface PositionedEdge {
  id: string
  sourcePosition: Position
  targetPosition: Position
}

export interface ThreatLayout {
  nodes: PositionedNode[]
  edges: PositionedEdge[]
  pathType: LayoutPathType
}

export type ThreatShape = "star" | "chain"

interface ShapeInfo {
  shape: ThreatShape
  anchorId: string | null
}

const CHAIN_COLUMNS = 2
const CHAIN_COLUMN_GAP = 300
const CHAIN_ROW_GAP = 120

export function classifyThreatShape(threat: Threat): ShapeInfo {
  if (threat.edges.length < 2) return { shape: "chain", anchorId: null }
  const sources = new Set(threat.edges.map((e) => e.from))
  if (sources.size === 1) {
    const anchorId = threat.edges[0]!.from
    return { shape: "star", anchorId }
  }
  return { shape: "chain", anchorId: null }
}

export async function layoutThreatGraph(
  threat: Threat,
  nodeWidth: number,
  nodeHeight: number,
): Promise<ThreatLayout> {
  const info = classifyThreatShape(threat)

  if (info.shape === "star" && info.anchorId) {
    return layoutStar(threat, info.anchorId, nodeWidth, nodeHeight)
  }
  return layoutChain(threat, nodeWidth, nodeHeight)
}

function layoutStar(
  threat: Threat,
  anchorId: string,
  nodeWidth: number,
  nodeHeight: number,
): ThreatLayout {
  const sortedEvents = sortEvents(threat)
  const spokes = sortedEvents.filter((evt) => evt.uuid !== anchorId)
  const n = Math.max(1, spokes.length)

  const minRadius = 280
  const arcSpacing = Math.max(nodeWidth, nodeHeight) * 1.6
  const radius = Math.max(minRadius, (arcSpacing * n) / (2 * Math.PI))

  const centres = new Map<string, { cx: number; cy: number }>()
  centres.set(anchorId, { cx: nodeWidth / 2, cy: nodeHeight / 2 })
  spokes.forEach((evt, i) => {
    const angle = (2 * Math.PI * i) / n - Math.PI / 2
    centres.set(evt.uuid, {
      cx: radius * Math.cos(angle) + nodeWidth / 2,
      cy: radius * Math.sin(angle) + nodeHeight / 2,
    })
  })

  const nodes: PositionedNode[] = sortedEvents.map((evt) => {
    const c = centres.get(evt.uuid)!
    return { id: evt.uuid, x: c.cx - nodeWidth / 2, y: c.cy - nodeHeight / 2 }
  })

  const edges: PositionedEdge[] = threat.edges.map((e, i) => {
    const handles = pickRadialHandles(centres.get(e.from), centres.get(e.to))
    return {
      id: edgeId(i, e.from, e.to),
      sourcePosition: handles.source,
      targetPosition: handles.target,
    }
  })

  return { nodes, edges, pathType: "bezier" }
}

function layoutChain(threat: Threat, nodeWidth: number, nodeHeight: number): ThreatLayout {
  const sortedEvents = sortEvents(threat)
  const indexById = new Map(sortedEvents.map((evt, index) => [evt.uuid, index] as const))
  const columnStep = nodeWidth + CHAIN_COLUMN_GAP
  const rowStep = nodeHeight + CHAIN_ROW_GAP

  const nodes: PositionedNode[] = sortedEvents.map((evt, index) => {
    const column = index % CHAIN_COLUMNS
    const row = Math.floor(index / CHAIN_COLUMNS)
    return { id: evt.uuid, x: column * columnStep, y: row * rowStep }
  })

  const edges: PositionedEdge[] = threat.edges.map((e, i) => {
    const sourceIndex = indexById.get(e.from)
    const targetIndex = indexById.get(e.to)
    const handles =
      sourceIndex === undefined || targetIndex === undefined
        ? { source: Position.Right, target: Position.Left }
        : pickChainHandles(sourceIndex, targetIndex)

    return {
      id: edgeId(i, e.from, e.to),
      sourcePosition: handles.source,
      targetPosition: handles.target,
    }
  })

  return { nodes, edges, pathType: "orthogonal" }
}

function pickChainHandles(
  sourceIndex: number,
  targetIndex: number,
): { source: Position; target: Position } {
  const sourceRow = Math.floor(sourceIndex / CHAIN_COLUMNS)
  const targetRow = Math.floor(targetIndex / CHAIN_COLUMNS)
  const sourceColumn = sourceIndex % CHAIN_COLUMNS
  const targetColumn = targetIndex % CHAIN_COLUMNS

  if (sourceRow === targetRow) {
    return targetColumn >= sourceColumn
      ? { source: Position.Right, target: Position.Left }
      : { source: Position.Left, target: Position.Right }
  }

  return targetRow > sourceRow
    ? { source: Position.Bottom, target: Position.Top }
    : { source: Position.Top, target: Position.Bottom }
}

function sortEvents(threat: Threat): Threat["events"] {
  return [...threat.events].sort((a, b) => Date.parse(a.time) - Date.parse(b.time))
}

function edgeId(index: number, from: string, to: string): string {
  return `e-${index}-${from}-${to}`
}

function pickRadialHandles(
  src: { cx: number; cy: number } | undefined,
  tgt: { cx: number; cy: number } | undefined,
): { source: Position; target: Position } {
  if (!src || !tgt) return { source: Position.Right, target: Position.Left }
  const dx = tgt.cx - src.cx
  const dy = tgt.cy - src.cy
  if (Math.abs(dx) >= Math.abs(dy)) {
    return dx >= 0
      ? { source: Position.Right, target: Position.Left }
      : { source: Position.Left, target: Position.Right }
  }
  return dy >= 0
    ? { source: Position.Bottom, target: Position.Top }
    : { source: Position.Top, target: Position.Bottom }
}
