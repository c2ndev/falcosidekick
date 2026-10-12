import { Position } from "@xyflow/react"

interface Point {
  x: number
  y: number
}

export interface RoundedOrthogonalPathArgs {
  sourceX: number
  sourceY: number
  targetX: number
  targetY: number
  sourcePosition?: Position
  targetPosition?: Position
  borderRadius?: number
}

export function getRoundedOrthogonalPath({
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  borderRadius = 12,
}: RoundedOrthogonalPathArgs): [path: string, labelX: number, labelY: number] {
  const points = compactPoints(
    routePoints({ sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition }),
  )
  const label = longestSegmentMidpoint(points)
  return [roundedPolylinePath(points, borderRadius), label.x, label.y]
}

function routePoints({
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
}: Omit<RoundedOrthogonalPathArgs, "borderRadius">): Point[] {
  const source = { x: sourceX, y: sourceY }
  const target = { x: targetX, y: targetY }

  if (
    (sourcePosition === Position.Bottom && targetPosition === Position.Top) ||
    (sourcePosition === Position.Top && targetPosition === Position.Bottom)
  ) {
    const midY = (sourceY + targetY) / 2
    return [source, { x: sourceX, y: midY }, { x: targetX, y: midY }, target]
  }

  if (
    (sourcePosition === Position.Right && targetPosition === Position.Left) ||
    (sourcePosition === Position.Left && targetPosition === Position.Right)
  ) {
    if (nearlyEqual(sourceY, targetY)) return [source, target]
    const midX = (sourceX + targetX) / 2
    return [source, { x: midX, y: sourceY }, { x: midX, y: targetY }, target]
  }

  if (nearlyEqual(sourceX, targetX) || nearlyEqual(sourceY, targetY)) return [source, target]

  const midX = (sourceX + targetX) / 2
  return [source, { x: midX, y: sourceY }, { x: midX, y: targetY }, target]
}

function roundedPolylinePath(points: Point[], radius: number): string {
  if (points.length === 0) return ""
  if (points.length === 1) return `M${formatPoint(points[0]!)}`

  let path = `M${formatPoint(points[0]!)}`
  for (let i = 1; i < points.length - 1; i++) {
    const prev = points[i - 1]!
    const current = points[i]!
    const next = points[i + 1]!
    const incoming = distance(prev, current)
    const outgoing = distance(current, next)
    const cornerRadius = Math.min(radius, incoming / 2, outgoing / 2)

    if (cornerRadius <= 0) {
      path += ` L${formatPoint(current)}`
      continue
    }

    const before = pointToward(current, prev, cornerRadius)
    const after = pointToward(current, next, cornerRadius)
    path += ` L${formatPoint(before)} Q${formatPoint(current)} ${formatPoint(after)}`
  }
  path += ` L${formatPoint(points[points.length - 1]!)}`
  return path
}

function longestSegmentMidpoint(points: Point[]): Point {
  if (points.length === 0) return { x: 0, y: 0 }
  if (points.length === 1) return points[0]!

  let bestStart = points[0]!
  let bestEnd = points[1]!
  let bestLength = distance(bestStart, bestEnd)
  for (let i = 2; i < points.length; i++) {
    const start = points[i - 1]!
    const end = points[i]!
    const length = distance(start, end)
    if (length > bestLength) {
      bestStart = start
      bestEnd = end
      bestLength = length
    }
  }

  return {
    x: (bestStart.x + bestEnd.x) / 2,
    y: (bestStart.y + bestEnd.y) / 2,
  }
}

function pointToward(from: Point, to: Point, amount: number): Point {
  const length = distance(from, to)
  if (length === 0) return from
  return {
    x: from.x + ((to.x - from.x) / length) * amount,
    y: from.y + ((to.y - from.y) / length) * amount,
  }
}

function compactPoints(points: Point[]): Point[] {
  return points.filter((point, index) => {
    if (index === 0) return true
    const prev = points[index - 1]!
    return !nearlyEqual(point.x, prev.x) || !nearlyEqual(point.y, prev.y)
  })
}

function distance(a: Point, b: Point): number {
  return Math.hypot(b.x - a.x, b.y - a.y)
}

function formatPoint(point: Point): string {
  return `${formatNumber(point.x)},${formatNumber(point.y)}`
}

function formatNumber(n: number): string {
  return Number(n.toFixed(1)).toString()
}

function nearlyEqual(a: number, b: number): boolean {
  return Math.abs(a - b) < 0.5
}
