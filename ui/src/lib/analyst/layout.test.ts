import { Position } from "@xyflow/react"
import { describe, expect, test } from "bun:test"

import type { Event } from "@/lib/types"

import { layoutThreatGraph } from "./layout"
import type { Threat } from "./types"

function event(uuid: string, offsetS: number): Event {
  return {
    uuid,
    output: "sample",
    priority: "warning",
    rule: `rule ${uuid}`,
    time: new Date(Date.UTC(2026, 3, 27, 9, 0, offsetS)).toISOString(),
    output_fields: {},
    source: "syscall",
    hostname: "web-01",
  }
}

function chainThreat(count: number): Threat {
  const events = Array.from({ length: count }, (_, i) => event(`u-${i + 1}`, i))
  return {
    id: "chain",
    patternId: "chain",
    patternName: "Chain",
    patternDescription: "test",
    severity: "med",
    entityLabel: "web-01",
    firstTime: events[0]!.time,
    lastTime: events[events.length - 1]!.time,
    events,
    edges: events.slice(1).map((evt, i) => ({
      from: events[i]!.uuid,
      to: evt.uuid,
      kind: "temporal",
      label: "time",
    })),
    confidence: 1,
    reason: "test",
    phases: [],
    mitre: [],
    narrative: "test",
    suggestedAction: "test",
    actor: null,
  }
}

describe("layoutThreatGraph", () => {
  test("lays chain threats into a compact two-column grid", async () => {
    const layout = await layoutThreatGraph(chainThreat(6), 270, 96)

    expect(layout.pathType).toBe("orthogonal")
    expect(layout.nodes.map((node) => [node.id, node.x, node.y])).toEqual([
      ["u-1", 0, 0],
      ["u-2", 570, 0],
      ["u-3", 0, 216],
      ["u-4", 570, 216],
      ["u-5", 0, 432],
      ["u-6", 570, 432],
    ])
  })

  test("uses bottom-to-top handles for row wraps", async () => {
    const layout = await layoutThreatGraph(chainThreat(4), 270, 96)

    expect(layout.edges.map((edge) => [edge.sourcePosition, edge.targetPosition])).toEqual([
      [Position.Right, Position.Left],
      [Position.Bottom, Position.Top],
      [Position.Right, Position.Left],
    ])
  })
})
