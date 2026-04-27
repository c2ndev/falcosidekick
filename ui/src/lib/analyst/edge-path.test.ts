import { Position } from "@xyflow/react"
import { describe, expect, test } from "bun:test"

import { getRoundedOrthogonalPath } from "./edge-path"

describe("getRoundedOrthogonalPath", () => {
  test("routes bottom-to-top wraps as down-left-down with rounded corners", () => {
    const [path, labelX, labelY] = getRoundedOrthogonalPath({
      sourceX: 405,
      sourceY: 96,
      targetX: 135,
      targetY: 276,
      sourcePosition: Position.Bottom,
      targetPosition: Position.Top,
      borderRadius: 12,
    })

    expect(path).toBe(
      "M405,96 L405,174 Q405,186 393,186 L147,186 Q135,186 135,198 L135,276",
    )
    expect(labelX).toBe(270)
    expect(labelY).toBe(186)
  })

  test("centres labels on straight horizontal edges", () => {
    const [path, labelX, labelY] = getRoundedOrthogonalPath({
      sourceX: 270,
      sourceY: 48,
      targetX: 570,
      targetY: 48,
      sourcePosition: Position.Right,
      targetPosition: Position.Left,
    })

    expect(path).toBe("M270,48 L570,48")
    expect(labelX).toBe(420)
    expect(labelY).toBe(48)
  })
})
