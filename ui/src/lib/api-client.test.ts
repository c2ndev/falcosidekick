import { afterEach, describe, expect, test } from "bun:test"

import { setAccessToken, setUnauthorizedHandler } from "./api-client"

describe("api-client state helpers", () => {
  afterEach(() => {
    setAccessToken(null)
    setUnauthorizedHandler(null)
  })

  test("setAccessToken accepts string and null without throwing", () => {
    setAccessToken("abc123")
    setAccessToken(null)
    expect(true).toBe(true)
  })

  test("setUnauthorizedHandler accepts handler and null without throwing", () => {
    const handler = () => undefined
    setUnauthorizedHandler(handler)
    setUnauthorizedHandler(null)
    expect(true).toBe(true)
  })
})
