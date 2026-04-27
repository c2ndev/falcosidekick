import { describe, expect, test } from "bun:test"

import type { Event, Priority } from "@/lib/types"

import { fingerprint, SYSTEM_PROCS, SYSTEM_USERS, sameActor } from "./identity"
import { NARRATIVES } from "./narratives"
import { classifyEvent, containsOrdered, phaseOrder } from "./phases"

// --- Test helpers ---

let nextId = 0

function evt(o: {
  rule: string
  offsetS: number
  priority?: Priority
  hostname?: string
  fields?: Record<string, unknown>
  tags?: string[]
}): Event {
  nextId += 1
  return {
    uuid: `u-${nextId}`,
    output: "sample",
    priority: o.priority ?? "warning",
    rule: o.rule,
    time: new Date(Date.now() - o.offsetS * 1000).toISOString(),
    output_fields: o.fields ?? {},
    source: "syscall",
    hostname: o.hostname,
    tags: o.tags,
  }
}

// --- phases classifier ---

describe("classifyEvent", () => {
  test("sensitive file → credential-access T1552", () => {
    const e = evt({
      rule: "Read sensitive file untrusted",
      offsetS: 10,
      fields: { "fd.name": "/etc/shadow" },
    })
    const c = classifyEvent(e)
    expect(c?.phase).toBe("credential-access")
    expect(c?.mitre).toBe("T1552")
  })

  test("read sensitive file but non-sensitive path → discovery T1083", () => {
    const e = evt({
      rule: "Read sensitive file untrusted",
      offsetS: 10,
      fields: { "fd.name": "/var/log/syslog" },
    })
    const c = classifyEvent(e)
    expect(c?.phase).toBe("discovery")
    expect(c?.mitre).toBe("T1083")
  })

  test("terminal shell in container → execution T1059", () => {
    const c = classifyEvent(evt({ rule: "Terminal shell in container", offsetS: 0 }))
    expect(c?.phase).toBe("execution")
    expect(c?.mitre).toBe("T1059")
  })

  test("launch privileged container → privilege-escalation T1611", () => {
    const c = classifyEvent(evt({ rule: "Launch Privileged Container", offsetS: 0 }))
    expect(c?.phase).toBe("privilege-escalation")
    expect(c?.mitre).toBe("T1611")
  })

  test("change thread namespace → privilege-escalation", () => {
    const c = classifyEvent(evt({ rule: "Change thread namespace", offsetS: 0 }))
    expect(c?.phase).toBe("privilege-escalation")
  })

  test("write below etc with cron path → persistence T1547", () => {
    const c = classifyEvent(
      evt({
        rule: "Write below etc",
        offsetS: 0,
        fields: { "fd.name": "/etc/cron.d/backdoor" },
      }),
    )
    expect(c?.phase).toBe("persistence")
    expect(c?.mitre).toBe("T1547")
  })

  test("write below etc with generic path → defense-evasion fallback", () => {
    const c = classifyEvent(
      evt({
        rule: "Write below etc",
        offsetS: 0,
        fields: { "fd.name": "/etc/foo.conf" },
      }),
    )
    expect(c?.phase).toBe("defense-evasion")
  })

  test("outbound connection → c2 T1071", () => {
    const c = classifyEvent(
      evt({ rule: "Unexpected outbound connection", offsetS: 0 }),
    )
    expect(c?.phase).toBe("c2")
  })

  test("clear log activities → defense-evasion T1070", () => {
    const c = classifyEvent(evt({ rule: "Clear Log Activities", offsetS: 0 }))
    expect(c?.phase).toBe("defense-evasion")
    expect(c?.mitre).toBe("T1070")
  })

  test("contact K8s API (field-matched) → discovery T1613", () => {
    const c = classifyEvent(
      evt({
        rule: "Contact K8S API Server From Container",
        offsetS: 0,
        fields: { "fd.sip": "10.96.0.1" },
      }),
    )
    expect(c?.phase).toBe("discovery")
  })

  test("sudo escalation → privilege-escalation T1548.003", () => {
    const c = classifyEvent(
      evt({ rule: "Sudo Potential Privilege Escalation", offsetS: 0 }),
    )
    expect(c?.phase).toBe("privilege-escalation")
    expect(c?.mitre).toBe("T1548.003")
  })

  test("miner cmdline catch-all → impact T1496", () => {
    const c = classifyEvent(
      evt({ rule: "Any rule", offsetS: 0, fields: { "proc.cmdline": "xmrig --pool=..." } }),
    )
    expect(c?.phase).toBe("impact")
    expect(c?.mitre).toBe("T1496")
  })

  test("unknown rule → null", () => {
    const c = classifyEvent(evt({ rule: "Completely unknown rule name", offsetS: 0 }))
    expect(c).toBeNull()
  })

  test("phaseOrder puts execution before impact", () => {
    expect(phaseOrder("execution")).toBeLessThan(phaseOrder("impact"))
  })

  test("containsOrdered respects order", () => {
    expect(containsOrdered(["execution", "c2"], ["execution", "c2"])).toBe(true)
    expect(containsOrdered(["c2", "execution"], ["execution", "c2"])).toBe(false)
    expect(
      containsOrdered(["execution", "discovery", "c2"], ["execution", "c2"]),
    ).toBe(true)
  })
})

// --- identity ---

describe("fingerprint + sameActor", () => {
  test("non-system user binds", () => {
    const a = fingerprint(evt({ rule: "x", offsetS: 0, fields: { "user.name": "alice" } }))
    const b = fingerprint(evt({ rule: "y", offsetS: 0, fields: { "user.name": "alice" } }))
    expect(a.user).toBe("alice")
    expect(sameActor(a, b)).toBe(true)
  })

  test("root never binds", () => {
    const a = fingerprint(evt({ rule: "x", offsetS: 0, fields: { "user.name": "root" } }))
    const b = fingerprint(evt({ rule: "y", offsetS: 0, fields: { "user.name": "root" } }))
    expect(a.user).toBeNull()
    expect(sameActor(a, b)).toBe(false)
  })

  test("SYSTEM_USERS covers kubelet and systemd", () => {
    expect(SYSTEM_USERS.has("kubelet")).toBe(true)
    expect(SYSTEM_USERS.has("systemd")).toBe(true)
  })

  test("SYSTEM_PROCS covers systemd and containerd-shim", () => {
    expect(SYSTEM_PROCS.has("systemd")).toBe(true)
    expect(SYSTEM_PROCS.has("containerd-shim")).toBe(true)
  })

  test("container id binds even when users are both system", () => {
    const a = fingerprint(
      evt({
        rule: "x",
        offsetS: 0,
        fields: { "user.name": "root", "container.id": "abc123def456" },
      }),
    )
    const b = fingerprint(
      evt({
        rule: "y",
        offsetS: 0,
        fields: { "user.name": "root", "container.id": "abc123def456" },
      }),
    )
    expect(sameActor(a, b)).toBe(true)
  })
})

// --- Per-narrative catalog sanity ---

describe("NARRATIVES catalog", () => {
  test("exactly 12 narratives", () => {
    expect(NARRATIVES).toHaveLength(12)
  })

  test("all ids are unique", () => {
    const ids = new Set(NARRATIVES.map((n) => n.id))
    expect(ids.size).toBe(NARRATIVES.length)
  })

  test("all required fields populated", () => {
    for (const n of NARRATIVES) {
      expect(n.name).toBeTruthy()
      expect(n.mitre.length).toBeGreaterThan(0)
      expect(n.suggestedAction).toBeTruthy()
      expect(n.description).toBeTruthy()
      expect(n.windowMs).toBeGreaterThan(0)
    }
  })
})
