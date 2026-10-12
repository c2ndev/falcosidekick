import { describe, expect, test } from "bun:test"

import type { Event, Priority } from "@/lib/types"

import { correlate } from "./correlate"

let nextId = 0
function evt(o: {
  rule: string
  offsetS: number
  priority?: Priority
  hostname?: string
  fields?: Record<string, unknown>
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
  }
}

describe("correlate — engine-level", () => {
  test("empty input returns nothing", () => {
    expect(correlate([])).toEqual([])
  })

  test("events classifying as no phase produce no threats", () => {
    const events = [
      evt({ rule: "Totally unknown rule foo", offsetS: 10, hostname: "h" }),
      evt({ rule: "Another unknown", offsetS: 5, hostname: "h" }),
    ]
    expect(correlate(events)).toEqual([])
  })

  test("maxThreats cap applies", () => {
    const mk = (user: string, proc: string) => [
      evt({
        rule: "Read sensitive file untrusted",
        offsetS: 30,
        fields: { "user.name": user, "proc.pname": proc, "fd.name": "/etc/shadow" },
      }),
      evt({
        rule: "Unexpected outbound connection",
        offsetS: 20,
        fields: { "user.name": user, "proc.pname": proc, "fd.rip": "203.0.113.10" },
      }),
    ]
    const events = [
      ...mk("alice", "apache2"),
      ...mk("bob", "nginx"),
      ...mk("carol", "php-fpm"),
    ]
    const threats = correlate(events, { maxThreats: 2 })
    expect(threats.length).toBeLessThanOrEqual(2)
  })

  test("backward-compat fields populated", () => {
    const events = [
      evt({
        rule: "Read sensitive file untrusted",
        offsetS: 30,
        fields: { "user.name": "alice", "proc.pname": "apache2", "fd.name": "/etc/shadow" },
      }),
      evt({
        rule: "Unexpected outbound connection",
        offsetS: 20,
        fields: { "user.name": "alice", "proc.pname": "apache2", "fd.rip": "203.0.113.10" },
      }),
    ]
    const t = correlate(events)[0]!
    expect(t.patternId).toBe("credential-access-then-c2")
    expect(t.patternName).toBeTruthy()
    expect(t.patternDescription).toBeTruthy()
    expect(t.phases).toEqual(["credential-access", "c2"])
    expect(t.mitre).toContain("T1552")
    expect(t.narrative).toContain("alice")
    expect(t.suggestedAction).toBeTruthy()
    expect(t.actor?.user).toBe("alice")
  })

  test("credential-access-then-c2 near-miss: different proc tree", () => {
    const events = [
      evt({
        rule: "Read sensitive file untrusted",
        offsetS: 30,
        fields: {
          "user.name": "alice",
          "proc.pname": "apache2",
          "fd.name": "/etc/shadow",
        },
      }),
      evt({
        rule: "Unexpected outbound connection",
        offsetS: 20,
        fields: {
          "user.name": "bob",
          "proc.pname": "nginx",
          "fd.rip": "203.0.113.5",
        },
      }),
    ]
    expect(
      correlate(events).some((t) => t.patternId === "credential-access-then-c2"),
    ).toBe(false)
  })

  test("reverse-shell positive", () => {
    const events = [
      evt({
        rule: "Terminal shell in container",
        offsetS: 10,
        fields: {
          "user.name": "bob",
          "proc.pname": "php-fpm",
          "container.id": "abc123def456",
        },
      }),
      evt({
        rule: "Unexpected outbound connection",
        offsetS: 5,
        fields: {
          "user.name": "bob",
          "proc.pname": "php-fpm",
          "container.id": "abc123def456",
        },
      }),
    ]
    expect(correlate(events).some((t) => t.patternId === "reverse-shell")).toBe(true)
  })

  test("reverse-shell near-miss: no outbound", () => {
    const events = [
      evt({
        rule: "Terminal shell in container",
        offsetS: 10,
        fields: {
          "user.name": "bob",
          "proc.pname": "php-fpm",
          "container.id": "abc123def456",
        },
      }),
    ]
    expect(correlate(events).some((t) => t.patternId === "reverse-shell")).toBe(false)
  })

  test("container-breakout positive", () => {
    const events = [
      evt({
        rule: "Change thread namespace",
        offsetS: 20,
        fields: { "container.id": "abc123def456", "user.name": "alice" },
      }),
      evt({
        rule: "Write below etc",
        offsetS: 10,
        fields: {
          "container.id": "abc123def456",
          "user.name": "alice",
          "fd.name": "/etc/cron.d/evil",
        },
      }),
    ]
    expect(correlate(events).some((t) => t.patternId === "container-breakout")).toBe(true)
  })

  test("container-breakout near-miss: different container", () => {
    const events = [
      evt({
        rule: "Change thread namespace",
        offsetS: 20,
        fields: { "container.id": "aaa111bbb222", "user.name": "alice" },
      }),
      evt({
        rule: "Write below etc",
        offsetS: 10,
        fields: {
          "container.id": "ccc333ddd444",
          "user.name": "alice",
          "fd.name": "/etc/cron.d/evil",
        },
      }),
    ]
    expect(correlate(events).some((t) => t.patternId === "container-breakout")).toBe(false)
  })

  test("lateral-with-creds positive (different hosts)", () => {
    const events = [
      evt({
        rule: "Read sensitive file untrusted",
        offsetS: 600,
        hostname: "web-01",
        fields: { "user.name": "carol", "fd.name": "/home/carol/.ssh/id_rsa" },
      }),
      evt({
        rule: "Terminal shell in container",
        offsetS: 300,
        hostname: "app-02",
        fields: { "user.name": "carol" },
      }),
    ]
    expect(correlate(events).some((t) => t.patternId === "lateral-with-creds")).toBe(true)
  })

  test("lateral-with-creds near-miss: same host", () => {
    const events = [
      evt({
        rule: "Read sensitive file untrusted",
        offsetS: 600,
        hostname: "web-01",
        fields: { "user.name": "carol", "fd.name": "/home/carol/.ssh/id_rsa" },
      }),
      evt({
        rule: "Terminal shell in container",
        offsetS: 300,
        hostname: "web-01",
        fields: { "user.name": "carol" },
      }),
    ]
    expect(correlate(events).some((t) => t.patternId === "lateral-with-creds")).toBe(false)
  })

  test("results sort critical > high > med", () => {
    const events = [
      evt({
        rule: "Read sensitive file untrusted",
        offsetS: 50,
        fields: { "user.name": "alice", "proc.pname": "apache2", "fd.name": "/etc/shadow" },
      }),
      evt({
        rule: "Unexpected outbound connection",
        offsetS: 40,
        fields: { "user.name": "alice", "proc.pname": "apache2", "fd.rip": "1.2.3.4" },
      }),
      evt({
        rule: "Terminal shell in container",
        offsetS: 10,
        fields: {
          "user.name": "bob",
          "proc.pname": "php-fpm",
          "container.id": "abc123def456",
        },
      }),
      evt({
        rule: "Unexpected outbound connection",
        offsetS: 5,
        fields: {
          "user.name": "bob",
          "proc.pname": "php-fpm",
          "container.id": "abc123def456",
        },
      }),
    ]
    const threats = correlate(events)
    expect(threats.length).toBeGreaterThanOrEqual(2)
    const rank = { low: 0, med: 1, high: 2, critical: 3 }
    for (let i = 1; i < threats.length; i++) {
      expect(rank[threats[i]!.severity]).toBeLessThanOrEqual(rank[threats[i - 1]!.severity])
    }
  })

  test("persist-after-privesc positive", () => {
    const events = [
      evt({
        rule: "Change thread namespace",
        offsetS: 120,
        hostname: "node-1",
        fields: { "user.name": "dan" },
      }),
      evt({
        rule: "Write below etc",
        offsetS: 60,
        hostname: "node-1",
        fields: { "user.name": "dan", "fd.name": "/etc/cron.daily/bd" },
      }),
    ]
    expect(correlate(events).some((t) => t.patternId === "persist-after-privesc")).toBe(true)
  })

  test("persist-after-privesc near-miss: persistence only", () => {
    const events = [
      evt({
        rule: "Write below etc",
        offsetS: 60,
        hostname: "node-1",
        fields: { "user.name": "dan", "fd.name": "/etc/cron.daily/bd" },
      }),
    ]
    expect(correlate(events).some((t) => t.patternId === "persist-after-privesc")).toBe(false)
  })

  test("defense-evasion-after-exec positive", () => {
    const events = [
      evt({
        rule: "Terminal shell in container",
        offsetS: 60,
        fields: { "user.name": "erin", "proc.pname": "apache2" },
      }),
      evt({
        rule: "Clear Log Activities",
        offsetS: 30,
        fields: { "user.name": "erin", "proc.pname": "apache2" },
      }),
    ]
    expect(
      correlate(events).some((t) => t.patternId === "defense-evasion-after-exec"),
    ).toBe(true)
  })

  test("defense-evasion-after-exec near-miss: clear only", () => {
    const events = [
      evt({
        rule: "Clear Log Activities",
        offsetS: 30,
        fields: { "user.name": "erin", "proc.pname": "apache2" },
      }),
    ]
    expect(
      correlate(events).some((t) => t.patternId === "defense-evasion-after-exec"),
    ).toBe(false)
  })

  test("k8s-priv-abuse positive", () => {
    const events = [
      evt({
        rule: "Launch Privileged Container",
        offsetS: 60,
        fields: { "container.id": "kkk111lll222" },
      }),
      evt({
        rule: "Contact K8S API Server From Container",
        offsetS: 30,
        fields: { "container.id": "kkk111lll222", "fd.sip": "10.96.0.1" },
      }),
    ]
    expect(correlate(events).some((t) => t.patternId === "k8s-priv-abuse")).toBe(true)
  })

  test("k8s-priv-abuse near-miss: only privileged", () => {
    const events = [
      evt({
        rule: "Launch Privileged Container",
        offsetS: 60,
        fields: { "container.id": "kkk111lll222" },
      }),
    ]
    expect(correlate(events).some((t) => t.patternId === "k8s-priv-abuse")).toBe(false)
  })

  test("k8s-serviceaccount-abuse positive", () => {
    const events = [
      evt({
        rule: "Read sensitive file untrusted",
        offsetS: 60,
        fields: {
          "container.id": "svc0001acct02",
          "fd.name": "/var/run/secrets/kubernetes.io/serviceaccount/token",
        },
      }),
      evt({
        rule: "Contact K8S API Server From Container",
        offsetS: 30,
        fields: { "container.id": "svc0001acct02", "fd.sip": "10.96.0.1" },
      }),
    ]
    expect(
      correlate(events).some((t) => t.patternId === "k8s-serviceaccount-abuse"),
    ).toBe(true)
  })

  test("k8s-serviceaccount-abuse near-miss: cred only", () => {
    const events = [
      evt({
        rule: "Read sensitive file untrusted",
        offsetS: 60,
        fields: {
          "container.id": "svc0001acct02",
          "fd.name": "/var/run/secrets/kubernetes.io/serviceaccount/token",
        },
      }),
    ]
    expect(
      correlate(events).some((t) => t.patternId === "k8s-serviceaccount-abuse"),
    ).toBe(false)
  })

  test("sudo-privesc-chain positive", () => {
    const events = [
      evt({
        rule: "Sudo Potential Privilege Escalation",
        offsetS: 120,
        hostname: "node-s",
        fields: { "user.name": "frank" },
      }),
      evt({
        rule: "Write below etc",
        offsetS: 60,
        hostname: "node-s",
        fields: { "user.name": "frank", "fd.name": "/etc/cron.d/b" },
      }),
    ]
    expect(correlate(events).some((t) => t.patternId === "sudo-privesc-chain")).toBe(true)
  })

  test("sudo-privesc-chain near-miss: non-sudo source", () => {
    const events = [
      evt({
        rule: "Change thread namespace",
        offsetS: 120,
        hostname: "node-s",
        fields: { "user.name": "frank" },
      }),
      evt({
        rule: "Write below etc",
        offsetS: 60,
        hostname: "node-s",
        fields: { "user.name": "frank", "fd.name": "/etc/cron.d/b" },
      }),
    ]
    expect(correlate(events).some((t) => t.patternId === "sudo-privesc-chain")).toBe(false)
  })

  test("cryptomining positive", () => {
    const events = [
      evt({
        rule: "Any rule",
        offsetS: 30,
        fields: {
          "proc.cmdline": "xmrig --pool=us-east.miner.io:3333",
          "proc.pname": "miner-worker",
          "container.id": "miner1234abcd",
        },
      }),
    ]
    expect(correlate(events).some((t) => t.patternId === "cryptomining")).toBe(true)
  })

  test("cryptomining near-miss: generic cmdline", () => {
    const events = [
      evt({
        rule: "Terminal shell in container",
        offsetS: 30,
        fields: {
          "proc.cmdline": "ls -la",
          "proc.pname": "miner-worker",
          "container.id": "miner1234abcd",
        },
      }),
    ]
    expect(correlate(events).some((t) => t.patternId === "cryptomining")).toBe(false)
  })

  test("mass-recon positive", () => {
    const events = Array.from({ length: 10 }, (_, i) =>
      evt({
        rule: "System information discovery",
        offsetS: 90 - i * 5,
        fields: { "user.name": "gail", "proc.pname": "python" },
      }),
    )
    expect(correlate(events).some((t) => t.patternId === "mass-recon")).toBe(true)
  })

  test("mass-recon near-miss: only 3 events", () => {
    const events = Array.from({ length: 3 }, (_, i) =>
      evt({
        rule: "System information discovery",
        offsetS: 90 - i * 5,
        fields: { "user.name": "gail", "proc.pname": "python" },
      }),
    )
    expect(correlate(events).some((t) => t.patternId === "mass-recon")).toBe(false)
  })

  test("compromise-and-pivot positive", () => {
    const events = [
      evt({
        rule: "Change thread namespace",
        offsetS: 600,
        hostname: "host-A",
        fields: { "user.name": "henry" },
      }),
      evt({
        rule: "Terminal shell in container",
        offsetS: 300,
        hostname: "host-B",
        fields: { "user.name": "henry" },
      }),
    ]
    expect(correlate(events).some((t) => t.patternId === "compromise-and-pivot")).toBe(true)
  })

  test("compromise-and-pivot near-miss: same host", () => {
    const events = [
      evt({
        rule: "Change thread namespace",
        offsetS: 600,
        hostname: "host-A",
        fields: { "user.name": "henry" },
      }),
      evt({
        rule: "Terminal shell in container",
        offsetS: 300,
        hostname: "host-A",
        fields: { "user.name": "henry" },
      }),
    ]
    expect(correlate(events).some((t) => t.patternId === "compromise-and-pivot")).toBe(false)
  })
})
