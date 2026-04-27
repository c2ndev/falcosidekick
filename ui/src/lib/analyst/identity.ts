import type { Event } from "@/lib/types"

/**
 * Users that appear on every host in every cluster and carry no attack-actor
 * signal by themselves. When an event reports `user.name=root` we treat the
 * user slot as unknown, not as correlation binding. A compromise involving
 * root still correlates through process tree or container id.
 */
export const SYSTEM_USERS: ReadonlySet<string> = new Set([
  "root",
  "nobody",
  "daemon",
  "systemd",
  "systemd-network",
  "systemd-resolve",
  "systemd-timesync",
  "kubelet",
  "containerd",
  "docker",
  "runc",
  "init",
  "sshd",
  "dbus",
  "syslog",
  "messagebus",
])

/**
 * Process names that appear as the parent of half the cluster's events and
 * carry no attack-actor signal. `proc.pname=bash` or `proc.pname=systemd`
 * by itself cannot tie two events together.
 */
export const SYSTEM_PROCS: ReadonlySet<string> = new Set([
  "systemd",
  "kubelet",
  "containerd-shim",
  "containerd",
  "dockerd",
  "docker",
  "runc",
  "init",
  "sshd",
  "bash",
  "sh",
  "zsh",
  "cron",
  "crond",
  "login",
])

export interface Identity {
  host: string | null
  /** `null` if the event's user is in SYSTEM_USERS. */
  user: string | null
  /** `null` if the event's proc.pname is in SYSTEM_PROCS. */
  proc: string | null
  /** Ancestor process (proc.aname / proc.aname[2]); nullable for the same reason as `proc`. */
  ancestor: string | null
  /** Short (12-char) container id; `null` if none reported. */
  container: string | null
}

function field(evt: Event, ...keys: string[]): string | undefined {
  const fields = evt.output_fields ?? {}
  for (const k of keys) {
    const v = (fields as Record<string, unknown>)[k]
    if (typeof v === "string" && v.length > 0) return v
    if (typeof v === "number") return String(v)
  }
  return undefined
}

function shortContainer(cid: string | undefined): string | null {
  if (!cid) return null
  return cid.length > 12 ? cid.slice(0, 12) : cid
}

function significantUser(name: string | undefined): string | null {
  if (!name) return null
  return SYSTEM_USERS.has(name) ? null : name
}

function significantProc(name: string | undefined): string | null {
  if (!name) return null
  return SYSTEM_PROCS.has(name) ? null : name
}

export function fingerprint(evt: Event): Identity {
  return {
    host: evt.hostname ?? null,
    user: significantUser(field(evt, "user.name", "user")),
    proc: significantProc(field(evt, "proc.pname", "proc.name")),
    ancestor: significantProc(field(evt, "proc.aname[2]", "proc.aname")),
    container: shortContainer(field(evt, "container.id")),
  }
}

/**
 * Two events share an actor when at least one **non-null** identity slot
 * matches. System accounts and system process names (null slots) never bind.
 */
export function sameActor(a: Identity, b: Identity): boolean {
  if (a.user !== null && a.user === b.user) return true
  if (a.proc !== null && a.proc === b.proc) return true
  if (a.ancestor !== null && a.ancestor === b.ancestor) return true
  if (a.container !== null && a.container === b.container) return true
  return false
}

/** Matches the caller-facing narrative `identityBinding` discriminator. */
export type IdentityBinding = "proc-tree" | "container" | "user" | "host" | "host+user"

/**
 * Returns a stable grouping key for narrative matching. A `null` return means
 * the event carries no actor signal under this binding and must be skipped.
 */
export function bindingKey(id: Identity, binding: IdentityBinding): string | null {
  switch (binding) {
    case "proc-tree": {
      if (id.proc) return `proc:${id.proc}`
      if (id.ancestor) return `anc:${id.ancestor}`
      if (id.container) return `cnt:${id.container}`
      return null
    }
    case "container":
      return id.container ? `cnt:${id.container}` : null
    case "user":
      return id.user ? `usr:${id.user}` : null
    case "host":
      return id.host ? `host:${id.host}` : null
    case "host+user":
      if (!id.host || !id.user) return null
      return `host:${id.host}|usr:${id.user}`
  }
}

/** True iff `id` matches any concrete (non-null) slot of `other`. */
export function overlaps(id: Identity, other: Identity): boolean {
  return sameActor(id, other) || (id.host !== null && id.host === other.host)
}

/** Human-readable short label of the most specific identity slot available. */
export function identityLabel(id: Identity): string {
  if (id.user && id.host) return `${id.user} @ ${id.host}`
  if (id.user) return id.user
  if (id.container) return `container ${id.container}`
  if (id.proc) return `proc ${id.proc}`
  if (id.host) return `host ${id.host}`
  return "unknown actor"
}
