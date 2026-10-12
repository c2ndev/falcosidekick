import type { Event } from "@/lib/types"

import type { Identity } from "./identity"
import type { Phase } from "./phases"
import { phaseOrder } from "./phases"
import type {
  ActorCluster,
  AttackNarrative,
  MatchResult,
  NarrativeContext,
  PhasedEvent,
  ThreatEdge,
} from "./types"

// --- helpers ---

function timeMs(evt: Event): number {
  const t = Date.parse(evt.time)
  return Number.isFinite(t) ? t : 0
}

function formatDelta(ms: number): string {
  if (ms < 1000) return `${ms}ms`
  const s = Math.round(ms / 1000)
  if (s < 60) return `+${s}s`
  const m = Math.round(s / 60)
  if (m < 60) return `+${m}m`
  const h = Math.round(m / 60)
  return `+${h}h`
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

function distinctPhases(events: readonly PhasedEvent[]): Phase[] {
  const seen = new Set<Phase>()
  const out: Phase[] = []
  for (const e of events) {
    if (!seen.has(e.phase)) {
      seen.add(e.phase)
      out.push(e.phase)
    }
  }
  return out
}

function distinctMitre(events: readonly PhasedEvent[]): string[] {
  const seen = new Set<string>()
  for (const e of events) seen.add(e.mitre)
  return Array.from(seen)
}

function distinctHosts(events: readonly PhasedEvent[]): string[] {
  const hosts = new Set<string>()
  for (const e of events) if (e.event.hostname) hosts.add(e.event.hostname)
  return Array.from(hosts)
}

function findOrderedPhaseWindow(
  events: readonly PhasedEvent[],
  required: readonly Phase[],
  windowMs: number,
): { core: PhasedEvent[]; full: PhasedEvent[] } | null {
  if (required.length === 0) return null
  for (let start = 0; start < events.length; start++) {
    if (events[start]!.phase !== required[0]) continue
    const anchor = timeMs(events[start]!.event)
    const core: PhasedEvent[] = [events[start]!]
    let reqIdx = 1
    let lastEnd = start
    for (let i = start + 1; i < events.length && reqIdx < required.length; i++) {
      if (timeMs(events[i]!.event) - anchor > windowMs) break
      if (events[i]!.phase === required[reqIdx]) {
        core.push(events[i]!)
        reqIdx++
        lastEnd = i
      }
    }
    if (reqIdx === required.length) {
      return { core, full: events.slice(start, lastEnd + 1) }
    }
  }
  return null
}

function fullChainEdges(full: readonly PhasedEvent[], core: readonly PhasedEvent[]): ThreatEdge[] {
  const coreKeys = new Set<string>()
  for (let i = 1; i < core.length; i++) {
    coreKeys.add(`${core[i - 1]!.event.uuid}->${core[i]!.event.uuid}`)
  }
  const edges: ThreatEdge[] = []
  for (let i = 1; i < full.length; i++) {
    const a = full[i - 1]!
    const b = full[i]!
    const delta = formatDelta(timeMs(b.event) - timeMs(a.event))
    const isCoreTransition = coreKeys.has(`${a.event.uuid}->${b.event.uuid}`)
    if (isCoreTransition) {
      edges.push({
        from: a.event.uuid,
        to: b.event.uuid,
        kind: "escalation",
        label: `${a.phase} → ${b.phase}`,
        detail: delta,
        tooltip: `${a.phase} (${a.mitre}) followed by ${b.phase} (${b.mitre}) ${delta} later — narrative-required transition.`,
      })
    } else {
      edges.push({
        from: a.event.uuid,
        to: b.event.uuid,
        kind: "temporal",
        label: a.phase === b.phase ? a.phase : `${a.phase} → ${b.phase}`,
        detail: delta,
        tooltip: `${a.phase} (${a.mitre}) → ${b.phase} (${b.mitre}), ${delta} later in the same actor timeline.`,
      })
    }
  }
  return edges
}

function baseConfidence(
  core: readonly PhasedEvent[],
  required: readonly Phase[],
  windowMs: number,
): number {
  const coverage = core.length / Math.max(1, required.length)
  const span = timeMs(core[core.length - 1]!.event) - timeMs(core[0]!.event)
  const tightness = 1 - Math.min(1, span / Math.max(1, windowMs))
  const avgRule = core.reduce((s, e) => s + e.confidence, 0) / core.length
  return Math.min(1, 0.35 * coverage + 0.3 * tightness + 0.35 * avgRule)
}

function actorLabel(actor: Identity | null): string {
  if (!actor) return "unknown actor"
  if (actor.user && actor.host) return `${actor.user}@${actor.host}`
  if (actor.user) return actor.user
  if (actor.container) return `container ${actor.container}`
  if (actor.proc) return `proc ${actor.proc}`
  if (actor.host) return `host ${actor.host}`
  return "unknown actor"
}

function orderedPhaseMatcher(params: {
  required: readonly Phase[]
  windowMs: number
  extraCheck?: (core: PhasedEvent[], full: PhasedEvent[]) => boolean
  reasonFor: (core: PhasedEvent[]) => string
}): AttackNarrative["match"] {
  return (cluster) => {
    const win = findOrderedPhaseWindow(cluster.events, params.required, params.windowMs)
    if (!win) return null
    if (params.extraCheck && !params.extraCheck(win.core, win.full)) return null
    return {
      events: win.full,
      phases: distinctPhases(win.full),
      mitre: distinctMitre(win.full),
      edges: fullChainEdges(win.full, win.core),
      confidence:
        Math.round(baseConfidence(win.core, params.required, params.windowMs) * 100) / 100,
      reason: params.reasonFor(win.core),
      hosts: distinctHosts(win.full),
    }
  }
}

// --- catalog ---

const credentialAccessThenC2: AttackNarrative = {
  id: "credential-access-then-c2",
  name: "Credential theft → C2 / exfil",
  description:
    "An actor read a sensitive secret file and then opened an outbound connection within the same process tree.",
  severityBase: "critical",
  mitre: ["T1552", "T1041", "T1071"],
  identityBinding: "proc-tree",
  windowMs: 10 * 60_000,
  minEvents: 2,
  requiredPhases: ["credential-access", "c2"],
  suggestedAction:
    "Isolate the host, rotate the exposed credentials, review outbound destinations.",
  match: orderedPhaseMatcher({
    required: ["credential-access", "c2"],
    windowMs: 10 * 60_000,
    reasonFor: (core) => {
      const dst = field(core[1]!.event, "fd.rip", "fd.name") ?? "unknown peer"
      const file = field(core[0]!.event, "fd.name") ?? "sensitive file"
      return `Read ${file} → outbound to ${dst} (${formatDelta(timeMs(core[1]!.event) - timeMs(core[0]!.event))})`
    },
  }),
  narrative: (match, actor) =>
    `${actorLabel(actor)} read a sensitive file (${match.mitre[0]}) and immediately opened a C2-class outbound connection. Canonical credential-exfil narrative.`,
}

const reverseShell: AttackNarrative = {
  id: "reverse-shell",
  name: "Reverse shell",
  description:
    "An interactive shell spawned inside a container was followed by an outbound connection from the same process tree.",
  severityBase: "high",
  mitre: ["T1059", "T1071"],
  identityBinding: "proc-tree",
  windowMs: 5 * 60_000,
  minEvents: 2,
  requiredPhases: ["execution", "c2"],
  suggestedAction: "Kill the shell process, snapshot the container, block the outbound peer.",
  match: orderedPhaseMatcher({
    required: ["execution", "c2"],
    windowMs: 5 * 60_000,
    reasonFor: (core) =>
      `Shell spawn → outbound (${formatDelta(timeMs(core[1]!.event) - timeMs(core[0]!.event))})`,
  }),
  narrative: (_m, actor) =>
    `${actorLabel(actor)} spawned an interactive shell and then initiated an outbound connection from the same process tree (T1059 + T1071).`,
}

const containerBreakout: AttackNarrative = {
  id: "container-breakout",
  name: "Container breakout",
  description:
    "A privileged container performed a namespace change and wrote to a host-persistence path.",
  severityBase: "high",
  mitre: ["T1611"],
  identityBinding: "container",
  windowMs: 5 * 60_000,
  minEvents: 2,
  requiredPhases: ["privilege-escalation", "persistence"],
  suggestedAction:
    "Terminate the container, inspect host filesystem for dropped artifacts, review admission policies.",
  match: orderedPhaseMatcher({
    required: ["privilege-escalation", "persistence"],
    windowMs: 5 * 60_000,
    reasonFor: (core) => {
      const target = field(core[1]!.event, "fd.name") ?? "host path"
      return `Privilege escalation → write to ${target}`
    },
  }),
  narrative: (_m, actor) =>
    `${actorLabel(actor)} performed a privileged action and wrote to a persistence-class host path in the same window (T1611).`,
}

const lateralWithCreds: AttackNarrative = {
  id: "lateral-with-creds",
  name: "Lateral movement with stolen credentials",
  description:
    "The same user identity read a sensitive credential on one host, then executed on a different host.",
  severityBase: "critical",
  mitre: ["T1552", "T1078", "T1021"],
  identityBinding: "user",
  windowMs: 30 * 60_000,
  minEvents: 2,
  requiredPhases: ["credential-access", "execution"],
  suggestedAction:
    "Rotate the user's credentials cluster-wide, revoke active sessions on all hosts.",
  match: orderedPhaseMatcher({
    required: ["credential-access", "execution"],
    windowMs: 30 * 60_000,
    extraCheck: (core) => {
      const a = core[0]!.event.hostname
      const b = core[1]!.event.hostname
      return !!a && !!b && a !== b
    },
    reasonFor: (core) =>
      `${core[0]!.event.hostname} → ${core[1]!.event.hostname} (${formatDelta(timeMs(core[1]!.event) - timeMs(core[0]!.event))})`,
  }),
  narrative: (_m, actor) =>
    `${actorLabel(actor)} read a credential on one host and then executed on a different host (T1552 → T1078 → T1021).`,
}

const persistAfterPrivesc: AttackNarrative = {
  id: "persist-after-privesc",
  name: "Persistence after privilege escalation",
  description:
    "A privilege-escalation event was followed by a write to a persistence-class path.",
  severityBase: "high",
  mitre: ["T1068", "T1547"],
  identityBinding: "host+user",
  windowMs: 15 * 60_000,
  minEvents: 2,
  requiredPhases: ["privilege-escalation", "persistence"],
  suggestedAction:
    "Audit cron / systemd units / authorized_keys on the host; re-image if scope is unclear.",
  match: orderedPhaseMatcher({
    required: ["privilege-escalation", "persistence"],
    windowMs: 15 * 60_000,
    reasonFor: (core) => {
      const host = core[0]!.event.hostname ?? "?"
      const target = field(core[1]!.event, "fd.name") ?? "persistence path"
      return `${host}: privesc → ${target}`
    },
  }),
  narrative: (_m, actor) =>
    `${actorLabel(actor)} escalated privileges and then installed persistence (cron, systemd unit, shell rc, or authorized_keys). T1068 → T1547.`,
}

const defenseEvasionAfterExec: AttackNarrative = {
  id: "defense-evasion-after-exec",
  name: "Defense evasion after execution",
  description:
    "An execution event was followed by a log-clearing or history-wipe action from the same process tree.",
  severityBase: "high",
  mitre: ["T1059", "T1070"],
  identityBinding: "proc-tree",
  windowMs: 10 * 60_000,
  minEvents: 2,
  requiredPhases: ["execution", "defense-evasion"],
  suggestedAction:
    "Preserve existing logs from durable storage, correlate with upstream shipping.",
  match: orderedPhaseMatcher({
    required: ["execution", "defense-evasion"],
    windowMs: 10 * 60_000,
    reasonFor: (core) => `exec → ${core[1]!.event.rule}`,
  }),
  narrative: (_m, actor) =>
    `${actorLabel(actor)} executed and then attempted to wipe logs or history — classic defense-evasion cover-up (T1070).`,
}

const k8sPrivAbuse: AttackNarrative = {
  id: "k8s-priv-abuse",
  name: "Kubernetes privilege abuse",
  description: "A privileged container performed API-server-class discovery from inside the pod.",
  severityBase: "high",
  mitre: ["T1610", "T1611"],
  identityBinding: "container",
  windowMs: 10 * 60_000,
  minEvents: 2,
  requiredPhases: ["privilege-escalation", "discovery"],
  suggestedAction:
    "Review pod SecurityContext, check API audit logs, rotate the service account.",
  match: orderedPhaseMatcher({
    required: ["privilege-escalation", "discovery"],
    windowMs: 10 * 60_000,
    reasonFor: (core) => {
      const peer = field(core[1]!.event, "fd.sip", "fd.name") ?? "K8s API"
      return `privileged pod → ${peer}`
    },
  }),
  narrative: (_m, actor) =>
    `${actorLabel(actor)} ran privileged and then contacted the K8s API / cloud metadata (T1610 / T1611).`,
}

const k8sServiceAccountAbuse: AttackNarrative = {
  id: "k8s-serviceaccount-abuse",
  name: "Kubernetes service-account token abuse",
  description:
    "A container read its projected service-account token and then talked to the Kubernetes API.",
  severityBase: "high",
  mitre: ["T1552.005", "T1078"],
  identityBinding: "container",
  windowMs: 10 * 60_000,
  minEvents: 2,
  requiredPhases: ["credential-access", "discovery"],
  suggestedAction:
    "Rotate the service-account token, check RBAC for over-privileged bindings.",
  match: orderedPhaseMatcher({
    required: ["credential-access", "discovery"],
    windowMs: 10 * 60_000,
    extraCheck: (core) => /serviceaccount|token/i.test(field(core[0]!.event, "fd.name") ?? ""),
    reasonFor: (core) =>
      `SA token → ${field(core[1]!.event, "fd.sip", "fd.name") ?? "K8s API"}`,
  }),
  narrative: (_m, actor) =>
    `${actorLabel(actor)} read a projected service-account token and then contacted the K8s API (T1552.005 + T1078).`,
}

const sudoPrivescChain: AttackNarrative = {
  id: "sudo-privesc-chain",
  name: "Sudo-driven privilege escalation chain",
  description:
    "A sudo-based privilege escalation was followed by a persistence write on the same host and user.",
  severityBase: "high",
  mitre: ["T1548.003", "T1547"],
  identityBinding: "host+user",
  windowMs: 15 * 60_000,
  minEvents: 2,
  requiredPhases: ["privilege-escalation", "persistence"],
  suggestedAction: "Audit sudoers, review cron/rc files, rotate the user's credential.",
  match: orderedPhaseMatcher({
    required: ["privilege-escalation", "persistence"],
    windowMs: 15 * 60_000,
    extraCheck: (core) => /sudo/i.test(core[0]!.event.rule ?? ""),
    reasonFor: (core) =>
      `sudo escalation on ${core[0]!.event.hostname ?? "?"} → ${field(core[1]!.event, "fd.name") ?? "persistence path"}`,
  }),
  narrative: (_m, actor) =>
    `${actorLabel(actor)} used sudo to escalate and then installed persistence (T1548.003 → T1547).`,
}

const cryptomining: AttackNarrative = {
  id: "cryptomining",
  name: "Cryptomining activity",
  description: "A process matched a known miner binary or mining-pool destination.",
  severityBase: "med",
  mitre: ["T1496"],
  identityBinding: "proc-tree",
  windowMs: 5 * 60_000,
  minEvents: 1,
  requiredPhases: ["impact"],
  suggestedAction:
    "Kill the miner process, quarantine the container image, review deployment manifest.",
  match: (cluster) => {
    const miners = cluster.events.filter((e) => e.phase === "impact")
    if (miners.length === 0) return null
    const edges: ThreatEdge[] = []
    for (let i = 1; i < miners.length; i++) {
      const a = miners[i - 1]!
      const b = miners[i]!
      edges.push({
        from: a.event.uuid,
        to: b.event.uuid,
        kind: "temporal",
        label: "mining activity",
        detail: formatDelta(timeMs(b.event) - timeMs(a.event)),
      })
    }
    return {
      events: miners,
      phases: ["impact"],
      mitre: distinctMitre(miners),
      edges,
      confidence: Math.min(1, 0.6 + 0.05 * miners.length),
      reason: `${miners.length} impact-class event(s) indicative of mining`,
      hosts: distinctHosts(miners),
    }
  },
  narrative: (match, actor) =>
    `${actorLabel(actor)} is associated with ${match.events.length} impact-class event(s) matching known crypto-mining signatures (T1496).`,
}

const massRecon: AttackNarrative = {
  id: "mass-recon",
  name: "Mass reconnaissance",
  description: "A single actor emitted many discovery-class events in a tight window.",
  severityBase: "med",
  mitre: ["T1083", "T1087"],
  identityBinding: "proc-tree",
  windowMs: 2 * 60_000,
  minEvents: 8,
  requiredPhases: ["discovery"],
  suggestedAction:
    "Watch for follow-on credential access or execution from the same process tree.",
  match: (cluster) => {
    const discovery = cluster.events.filter((e) => e.phase === "discovery")
    if (discovery.length < 8) return null
    const span = timeMs(discovery[discovery.length - 1]!.event) - timeMs(discovery[0]!.event)
    if (span > 2 * 60_000) return null
    const edges: ThreatEdge[] = []
    for (let i = 1; i < Math.min(discovery.length, 6); i++) {
      const a = discovery[i - 1]!
      const b = discovery[i]!
      edges.push({
        from: a.event.uuid,
        to: b.event.uuid,
        kind: "temporal",
        label: "recon",
        detail: formatDelta(timeMs(b.event) - timeMs(a.event)),
      })
    }
    return {
      events: discovery,
      phases: ["discovery"],
      mitre: distinctMitre(discovery),
      edges,
      confidence: Math.min(1, 0.5 + 0.03 * discovery.length),
      reason: `${discovery.length} discovery events in ${formatDelta(span)}`,
      hosts: distinctHosts(discovery),
    }
  },
  narrative: (match, actor) =>
    `${actorLabel(actor)} fired ${match.events.length} discovery-class events in a tight window.`,
}

const compromiseAndPivot: AttackNarrative = {
  id: "compromise-and-pivot",
  name: "Compromise and pivot",
  description:
    "A privilege-escalation on one host was followed by execution on a different host by the same user — a mixed chain-plus-star attack.",
  severityBase: "critical",
  mitre: ["T1068", "T1021", "T1059"],
  identityBinding: "user",
  windowMs: 30 * 60_000,
  minEvents: 2,
  requiredPhases: ["privilege-escalation", "execution"],
  suggestedAction:
    "Isolate both hosts, rotate the user's credential cluster-wide, review lateral-movement artifacts.",
  match: orderedPhaseMatcher({
    required: ["privilege-escalation", "execution"],
    windowMs: 30 * 60_000,
    extraCheck: (core) => {
      const a = core[0]!.event.hostname
      const b = core[1]!.event.hostname
      return !!a && !!b && a !== b
    },
    reasonFor: (core) =>
      `${core[0]!.event.hostname} (privesc) → ${core[1]!.event.hostname} (exec)`,
  }),
  narrative: (_m, actor) =>
    `${actorLabel(actor)} escalated on one host and then executed on a different host (T1068 → T1021 → T1059).`,
}

export const NARRATIVES: readonly AttackNarrative[] = [
  credentialAccessThenC2,
  reverseShell,
  containerBreakout,
  lateralWithCreds,
  persistAfterPrivesc,
  defenseEvasionAfterExec,
  k8sPrivAbuse,
  k8sServiceAccountAbuse,
  sudoPrivescChain,
  cryptomining,
  massRecon,
  compromiseAndPivot,
]

export function narrativeById(id: string): AttackNarrative | undefined {
  return NARRATIVES.find((n) => n.id === id)
}

export function phaseOrderFn(p: Phase): number {
  return phaseOrder(p)
}

export type { ActorCluster, MatchResult, NarrativeContext }
