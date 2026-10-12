import type { Event, Priority } from "@/lib/types"

import type { Identity, IdentityBinding } from "./identity"
import type { Phase } from "./phases"

export type ThreatSeverity = "low" | "med" | "high" | "critical"

export type ThreatEdgeKind = "temporal" | "shared-entity" | "escalation"

export interface ThreatEdge {
  from: string
  to: string
  kind: ThreatEdgeKind
  /** Short, single-line reason the edge exists. Shown on the edge chip. */
  label?: string
  /** Optional second-line detail. Useful for time delta or context. */
  detail?: string
  /** Long human-readable explanation surfaced in the hover tooltip. */
  tooltip?: string
}

export interface Threat {
  id: string
  /**
   * Narrative id (backward-compatible name retained for the existing UI).
   * Consumers should prefer `narrative` / `mitre` / `phases` for new work.
   */
  patternId: string
  patternName: string
  patternDescription: string
  severity: ThreatSeverity
  entityLabel: string
  firstTime: string
  lastTime: string
  events: Event[]
  edges: ThreatEdge[]
  confidence: number
  reason: string
  /** Distinct phases that fired, in first-seen order. */
  phases: Phase[]
  /** Deduped MITRE technique ids (e.g. "T1552", "T1071"). */
  mitre: string[]
  /** One-to-two sentence plain-English explanation of the narrative. */
  narrative: string
  /** Imperative next step for the operator (e.g. "Rotate alice's credentials"). */
  suggestedAction: string
  /** Binding identity. Null for narratives bound only to host. */
  actor: Identity | null
}

export interface NarrativeContext {
  now: number
}

/** Event annotated with its classified phase + MITRE id. */
export interface PhasedEvent {
  event: Event
  phase: Phase
  mitre: string
  confidence: number
}

/** Actor-grouped, phase-annotated event cluster fed into `AttackNarrative.match`. */
export interface ActorCluster {
  /** Binding key (`proc:bash`, `cnt:abc...`, `usr:alice`, `host:node-1|usr:alice`). */
  key: string
  actor: Identity | null
  events: PhasedEvent[]
}

export interface MatchResult {
  /** Events that form the narrative, in time order. */
  events: PhasedEvent[]
  /** Phases observed (distinct, first-seen order). */
  phases: Phase[]
  /** MITRE technique ids seen (distinct). */
  mitre: string[]
  /** Correlation edges between events — optional; the engine synthesises defaults if omitted. */
  edges?: ThreatEdge[]
  /** Confidence in [0, 1]; the engine may adjust based on coverage / tightness. */
  confidence: number
  /** Short machine-readable reason string; surfaced in `Threat.reason`. */
  reason: string
  /** Hosts implicated; used when `entityLabel` is `auto`. */
  hosts?: string[]
}

export interface AttackNarrative {
  id: string
  name: string
  /** Sentence surfaced in the existing `patternDescription` slot. */
  description: string
  severityBase: ThreatSeverity
  mitre: readonly string[]
  identityBinding: IdentityBinding
  windowMs: number
  /** Optional: phases that MUST appear in this order (gaps allowed). */
  requiredPhases?: readonly Phase[]
  /** Optional: phases that boost confidence if present. */
  optionalPhases?: readonly Phase[]
  /** Minimum number of events in the cluster before `match` is invoked. */
  minEvents: number
  /** Imperative operator action text. */
  suggestedAction: string
  /** Returns null when this cluster does not fit the narrative. */
  match: (cluster: ActorCluster, ctx: NarrativeContext) => MatchResult | null
  /** Human-readable 1-2 sentence explanation of the fired match. */
  narrative: (match: MatchResult, actor: Identity | null) => string
}

export const PRIORITY_TO_SEVERITY: Record<Priority, ThreatSeverity> = {
  emergency: "critical",
  alert: "critical",
  critical: "critical",
  error: "high",
  warning: "med",
  notice: "low",
  informational: "low",
  debug: "low",
}

const SEVERITY_RANK: Record<ThreatSeverity, number> = {
  low: 0,
  med: 1,
  high: 2,
  critical: 3,
}

export function maxSeverity(events: Event[]): ThreatSeverity {
  let s: ThreatSeverity = "low"
  for (const e of events) {
    const cand = PRIORITY_TO_SEVERITY[e.priority] ?? "low"
    if (SEVERITY_RANK[cand] > SEVERITY_RANK[s]) s = cand
  }
  return s
}

export function severityOrder(s: ThreatSeverity): number {
  return SEVERITY_RANK[s]
}
