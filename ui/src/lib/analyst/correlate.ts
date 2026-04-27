import type { Event } from "@/lib/types"

import { bindingKey, fingerprint, identityLabel, type Identity } from "./identity"
import { NARRATIVES } from "./narratives"
import { classifyEvent } from "./phases"
import {
  maxSeverity,
  severityOrder,
  type ActorCluster,
  type AttackNarrative,
  type PhasedEvent,
  type Threat,
  type ThreatSeverity,
} from "./types"

export interface CorrelateOptions {
  now?: number
  narratives?: readonly AttackNarrative[]
  maxThreats?: number
}

/**
 * Phase-driven correlation engine. For every narrative in the catalog we:
 *   1. classify each event into a MITRE-ATT&CK phase (events without a phase
 *      are ignored),
 *   2. group phased events by the narrative's identity binding (system users
 *      / system procs never bind — see identity.ts),
 *   3. sort each group by time and hand it to the narrative's `match` fn,
 *   4. emit a Threat on success, deduped by (narrative id + actor key).
 *
 * Backward-compatible fields (`patternId` / `patternName` / `patternDescription`)
 * are populated so the existing UI components (`threat-table`, `threat-filters`,
 * `analyst-threat`) keep working unchanged.
 */
export function correlate(events: readonly Event[], opts: CorrelateOptions = {}): Threat[] {
  const narratives = opts.narratives ?? NARRATIVES
  const now = opts.now ?? Date.now()
  const maxThreats = opts.maxThreats ?? 200

  if (events.length === 0) return []

  // 1. classify once per event
  const phased: PhasedEvent[] = []
  const identityOf = new Map<string, Identity>()
  for (const e of events) {
    const cls = classifyEvent(e)
    if (!cls) continue
    phased.push({ event: e, phase: cls.phase, mitre: cls.mitre, confidence: cls.confidence })
    identityOf.set(e.uuid, fingerprint(e))
  }
  if (phased.length === 0) return []

  // 2. stable time sort
  phased.sort((a, b) => Date.parse(a.event.time) - Date.parse(b.event.time))

  const threats: Threat[] = []
  const seen = new Set<string>()

  outer: for (const narrative of narratives) {
    const groups = new Map<string, PhasedEvent[]>()
    const actors = new Map<string, Identity>()

    for (const pe of phased) {
      const id = identityOf.get(pe.event.uuid)!
      const key = bindingKey(id, narrative.identityBinding)
      if (!key) continue
      const g = groups.get(key)
      if (g) g.push(pe)
      else {
        groups.set(key, [pe])
        actors.set(key, id)
      }
    }

    for (const [key, groupEvents] of groups) {
      if (groupEvents.length < narrative.minEvents) continue
      const actor = actors.get(key) ?? null
      const cluster: ActorCluster = { key, actor, events: groupEvents }
      const match = narrative.match(cluster, { now })
      if (!match) continue

      const first = match.events[0]!
      const last = match.events[match.events.length - 1]!
      const dedupeId = `${narrative.id}:${key}:${first.event.uuid}:${last.event.uuid}`
      if (seen.has(dedupeId)) continue
      seen.add(dedupeId)

      const events = match.events.map((pe) => pe.event)
      const severity = pickSeverity(narrative.severityBase, events)
      const hosts = match.hosts ?? []
      const actorText = actor ? identityLabel(actor) : "unknown actor"
      const entityLabel =
        hosts.length > 1 ? `${actorText} · ${hosts.length} hosts` : actorText

      threats.push({
        id: dedupeId,
        patternId: narrative.id,
        patternName: narrative.name,
        patternDescription: narrative.description,
        severity,
        entityLabel,
        firstTime: first.event.time,
        lastTime: last.event.time,
        events,
        edges: match.edges ?? [],
        confidence: match.confidence,
        reason: match.reason,
        phases: match.phases,
        mitre: match.mitre,
        narrative: narrative.narrative(match, actor),
        suggestedAction: narrative.suggestedAction,
        actor,
      })

      if (threats.length >= maxThreats) break outer
    }
  }

  threats.sort((a, b) => {
    const sev = severityOrder(b.severity) - severityOrder(a.severity)
    if (sev !== 0) return sev
    return Date.parse(b.lastTime) - Date.parse(a.lastTime)
  })

  return threats
}

/**
 * Narrative severity wins unless a more serious priority appears in the evidence.
 * Observed priority can escalate (e.g. a `med` narrative with a `critical` event
 * becomes `critical`) but never downgrade.
 */
function pickSeverity(base: ThreatSeverity, events: readonly Event[]): ThreatSeverity {
  const observed = maxSeverity(events as Event[])
  return severityOrder(observed) > severityOrder(base) ? observed : base
}
