import type { Event } from "@/lib/types"

/**
 * MITRE-ATT&CK-aligned phase vocabulary. Each Falco event the analyst engine
 * understands is classified into exactly one phase. Events that cannot be
 * classified are ignored by narrative matching — they stay visible in the
 * event list but do not contribute to threat correlation.
 */
export type Phase =
  | "recon"
  | "initial-access"
  | "execution"
  | "privilege-escalation"
  | "persistence"
  | "defense-evasion"
  | "credential-access"
  | "discovery"
  | "lateral-movement"
  | "collection"
  | "c2"
  | "exfiltration"
  | "impact"

/** Display order for phase timelines — aligned with attack kill-chain flow. */
export const PHASE_ORDER: readonly Phase[] = [
  "recon",
  "initial-access",
  "execution",
  "privilege-escalation",
  "persistence",
  "defense-evasion",
  "credential-access",
  "discovery",
  "lateral-movement",
  "collection",
  "c2",
  "exfiltration",
  "impact",
]

export interface PhaseClassification {
  phase: Phase
  mitre: string
  confidence: number
}

export interface PhaseRule {
  /** Regex matched against `event.rule`. Case-insensitive, multi-word tolerated. */
  rule: RegExp
  /** Optional disambiguator on the event's `output_fields` / other shape. */
  fieldMatch?: (evt: Event) => boolean
  phase: Phase
  mitre: string
  confidence: number
}

/**
 * Lookup helper for Falco `output_fields`. Returns the first non-empty string
 * value among the provided keys, or undefined if none are set. Number values
 * are coerced to string. Exported for reuse by UI components that surface
 * these fields directly.
 */
export function outputField(evt: Event, ...keys: string[]): string | undefined {
  const fields = evt.output_fields ?? {}
  for (const k of keys) {
    const v = (fields as Record<string, unknown>)[k]
    if (typeof v === "string" && v.length > 0) return v
    if (typeof v === "number") return String(v)
  }
  return undefined
}

const field = outputField

const SENSITIVE_FILE_RE = /\/etc\/shadow|\/root\/\.ssh|id_rsa|kubeconfig|\.ssh\/|service.*token|token$/i
const SA_TOKEN_RE = /serviceaccount.*token|kubernetes\.io\/serviceaccount/i
const MINER_PROC_RE = /xmrig|minerd|cpuminer|ccminer|ethminer|nicehash|phoenixminer/i
const MINER_PORT_RE = /:(3333|4444|5555|7777|8080|8888|9999|14433|14444|45700)\b/i
const CRON_PATH_RE = /\/etc\/cron|\/etc\/systemd\/system\/|authorized_keys|\/etc\/ld\.so|\.bashrc|\.profile/i
const KUBE_API_RE = /kube-apiserver|kubernetes\.default\.svc|(^|[^0-9])10\.96\.0\.1([^0-9]|$)/i

/**
 * Ordered classification rules. First match wins. The regex list intentionally
 * covers the Falco stock ruleset as shipped in falcosecurity/rules. When Falco
 * rule names drift upstream, the impact is graceful: unknown names classify
 * as null and the narrative engine skips them.
 */
export const RULE_PHASE_MAP: readonly PhaseRule[] = [
  {
    rule: /read sensitive file/i,
    fieldMatch: (e) => SENSITIVE_FILE_RE.test(field(e, "fd.name") ?? ""),
    phase: "credential-access",
    mitre: "T1552",
    confidence: 0.9,
  },
  {
    rule: /read\s+ssh\s+secret|read\s+private\s+key/i,
    phase: "credential-access",
    mitre: "T1552.004",
    confidence: 0.9,
  },
  {
    rule: /read.*service.*account.*token|serviceaccount.*token/i,
    fieldMatch: (e) => SA_TOKEN_RE.test(field(e, "fd.name") ?? ""),
    phase: "credential-access",
    mitre: "T1552.005",
    confidence: 0.9,
  },
  {
    rule: /read sensitive file/i,
    phase: "discovery",
    mitre: "T1083",
    confidence: 0.5,
  },

  {
    rule: /terminal shell in container|run shell untrusted/i,
    phase: "execution",
    mitre: "T1059",
    confidence: 0.85,
  },
  {
    rule: /launch suspicious network tool/i,
    phase: "execution",
    mitre: "T1059",
    confidence: 0.75,
  },
  {
    rule: /debugger (launched|exec)|exec.*from.*container/i,
    phase: "execution",
    mitre: "T1059",
    confidence: 0.7,
  },
  {
    rule: /launch package management/i,
    phase: "execution",
    mitre: "T1072",
    confidence: 0.65,
  },

  {
    rule: /launch privileged container|launch sensitive mount container/i,
    phase: "privilege-escalation",
    mitre: "T1611",
    confidence: 0.9,
  },
  {
    rule: /change thread namespace/i,
    phase: "privilege-escalation",
    mitre: "T1611",
    confidence: 0.9,
  },
  {
    rule: /sudo potential privilege escalation|sudo.*exec/i,
    phase: "privilege-escalation",
    mitre: "T1548.003",
    confidence: 0.75,
  },
  {
    rule: /setuid or setgid bit.*set|chmod.*sensitive.*file/i,
    phase: "privilege-escalation",
    mitre: "T1548",
    confidence: 0.7,
  },

  {
    rule: /schedule cron|modify.*crontab|write.*cron/i,
    phase: "persistence",
    mitre: "T1053.003",
    confidence: 0.9,
  },
  {
    rule: /modify shell configuration|modify binary dirs/i,
    phase: "persistence",
    mitre: "T1547",
    confidence: 0.85,
  },
  {
    rule: /create symlink over sensitive files/i,
    phase: "persistence",
    mitre: "T1547",
    confidence: 0.7,
  },
  {
    rule: /write below (etc|root|binary dir)/i,
    fieldMatch: (e) => CRON_PATH_RE.test(field(e, "fd.name") ?? ""),
    phase: "persistence",
    mitre: "T1547",
    confidence: 0.85,
  },
  {
    rule: /write below (etc|root|binary dir)/i,
    phase: "defense-evasion",
    mitre: "T1070",
    confidence: 0.55,
  },
  {
    rule: /mkdir binary dirs/i,
    phase: "persistence",
    mitre: "T1547",
    confidence: 0.75,
  },

  {
    rule: /clear log activities|remove bulk data from disk|disable.*(audit|selinux|apparmor)/i,
    phase: "defense-evasion",
    mitre: "T1070",
    confidence: 0.9,
  },
  {
    rule: /delete or rename.*bash_history|clear.*history/i,
    phase: "defense-evasion",
    mitre: "T1070.003",
    confidence: 0.85,
  },

  {
    rule: /contact k8s api server|contact cloud metadata/i,
    fieldMatch: (e) => {
      const host = field(e, "fd.sip", "fd.name") ?? ""
      return KUBE_API_RE.test(host) || /169\.254\.169\.254/.test(host)
    },
    phase: "discovery",
    mitre: "T1613",
    confidence: 0.85,
  },
  {
    rule: /contact k8s api server|contact cloud metadata/i,
    phase: "discovery",
    mitre: "T1613",
    confidence: 0.7,
  },
  {
    rule: /system information discovery|find.*\/etc\/passwd/i,
    phase: "discovery",
    mitre: "T1082",
    confidence: 0.7,
  },

  {
    rule: /ssh.*allowed.*outside|disallowed ssh connection/i,
    phase: "lateral-movement",
    mitre: "T1021.004",
    confidence: 0.75,
  },

  {
    rule: /exfiltrating artifacts via kubernetes control plane/i,
    phase: "collection",
    mitre: "T1530",
    confidence: 0.8,
  },

  {
    rule: /unexpected outbound|outbound connection (to|from)/i,
    phase: "c2",
    mitre: "T1071",
    confidence: 0.65,
  },
  {
    rule: /program run with disallowed.*proxy/i,
    phase: "c2",
    mitre: "T1090",
    confidence: 0.75,
  },

  {
    rule: /data.*exfiltration|large.*outbound/i,
    phase: "exfiltration",
    mitre: "T1041",
    confidence: 0.8,
  },

  {
    rule: /miner.*pool|cryptomining/i,
    phase: "impact",
    mitre: "T1496",
    confidence: 0.85,
  },
  {
    rule: /detect.*(outbound|connection).*miner/i,
    fieldMatch: (e) => {
      const dst = field(e, "fd.rip", "fd.name") ?? ""
      return MINER_PORT_RE.test(dst)
    },
    phase: "impact",
    mitre: "T1496",
    confidence: 0.85,
  },
  {
    rule: /.*/i,
    fieldMatch: (e) => MINER_PROC_RE.test(field(e, "proc.cmdline", "proc.name") ?? ""),
    phase: "impact",
    mitre: "T1496",
    confidence: 0.9,
  },
]

/**
 * Classify a Falco event into an attack phase. Returns null when no rule in
 * RULE_PHASE_MAP matches — the caller should skip such events.
 */
export function classifyEvent(evt: Event): PhaseClassification | null {
  const ruleName = evt.rule ?? ""
  if (!ruleName) return null
  for (const entry of RULE_PHASE_MAP) {
    if (!entry.rule.test(ruleName)) continue
    if (entry.fieldMatch && !entry.fieldMatch(evt)) continue
    return { phase: entry.phase, mitre: entry.mitre, confidence: entry.confidence }
  }
  return null
}

/** Stable comparator by kill-chain flow position. */
export function phaseOrder(p: Phase): number {
  const idx = PHASE_ORDER.indexOf(p)
  return idx === -1 ? PHASE_ORDER.length : idx
}

/** True iff `phases` contains `required` in the given order (gaps allowed). */
export function containsOrdered(phases: readonly Phase[], required: readonly Phase[]): boolean {
  let i = 0
  for (const p of phases) {
    if (p === required[i]) i++
    if (i === required.length) return true
  }
  return false
}
