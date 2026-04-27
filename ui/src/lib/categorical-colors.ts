/**
 * Categorical color helpers for tags and sources.
 *
 * Returns a stable Tailwind class set per-key by hashing the key into a fixed
 * palette. Semantic mappings (MITRE, filesystem, network, k8s, etc.) are
 * honored first; everything else falls through to the hash palette.
 */

const PALETTE: readonly string[] = [
  "bg-sky-500/15 text-sky-600 border-sky-500/30 dark:text-sky-400",
  "bg-violet-500/15 text-violet-600 border-violet-500/30 dark:text-violet-400",
  "bg-emerald-500/15 text-emerald-600 border-emerald-500/30 dark:text-emerald-400",
  "bg-amber-500/15 text-amber-700 border-amber-500/30 dark:text-amber-400",
  "bg-rose-500/15 text-rose-600 border-rose-500/30 dark:text-rose-400",
  "bg-cyan-500/15 text-cyan-700 border-cyan-500/30 dark:text-cyan-400",
  "bg-fuchsia-500/15 text-fuchsia-600 border-fuchsia-500/30 dark:text-fuchsia-400",
  "bg-lime-500/15 text-lime-700 border-lime-500/30 dark:text-lime-400",
  "bg-indigo-500/15 text-indigo-600 border-indigo-500/30 dark:text-indigo-400",
  "bg-orange-500/15 text-orange-700 border-orange-500/30 dark:text-orange-400",
] as const

function hashIndex(s: string): number {
  let h = 0
  for (let i = 0; i < s.length; i++) {
    h = (h << 5) - h + s.charCodeAt(i)
    h |= 0
  }
  return Math.abs(h) % PALETTE.length
}

function take(i: number): string {
  return PALETTE[i % PALETTE.length] as string
}

const TAG_CATEGORIES: Array<{ match: (t: string) => boolean; index: number }> = [
  { match: (t) => t.startsWith("mitre_"), index: 1 },
  { match: (t) => t === "network" || t === "tcp" || t === "udp", index: 0 },
  { match: (t) => t === "filesystem" || t === "file" || t === "fs", index: 3 },
  { match: (t) => t === "process" || t === "proc", index: 8 },
  { match: (t) => t === "container" || t === "cri", index: 5 },
  { match: (t) => t === "k8s" || t === "kubernetes", index: 6 },
  { match: (t) => t === "shell", index: 4 },
  { match: (t) => t === "users" || t === "user", index: 2 },
  { match: (t) => t === "database" || t === "db", index: 9 },
  { match: (t) => t === "logs" || t === "logging" || t === "audit", index: 7 },
  { match: (t) => t === "drift", index: 4 },
  { match: (t) => t === "software_mgmt" || t === "package", index: 9 },
]

export function classesForTag(tag: string): string {
  const lower = tag.toLowerCase()
  for (const cat of TAG_CATEGORIES) {
    if (cat.match(lower)) return take(cat.index)
  }
  return take(hashIndex(lower))
}

const SOURCE_OVERRIDES: Record<string, number> = {
  syscall: 0,
  k8s_audit: 6,
  kubernetes: 6,
  docker: 5,
  cri: 5,
  plugin: 2,
}

export function classesForSource(source: string): string {
  const lower = source.toLowerCase()
  const override = SOURCE_OVERRIDES[lower]
  if (override != null) return take(override)
  return take(hashIndex(lower))
}

export function rankedColor(index: number): string {
  return take(index)
}
