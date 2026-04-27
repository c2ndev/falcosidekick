import { cn } from "@/lib/utils"

interface ConfigTreeProps {
  data: Record<string, unknown>
  className?: string
}

export function ConfigTree({ data, className }: ConfigTreeProps) {
  const entries = Object.entries(data)
  if (entries.length === 0) {
    return <p className="text-sm text-muted-foreground">No configuration.</p>
  }
  return (
    <dl className={cn("space-y-1 font-mono text-xs", className)}>
      {entries.map(([k, v]) => (
        <ConfigNode key={k} name={k} value={v} />
      ))}
    </dl>
  )
}

interface NodeProps {
  name: string
  value: unknown
}

function ConfigNode({ name, value }: NodeProps) {
  if (value == null) {
    return <Leaf name={name} rendered={<span className="text-muted-foreground">null</span>} />
  }
  if (Array.isArray(value)) {
    if (value.length === 0) {
      return <Leaf name={name} rendered={<span className="text-muted-foreground">[]</span>} />
    }
    if (isPrimitiveArray(value)) {
      return (
        <Leaf
          name={name}
          rendered={
            <span className="break-all">
              [{value.map((v, i) => <PrimitiveSpan key={i} value={v} suffix={i < value.length - 1 ? ", " : ""} />)}]
            </span>
          }
        />
      )
    }
    return <Branch name={name}>
      {value.map((v, i) => (
        <ConfigNode key={i} name={`[${i}]`} value={v} />
      ))}
    </Branch>
  }
  if (typeof value === "object") {
    const nested = value as Record<string, unknown>
    const nestedEntries = Object.entries(nested)
    if (nestedEntries.length === 0) {
      return <Leaf name={name} rendered={<span className="text-muted-foreground">{"{}"}</span>} />
    }
    return (
      <Branch name={name}>
        {nestedEntries.map(([k, v]) => (
          <ConfigNode key={k} name={k} value={v} />
        ))}
      </Branch>
    )
  }
  return <Leaf name={name} rendered={<PrimitiveSpan value={value} />} />
}

function Leaf({ name, rendered }: { name: string; rendered: React.ReactNode }) {
  return (
    <div className="grid grid-cols-[minmax(0,10rem)_1fr] gap-x-3 items-baseline">
      <dt className="truncate text-muted-foreground">{name}</dt>
      <dd className="min-w-0 break-all">{rendered}</dd>
    </div>
  )
}

function Branch({ name, children }: { name: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1">
      <div className="text-muted-foreground">{name}:</div>
      <div className="ml-2 space-y-1 border-l border-border/60 pl-3">{children}</div>
    </div>
  )
}

function PrimitiveSpan({ value, suffix = "" }: { value: unknown; suffix?: string }) {
  if (typeof value === "string") {
    return <span>{value}{suffix}</span>
  }
  if (typeof value === "number" || typeof value === "bigint") {
    return <span className="text-foreground">{String(value)}{suffix}</span>
  }
  if (typeof value === "boolean") {
    return <span className="text-foreground">{value ? "true" : "false"}{suffix}</span>
  }
  return <span>{String(value)}{suffix}</span>
}

function isPrimitiveArray(arr: unknown[]): boolean {
  return arr.every((v) => v == null || typeof v === "string" || typeof v === "number" || typeof v === "boolean")
}
