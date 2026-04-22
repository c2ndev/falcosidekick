import { Button } from "@/components/ui/button"

export function App() {
  return (
    <div className="flex min-h-screen items-center justify-center">
      <div className="text-center space-y-4">
        <h1 className="text-4xl font-bold">Falcosidekick</h1>
        <p className="text-muted-foreground">v3.0 - UI bootstrap</p>
        <Button
          variant="outline"
          onClick={() =>
            fetch("/healthz")
              .then((r) => r.json())
              .then((data) => console.log(data))
          }
        >
          Check Health
        </Button>
      </div>
    </div>
  )
}

export default App
