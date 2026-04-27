import { Maximize2 } from "lucide-react"
import { useCallback, useMemo, useRef, useState } from "react"

import { EmptyState } from "@/components/common/empty-state"
import { LoadingSkeleton } from "@/components/common/loading-skeleton"
import { PageHeader } from "@/components/common/page-header"
import {
  PipelineCanvas,
  type PipelineCanvasHandle,
  type PipelineSelection,
} from "@/components/pipeline/canvas"
import { PipelineDetailPanel } from "@/components/pipeline/detail-panel"
import { Button } from "@/components/ui/button"
import {
  ResizableHandle,
  ResizablePanel,
  ResizablePanelGroup,
} from "@/components/ui/resizable"
import { usePipelineComposite, usePipelineStatus } from "@/hooks/use-pipeline"
import { usePipelineStore } from "@/stores/pipeline-store"

export function PipelinePage() {
  usePipelineStatus()
  const { data: composite, isPending, isError, error } = usePipelineComposite()
  const statusByName = usePipelineStore((s) => s.statusByName)
  const [selection, setSelection] = useState<PipelineSelection>(null)
  const canvasRef = useRef<PipelineCanvasHandle>(null)

  const handleSelect = useCallback((sel: PipelineSelection) => {
    setSelection((prev) => {
      if (sel && prev && sel.kind === prev.kind) {
        if (sel.kind === "sink" && prev.kind === "sink" && sel.name === prev.name) {
          return null
        }
        if (sel.kind !== "sink") {
          return null
        }
      }
      return sel
    })
  }, [])

  const selectedEntry = useMemo(() => {
    if (!composite || selection?.kind !== "sink") return null
    return composite.outputs.find((o) => o.name === selection.name) ?? null
  }, [composite, selection])

  const selectedStatus = useMemo(() => {
    if (selection?.kind !== "sink") return null
    return statusByName[selection.name] ?? null
  }, [statusByName, selection])

  return (
    <div className="flex h-full flex-col gap-4">
      <PageHeader
        title="Pipeline"
        description="Read-only view of the event pipeline. Click any node to inspect it; drag to rearrange."
        actions={
          <Button
            variant="outline"
            size="sm"
            onClick={() => canvasRef.current?.resetPositions()}
            disabled={!composite}
          >
            <Maximize2 className="mr-1 size-3.5" aria-hidden />
            Reset layout
          </Button>
        }
      />

      {isPending ? (
        <LoadingSkeleton lines={8} />
      ) : isError ? (
        <EmptyState
          title="Unable to load pipeline"
          description={error instanceof Error ? error.message : "Unknown error"}
        />
      ) : !composite ? (
        <EmptyState title="Pipeline is empty" />
      ) : (
        <ResizablePanelGroup
          orientation="horizontal"
          className="min-h-0 flex-1 rounded-lg"
          id="pipeline-layout"
        >
          <ResizablePanel defaultSize={70} minSize={20}>
            <div className="relative h-full min-h-96 pr-2">
              <PipelineCanvas
                ref={canvasRef}
                composite={composite}
                statusByName={statusByName}
                selection={selection}
                onSelect={handleSelect}
              />
            </div>
          </ResizablePanel>
          <ResizableHandle withHandle />
          <ResizablePanel defaultSize={30} minSize={15}>
            <div className="h-full pl-2">
              <PipelineDetailPanel
                selection={selection}
                entry={selectedEntry}
                status={selectedStatus}
              />
            </div>
          </ResizablePanel>
        </ResizablePanelGroup>
      )}
    </div>
  )
}

export default PipelinePage
