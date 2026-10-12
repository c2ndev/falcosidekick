import { useQuery } from "@tanstack/react-query"
import { useMemo } from "react"

import { correlate } from "@/lib/analyst/correlate"
import type { Threat } from "@/lib/analyst/types"
import { api } from "@/lib/api-client"
import type { Event } from "@/lib/types"

export interface ThreatsQuery {
  since: string
  maxEvents?: number
}

interface UseThreatsResult {
  threats: Threat[]
  eventCount: number
  isPending: boolean
  isFetching: boolean
  isError: boolean
  refetch: () => void
  updatedAt: number
}

/**
 * Correlation hook. Intentionally opts out of the global auto-refresh
 * interval: correlation is an exploratory analysis view and a periodic
 * re-render would steal focus from the drawer the user is reading.
 * Refresh is an explicit user action.
 */
export function useThreats(query: ThreatsQuery): UseThreatsResult {
  const limit = query.maxEvents ?? 10_000

  const { data, isPending, isFetching, isError, refetch, dataUpdatedAt } = useQuery<Event[]>({
    queryKey: ["analyst", "events", query.since, limit],
    queryFn: async ({ signal }) => {
      const res = await api.searchEvents(
        { since: query.since, limit, sort_by: "timestamp", sort_desc: false },
        signal,
      )
      return res.events
    },
    refetchInterval: false,
    refetchOnWindowFocus: false,
    placeholderData: (prev) => prev,
  })

  const threats = useMemo(() => (data ? correlate(data) : []), [data])

  return {
    threats,
    eventCount: data?.length ?? 0,
    isPending,
    isFetching,
    isError,
    refetch: () => {
      void refetch()
    },
    updatedAt: dataUpdatedAt,
  }
}
