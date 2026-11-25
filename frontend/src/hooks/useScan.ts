import { useQuery } from '@tanstack/react-query'

import { api } from '../api/client'
import type { ScanDetail } from '../types/scan'

export const ACTIVE_STATUSES = new Set(['queued', 'running'])

/** Polls a scan every ~1.5 s while it is queued/running, then stops. */
export function useScan(id: string | undefined) {
  return useQuery<ScanDetail>({
    queryKey: ['scan', id],
    queryFn: () => api.getScan(id!),
    enabled: Boolean(id),
    refetchInterval: (query) => {
      const status = query.state.data?.status
      if (query.state.error) return false
      return !status || ACTIVE_STATUSES.has(status) ? 1500 : false
    },
    refetchIntervalInBackground: false,
  })
}
