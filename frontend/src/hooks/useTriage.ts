import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import { api } from '../api/client'
import type { TriageItem, TriageStatus } from '../types/scan'

export interface TriageApi {
  items: Record<string, TriageItem>
  save: (findingId: string, status: TriageStatus, note: string) => Promise<void>
}

/** Triage decisions for a scan's domain (registered owners only; pass enabled=false otherwise). */
export function useTriage(scanId: string, enabled: boolean): TriageApi | undefined {
  const qc = useQueryClient()
  const key = ['triage', scanId]
  const { data } = useQuery({ queryKey: key, queryFn: () => api.getTriage(scanId), enabled })
  const mutation = useMutation({
    mutationFn: (v: { findingId: string; status: TriageStatus; note: string }) =>
      api.setTriage(scanId, v.findingId, v.status, v.note),
    onSuccess: (res) =>
      qc.setQueryData<{ items: Record<string, TriageItem> }>(key, (old) => {
        const items = { ...(old?.items ?? {}) }
        if (res.item) items[res.finding_id] = res.item
        else delete items[res.finding_id]
        return { items }
      }),
  })
  if (!enabled || !data) return undefined
  return {
    items: data.items,
    save: async (findingId, status, note) => {
      await mutation.mutateAsync({ findingId, status, note })
    },
  }
}

export const TRIAGE_LABEL: Record<TriageStatus, string> = {
  open: 'Open',
  false_positive: 'False positive',
  accepted_risk: 'Accepted risk',
  reported: 'Reported',
  fixed: 'Fixed',
}

export const TRIAGE_TONE: Record<TriageStatus, 'neutral' | 'ok' | 'warn' | 'accent'> = {
  open: 'neutral',
  false_positive: 'neutral',
  accepted_risk: 'warn',
  reported: 'accent',
  fixed: 'ok',
}

/** Statuses that take a finding off the to-do list. */
export const RESOLVED: ReadonlySet<TriageStatus> = new Set(['false_positive', 'accepted_risk', 'fixed'])
