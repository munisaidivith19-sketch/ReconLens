import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Check, Copy, Link2, Link2Off } from 'lucide-react'

import { api, ApiError } from '../../api/client'
import { Button } from '../ui/Button'
import { formatDateTime } from '../ui/format'
import { copyText } from './taxonomy'

/** Create, copy and revoke a read-only link to this report (registered accounts only). */
export function ShareButton({ scanId }: { scanId: string }) {
  const qc = useQueryClient()
  const key = ['scan-share', scanId]
  const [copied, setCopied] = useState(false)
  const { data } = useQuery({ queryKey: key, queryFn: () => api.getShare(scanId) })
  const share = data?.share ?? null

  const create = useMutation({
    mutationFn: () => api.createShare(scanId),
    onSuccess: (res) => qc.setQueryData(key, res),
  })
  const revoke = useMutation({
    mutationFn: () => api.deleteShare(scanId),
    onSuccess: () => qc.setQueryData(key, { share: null }),
  })
  const error = create.error ?? revoke.error

  const url = share ? `${window.location.origin}/shared/${share.token}` : ''
  const copy = async () => {
    if (await copyText(url)) {
      setCopied(true)
      window.setTimeout(() => setCopied(false), 2000)
    }
  }

  return (
    <div className="no-print flex max-w-full flex-col items-start gap-1 sm:items-end">
      {!share ? (
        <Button
          size="sm"
          onClick={() => create.mutate()}
          loading={create.isPending}
          icon={<Link2 size={16} aria-hidden="true" />}
        >
          Share read-only link
        </Button>
      ) : (
        <div className="flex max-w-full flex-wrap items-center gap-2">
          <code className="max-w-[16rem] truncate rounded-lg bg-glass px-2 py-1 font-mono text-xs" title={url}>
            {url}
          </code>
          <Button size="sm" onClick={copy} icon={copied ? <Check size={16} aria-hidden="true" /> : <Copy size={16} aria-hidden="true" />}>
            {copied ? 'Copied' : 'Copy'}
          </Button>
          <Button
            size="sm"
            onClick={() => revoke.mutate()}
            loading={revoke.isPending}
            icon={<Link2Off size={16} aria-hidden="true" />}
          >
            Stop sharing
          </Button>
        </div>
      )}
      {share && <p className="text-xs text-faint">Anyone with the link can view until {formatDateTime(share.expires_at)}.</p>}
      {error && (
        <p role="alert" className="text-xs text-danger">
          {error instanceof ApiError ? error.message : 'Something went wrong.'}
        </p>
      )}
    </div>
  )
}
