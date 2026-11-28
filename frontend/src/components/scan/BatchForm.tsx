import { useState, type FormEvent } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Layers, ShieldCheck } from 'lucide-react'
import { useNavigate } from 'react-router'

import { api, ApiError } from '../../api/client'
import { Button } from '../ui/Button'
import { Disclosure } from '../ui/Disclosure'
import { validateTarget } from './ScanForm'

export const MAX_BATCH = 5

/** Scan up to five domains at once (registered accounts). Each uses one scan from the daily quota. */
export function BatchForm({ remaining }: { remaining?: number }) {
  const navigate = useNavigate()
  const qc = useQueryClient()
  const [text, setText] = useState('')
  const [confirmed, setConfirmed] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const targets = [...new Set(text.split(/[\s,]+/).map((t) => t.trim()).filter(Boolean))]

  const start = useMutation({
    mutationFn: () => api.createBatch(targets),
    onSuccess: (res) => {
      void qc.invalidateQueries({ queryKey: ['quota'] })
      void qc.invalidateQueries({ queryKey: ['scans'] })
      navigate(`/batches/${res.batch_id}`)
    },
    onError: (err) => setError(err instanceof ApiError ? err.message : 'The scans could not be started.'),
  })

  const submit = (e: FormEvent) => {
    e.preventDefault()
    if (targets.length === 0) return setError('Enter at least one domain.')
    if (targets.length > MAX_BATCH) return setError(`Enter at most ${MAX_BATCH} domains.`)
    const bad = targets.map((t) => [t, validateTarget(t)] as const).find(([, p]) => p)
    if (bad) return setError(`${bad[0]}: ${bad[1]}`)
    if (!confirmed) return setError('Confirm you are authorized to test every domain.')
    setError(null)
    start.mutate()
  }

  return (
    <Disclosure
      summary={
        <span className="flex items-center gap-2 font-semibold">
          <Layers size={18} aria-hidden="true" /> Scan several domains at once
        </span>
      }
    >
      <form onSubmit={submit} noValidate className="flex flex-col gap-3" aria-label="Start a multi-domain scan">
        <label htmlFor="batch-targets" className="text-sm font-medium">
          Domains (one per line, up to {MAX_BATCH})
        </label>
        <textarea
          id="batch-targets"
          rows={4}
          value={text}
          onChange={(e) => {
            setText(e.target.value)
            setError(null)
          }}
          placeholder={'example.com\napp.example.com\nexample.org'}
          spellCheck={false}
          autoCapitalize="none"
          className="field resize-y font-mono text-sm"
          aria-invalid={error ? true : undefined}
          aria-describedby="batch-hint"
        />
        <label className="flex cursor-pointer items-start gap-2.5 text-sm">
          <input
            type="checkbox"
            checked={confirmed}
            onChange={(e) => setConfirmed(e.target.checked)}
            className="mt-0.5 size-4 accent-[var(--accent)]"
          />
          <span>
            <ShieldCheck size={14} aria-hidden="true" className="mr-1 inline text-ok" />I own every domain listed or am
            explicitly authorized to test it.
          </span>
        </label>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <p id="batch-hint" className="text-xs text-muted">
            {targets.length} domain(s) · each uses one scan from your daily quota
            {remaining !== undefined ? ` (${remaining} left)` : ''}.
          </p>
          <Button type="submit" variant="primary" size="sm" loading={start.isPending}>
            Scan {targets.length || ''} domain{targets.length === 1 ? '' : 's'}
          </Button>
        </div>
        {error && (
          <p role="alert" className="text-sm text-danger">
            {error}
          </p>
        )}
      </form>
    </Disclosure>
  )
}
