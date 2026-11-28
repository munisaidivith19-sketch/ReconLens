import { useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Check, Copy, KeyRound, Trash2 } from 'lucide-react'

import { api, ApiError } from '../api/client'
import { copyText } from '../components/report/taxonomy'
import { Alert } from '../components/ui/Alert'
import { Button } from '../components/ui/Button'
import { Card, CardHeader } from '../components/ui/Card'
import { Empty } from '../components/ui/Disclosure'
import { formatDateTime } from '../components/ui/format'
import type { ApiKey } from '../types/scan'

function CopyButton({ text, label = 'Copy' }: { text: string; label?: string }) {
  const [done, setDone] = useState(false)
  return (
    <Button
      size="sm"
      onClick={async () => {
        if (await copyText(text)) {
          setDone(true)
          window.setTimeout(() => setDone(false), 1500)
        }
      }}
      icon={done ? <Check size={16} aria-hidden="true" /> : <Copy size={16} aria-hidden="true" />}
    >
      {done ? 'Copied' : label}
    </Button>
  )
}

export default function ApiKeys() {
  const qc = useQueryClient()
  const [name, setName] = useState('')
  const [created, setCreated] = useState<ApiKey | null>(null)
  const keys = useQuery({ queryKey: ['api-keys'], queryFn: api.listKeys })

  const create = useMutation({
    mutationFn: (n: string) => api.createKey(n),
    onSuccess: (k) => {
      setCreated(k)
      setName('')
      void qc.invalidateQueries({ queryKey: ['api-keys'] })
    },
  })
  const revoke = useMutation({
    mutationFn: (id: string) => api.deleteKey(id),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['api-keys'] }),
  })

  const submit = (e: FormEvent) => {
    e.preventDefault()
    if (name.trim()) create.mutate(name.trim())
  }

  const items = keys.data?.items ?? []
  const max = keys.data?.max ?? 5
  const base = api.baseUrl || window.location.origin
  const example = `curl -X POST ${base}/api/scans \\
  -H "Authorization: Bearer $RECONLENS_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{"target": "example.com", "confirmed_authorized": true}'

# Poll the scan, then download the full report
curl -H "Authorization: Bearer $RECONLENS_KEY" ${base}/api/scans/<id>
curl -H "Authorization: Bearer $RECONLENS_KEY" ${base}/api/scans/<id>/export`

  const error = create.error ?? revoke.error

  return (
    <div className="mx-auto flex w-full max-w-3xl flex-col gap-5">
      <Card strong className="animate-rise">
        <CardHeader
          title="API keys"
          icon={<KeyRound size={20} />}
          description="Run scans from scripts or CI. Keys use your account's daily quota and the same authorization rules."
        />
        <form onSubmit={submit} className="flex flex-col gap-2 sm:flex-row" aria-label="Create an API key">
          <label htmlFor="key-name" className="sr-only">
            Key name
          </label>
          <input
            id="key-name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            maxLength={60}
            placeholder="Name, e.g. github-actions"
            className="field min-w-0 flex-1"
            disabled={items.length >= max}
          />
          <Button type="submit" variant="primary" loading={create.isPending} disabled={!name.trim() || items.length >= max}>
            Create key
          </Button>
        </form>
        <p className="mt-2 text-xs text-muted">
          {items.length} of {max} keys used. Letters, numbers, spaces, dots, dashes and underscores only.
        </p>
        {error && (
          <p role="alert" className="mt-2 text-sm text-danger">
            {error instanceof ApiError ? error.message : 'Something went wrong.'}
          </p>
        )}
      </Card>

      {created?.key && (
        <Alert
          tone="warning"
          title={`Copy your new key "${created.name}" now`}
          action={
            <button type="button" className="btn btn-sm" onClick={() => setCreated(null)}>
              Done
            </button>
          }
        >
          <span className="block">It won't be shown again. Store it as a secret (for example RECONLENS_KEY in your CI).</span>
          <span className="mt-2 flex flex-wrap items-center gap-2">
            <code className="min-w-0 rounded-lg bg-glass-strong px-2 py-1 font-mono text-xs break-all">{created.key}</code>
            <CopyButton text={created.key} />
          </span>
        </Alert>
      )}

      <Card aria-labelledby="keys-list">
        <CardHeader id="keys-list" title="Your keys" />
        {keys.isLoading ? (
          <p className="text-sm text-muted">Loading…</p>
        ) : items.length === 0 ? (
          <Empty>No API keys yet.</Empty>
        ) : (
          <ul className="flex flex-col gap-1.5">
            {items.map((k) => (
              <li
                key={k.id}
                className="grid min-w-0 gap-2 rounded-xl bg-glass px-3 py-2.5 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-center"
              >
                <span className="min-w-0">
                  <span className="block font-semibold [overflow-wrap:anywhere]">{k.name}</span>
                  <span className="block text-xs text-muted">
                    <code className="font-mono">{k.prefix}…</code> · created {formatDateTime(k.created_at)} ·{' '}
                    {k.last_used_at ? `last used ${formatDateTime(k.last_used_at)}` : 'never used'}
                  </span>
                </span>
                <Button
                  size="sm"
                  onClick={() => {
                    if (window.confirm(`Revoke "${k.name}"? Scripts using it will stop working.`)) revoke.mutate(k.id)
                  }}
                  loading={revoke.isPending && revoke.variables === k.id}
                  icon={<Trash2 size={16} aria-hidden="true" />}
                >
                  Revoke
                </Button>
              </li>
            ))}
          </ul>
        )}
      </Card>

      <Card aria-labelledby="keys-usage">
        <CardHeader
          id="keys-usage"
          title="Usage"
          action={<CopyButton text={example} label="Copy example" />}
          description="Send the key as a Bearer token. Every scan still requires confirmed_authorized: true."
        />
        <pre className="overflow-x-auto rounded-xl bg-glass-strong p-3 font-mono text-xs leading-relaxed text-muted">
          {example}
        </pre>
        <p className="mt-2 text-xs text-faint">
          Keys can start and read scans, batches (POST /api/scans/batch) and triage. They can't manage keys or sign in.
        </p>
      </Card>
    </div>
  )
}
