import { useState, type FormEvent } from 'react'
import { ArrowRight, Globe } from 'lucide-react'

import { Button } from '../ui/Button'

// Loose client-side check; the server performs the authoritative validation.
const TARGET_RE = /^(https?:\/\/)?([\p{L}\p{N}](?:[\p{L}\p{N}-]{0,61}[\p{L}\p{N}])?\.)+[\p{L}]{2,63}\.?(:(80|443))?(\/\S*)?$/u
const IP_RE = /^(https?:\/\/)?(\d{1,3}(\.\d{1,3}){3}|\[[0-9a-f:.]+\])(:\d+)?(\/.*)?$/i

export function validateTarget(raw: string): string | null {
  const v = raw.trim()
  if (!v) return 'Enter a domain to scan.'
  if (v.length > 2048) return 'That target is too long.'
  if (IP_RE.test(v)) return "Raw IP addresses can't be scanned. Enter a domain name such as example.com."
  if (/^[a-z][a-z0-9+.-]*:/i.test(v) && !/^https?:\/\//i.test(v) && !/^[^/]+:\d+/.test(v))
    return 'Only http:// and https:// targets are supported.'
  if (/@/.test(v.split('/').slice(0, 3).join('/'))) return "URLs with usernames or passwords aren't allowed."
  if (!TARGET_RE.test(v)) return 'Enter a valid domain, for example example.com or https://app.example.com.'
  return null
}

interface ScanFormProps {
  initial?: string
  serverError?: string | null
  onSubmit: (target: string) => void
}

export function ScanForm({ initial = '', serverError, onSubmit }: ScanFormProps) {
  const [target, setTarget] = useState(initial)
  const [error, setError] = useState<string | null>(null)
  const shown = error ?? serverError ?? null

  const submit = (e: FormEvent) => {
    e.preventDefault()
    const problem = validateTarget(target)
    setError(problem)
    if (!problem) onSubmit(target.trim())
  }

  return (
    <form onSubmit={submit} noValidate className="flex flex-col gap-3" aria-label="Start a scan">
      <label htmlFor="target" className="text-sm font-medium">
        Domain or URL
      </label>
      <div className="flex flex-col gap-3 sm:flex-row">
        <div className="relative min-w-0 flex-1">
          <Globe aria-hidden="true" size={18} className="pointer-events-none absolute top-1/2 left-4 -translate-y-1/2 text-faint" />
          <input
            id="target"
            name="target"
            className="field pl-11 font-mono"
            placeholder="example.com"
            autoComplete="off"
            autoCapitalize="none"
            spellCheck={false}
            inputMode="url"
            value={target}
            onChange={(e) => {
              setTarget(e.target.value)
              if (error) setError(null)
            }}
            aria-invalid={shown ? true : undefined}
            aria-describedby={shown ? 'target-error' : 'target-hint'}
          />
        </div>
        <Button type="submit" variant="primary" className="sm:w-auto" icon={<ArrowRight size={18} aria-hidden="true" />}>
          Continue
        </Button>
      </div>
      {shown ? (
        <p id="target-error" role="alert" className="text-sm text-danger">
          {shown}
        </p>
      ) : (
        <p id="target-hint" className="text-xs text-muted">
          Passive checks only. Ports 80/443, public domains. You'll confirm authorization next.
        </p>
      )}
    </form>
  )
}
