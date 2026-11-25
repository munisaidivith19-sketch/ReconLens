import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router'
import { ArrowLeft, Radar, ShieldAlert } from 'lucide-react'

import { Button } from '../ui/Button'

interface ScopeConfirmProps {
  target: string
  busy: boolean
  onBack: () => void
  onConfirm: () => void
}

function displayHost(target: string): string {
  try {
    return new URL(/^https?:\/\//i.test(target) ? target : `https://${target}`).hostname
  } catch {
    return target
  }
}

export function ScopeConfirm({ target, busy, onBack, onConfirm }: ScopeConfirmProps) {
  const [checked, setChecked] = useState(false)
  const headingRef = useRef<HTMLHeadingElement>(null)

  useEffect(() => headingRef.current?.focus(), [])

  return (
    <div className="flex flex-col gap-5" role="group" aria-labelledby="scope-title">
      <div className="flex items-start gap-3">
        <span aria-hidden="true" className="grid size-11 shrink-0 place-items-center rounded-2xl bg-glass-strong text-warn">
          <ShieldAlert size={22} />
        </span>
        <div className="min-w-0">
          <h2 id="scope-title" ref={headingRef} tabIndex={-1} className="text-xl font-semibold outline-none">
            Confirm you're authorized
          </h2>
          <p className="text-sm text-muted">ReconLens only scans targets you're allowed to test.</p>
        </div>
      </div>

      <div className="rounded-2xl border border-glass-border bg-glass p-4">
        <p className="text-xs tracking-wide text-muted uppercase">Target</p>
        <p className="mt-1 font-mono text-lg font-semibold break-all text-accent-text">{displayHost(target)}</p>
      </div>

      <label className="flex cursor-pointer items-start gap-3 rounded-2xl border border-glass-border bg-glass p-4 transition-colors hover:bg-glass-strong">
        <input
          type="checkbox"
          className="mt-1 size-5 shrink-0 cursor-pointer accent-[var(--accent)]"
          checked={checked}
          onChange={(e) => setChecked(e.target.checked)}
        />
        <span className="text-sm leading-relaxed">
          I own this domain, or I'm explicitly authorized to test it (it's in scope for a bug bounty program or covered
          by written permission). I understand my confirmation and its time are recorded, and I agree to the{' '}
          <Link to="/terms" target="_blank" className="font-semibold text-accent-text underline underline-offset-4">
            responsible use policy
          </Link>
          .
        </span>
      </label>

      <div className="flex flex-col-reverse gap-3 sm:flex-row sm:justify-between">
        <Button variant="ghost" onClick={onBack} disabled={busy} icon={<ArrowLeft size={18} aria-hidden="true" />}>
          Change target
        </Button>
        <Button
          variant="primary"
          onClick={onConfirm}
          disabled={!checked}
          loading={busy}
          icon={<Radar size={18} aria-hidden="true" />}
        >
          Start passive scan
        </Button>
      </div>
    </div>
  )
}
