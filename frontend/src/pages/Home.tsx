import { useState } from 'react'
import { Link, useNavigate } from 'react-router'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Bug, Clock3, Fingerprint, Globe, Lock, LogIn, Mail, Radar, Route, UserPlus } from 'lucide-react'

import { api, ApiError } from '../api/client'
import { BatchForm } from '../components/scan/BatchForm'
import { ScanForm } from '../components/scan/ScanForm'
import { ScopeConfirm } from '../components/scan/ScopeConfirm'
import { WakeUpNotice } from '../components/scan/WakeUpNotice'
import { Alert } from '../components/ui/Alert'
import { Badge } from '../components/ui/Badge'
import { Card } from '../components/ui/Card'
import { blockedTargetMessage, formatDateTime } from '../components/ui/format'
import { useAuth } from '../hooks/useAuth'

const CHECKS = [
  { icon: Globe, label: 'DNS, RDAP & subdomains' },
  { icon: Lock, label: 'TLS & security headers' },
  { icon: Mail, label: 'SPF, DMARC & DKIM' },
  { icon: Fingerprint, label: 'Tech stack & versions' },
  { icon: Bug, label: 'CVEs with KEV & EPSS' },
  { icon: Route, label: 'Forms & archived endpoints' },
]

function SignUpPrompt({ limit }: { limit: number }) {
  return (
    <div className="flex flex-col items-center gap-4 py-2 text-center">
      <span aria-hidden="true" className="grid size-12 place-items-center rounded-2xl bg-glass-strong text-accent-text">
        <UserPlus size={24} />
      </span>
      <div>
        <h2 className="text-xl font-semibold">You've used your {limit} free scans</h2>
        <p className="mt-1 max-w-md text-muted">
          Create a free account or sign in to keep scanning. Accounts get 10 scans a day and a history of past reports.
        </p>
      </div>
      <div className="flex w-full flex-col gap-3 sm:w-auto sm:flex-row">
        <Link to="/register" className="btn btn-primary">
          <UserPlus size={18} aria-hidden="true" />
          Create account
        </Link>
        <Link to="/login" className="btn">
          <LogIn size={18} aria-hidden="true" />
          Sign in
        </Link>
      </div>
    </div>
  )
}

export default function Home() {
  const { isGuest } = useAuth()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [step, setStep] = useState<'target' | 'confirm'>('target')
  const [target, setTarget] = useState('')
  const [formError, setFormError] = useState<string | null>(null)
  const [pageError, setPageError] = useState<{ title: string; body: string } | null>(null)
  const [guestLimitHit, setGuestLimitHit] = useState(false)

  const quota = useQuery({ queryKey: ['quota'], queryFn: api.quota })
  const recent = useQuery({ queryKey: ['scans', 1, 3], queryFn: () => api.listScans(1, 3) })

  const create = useMutation({
    mutationFn: (t: string) => api.createScan(t),
    onSuccess: (res) => {
      void queryClient.invalidateQueries({ queryKey: ['quota'] })
      void queryClient.invalidateQueries({ queryKey: ['scans'] })
      navigate(`/scans/${res.scan.id}`)
    },
    onError: (err) => {
      if (err instanceof ApiError && err.code.startsWith('blocked_target')) {
        setFormError(blockedTargetMessage(err.code, err.message))
        setStep('target')
      } else if (err instanceof ApiError && err.code === 'guest_limit_reached') {
        setGuestLimitHit(true)
        setStep('target')
        void queryClient.invalidateQueries({ queryKey: ['quota'] })
      } else if (err instanceof ApiError && err.code === 'quota_exceeded') {
        setPageError({ title: 'Daily scan limit reached', body: err.message })
        setStep('target')
      } else if (err instanceof ApiError && err.status === 422) {
        setFormError('Please confirm you are authorized to test this target.')
      } else {
        setPageError({
          title: 'The scan could not be started',
          body: err instanceof ApiError ? err.message : 'Please try again.',
        })
      }
    },
  })

  const remaining = quota.data?.remaining
  const guestQuota = isGuest && quota.data?.guest
  const showSignUp = isGuest && (guestLimitHit || (guestQuota && remaining === 0))

  return (
    <div className="flex flex-col gap-8">
      <section className="animate-rise mx-auto flex max-w-3xl flex-col items-center gap-4 text-center">
        <Badge tone="accent">
          <Radar size={14} aria-hidden="true" /> Passive attack-surface analysis
        </Badge>
        <h1 className="text-3xl font-bold tracking-tight sm:text-5xl">
          What does your domain{' '}
          <span className="bg-gradient-to-r from-accent to-accent-2 bg-clip-text text-transparent">reveal?</span>
        </h1>
        <p className="max-w-2xl text-muted sm:text-lg">
          Enter a domain you're authorized to test. ReconLens gathers public signals, matches versions to known
          vulnerabilities, scores the risk and writes a prioritized report. It never sends anything intrusive.
        </p>
      </section>

      <div className="mx-auto flex w-full max-w-3xl flex-col gap-4">
        <WakeUpNotice />
        {pageError && (
          <Alert
            tone="danger"
            title={pageError.title}
            action={
              <button type="button" className="btn btn-sm" onClick={() => setPageError(null)}>
                Dismiss
              </button>
            }
          >
            {pageError.body}
          </Alert>
        )}

        <Card strong className="animate-rise p-6 sm:p-8" aria-label="New scan">
          {showSignUp ? (
            <SignUpPrompt limit={quota.data?.limit ?? 3} />
          ) : step === 'target' ? (
            <ScanForm
              initial={target}
              serverError={formError}
              onSubmit={(t) => {
                setTarget(t)
                setFormError(null)
                setPageError(null)
                setStep('confirm')
              }}
            />
          ) : (
            <ScopeConfirm
              target={target}
              busy={create.isPending}
              onBack={() => setStep('target')}
              onConfirm={() => create.mutate(target)}
            />
          )}
        </Card>

        {!isGuest && (
          <Card className="p-4 sm:p-5" aria-label="Multi-domain scan">
            <BatchForm remaining={remaining} />
          </Card>
        )}

        <div className="flex flex-wrap items-center justify-between gap-3 px-1 text-sm text-muted">
          <span className="flex items-center gap-2">
            <Clock3 size={16} aria-hidden="true" />
            {remaining === undefined
              ? 'Checking your quota…'
              : guestQuota
                ? `${remaining} of ${quota.data?.limit} free scans left without an account`
                : `${remaining} of ${quota.data?.limit} scans left today (resets 00:00 UTC)`}
          </span>
          {guestQuota ? (
            <span>
              <Link to="/register" className="font-semibold text-accent-text underline-offset-4 hover:underline">
                Create a free account
              </Link>{' '}
              for 10 scans a day.
            </span>
          ) : (
            <span>Results for a domain are reused for 24 hours.</span>
          )}
        </div>
      </div>

      <section aria-labelledby="checks-title" className="mx-auto w-full max-w-5xl">
        <h2 id="checks-title" className="sr-only">
          What ReconLens checks
        </h2>
        <ul className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {CHECKS.map((c, i) => (
            <li
              key={c.label}
              className="glass animate-rise flex items-center gap-3 rounded-2xl p-4"
              style={{ animationDelay: `${50 * i}ms` }}
            >
              <span aria-hidden="true" className="grid size-10 shrink-0 place-items-center rounded-xl bg-glass-strong text-accent-text">
                <c.icon size={19} />
              </span>
              <span className="font-medium">{c.label}</span>
            </li>
          ))}
        </ul>
      </section>

      {recent.data && recent.data.items.length > 0 && (
        <section aria-labelledby="recent-title" className="mx-auto w-full max-w-5xl">
          <div className="mb-3 flex items-center justify-between gap-3">
            <h2 id="recent-title" className="text-lg font-semibold">
              Recent scans
            </h2>
            {!isGuest && (
              <Link to="/history" className="btn btn-sm btn-ghost">
                View all
              </Link>
            )}
          </div>
          <ul className="grid gap-3 md:grid-cols-3">
            {recent.data.items.map((s) => (
              <li key={s.id} className="min-w-0">
                <Link
                  to={`/scans/${s.id}`}
                  className="glass glass-interactive flex h-full min-w-0 flex-col gap-1 rounded-2xl p-4"
                >
                  <span className="truncate font-mono font-semibold">{s.domain}</span>
                  <span className="text-xs text-muted">{formatDateTime(s.created_at)}</span>
                  <span className="mt-1 text-sm">
                    {s.risk_score !== null ? `Risk ${s.risk_score}/100` : s.status}
                  </span>
                </Link>
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  )
}
