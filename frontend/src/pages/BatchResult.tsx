import { useQuery } from '@tanstack/react-query'
import { ArrowLeft, Layers } from 'lucide-react'
import { Link, useParams } from 'react-router'

import { api, ApiError } from '../api/client'
import { Alert } from '../components/ui/Alert'
import { Badge, SEVERITY_LABEL, SeverityBadge, severityClass } from '../components/ui/Badge'
import { Card, CardHeader } from '../components/ui/Card'
import { cn } from '../components/ui/cn'
import { Empty } from '../components/ui/Disclosure'
import { formatDateTime } from '../components/ui/format'
import { Spinner } from '../components/ui/Spinner'
import { ACTIVE_STATUSES } from '../hooks/useScan'
import { SEVERITIES, type BatchDetail, type Severity } from '../types/scan'

function riskTone(score: number | null): 'danger' | 'warn' | 'ok' | 'neutral' {
  if (score === null) return 'neutral'
  return score >= 60 ? 'danger' : score >= 30 ? 'warn' : 'ok'
}

/** Combined view of a multi-domain scan; polls until every scan finishes. */
export default function BatchResult() {
  const { id } = useParams()
  const { data, error, isLoading } = useQuery<BatchDetail>({
    queryKey: ['batch', id],
    queryFn: () => api.getBatch(id!),
    enabled: Boolean(id),
    refetchInterval: (q) => (q.state.data?.scans.some((s) => ACTIVE_STATUSES.has(s.status)) ? 3000 : false),
  })

  if (isLoading)
    return (
      <div className="grid place-items-center py-24">
        <Spinner label="Loading batch…" />
      </div>
    )
  if (error || !data)
    return (
      <Alert tone="danger" title="Batch not found">
        {error instanceof ApiError ? error.message : 'It may have expired (batches are kept for 30 days).'}
      </Alert>
    )

  const totals: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  data.scans.forEach((s) => SEVERITIES.forEach((sev) => (totals[sev] += s.severities[sev] ?? 0)))
  const running = data.scans.filter((s) => ACTIVE_STATUSES.has(s.status)).length
  const ranked = [...data.scans].sort((a, b) => (b.risk_score ?? -1) - (a.risk_score ?? -1))

  return (
    <div className="flex flex-col gap-5">
      <Link to="/history" className="btn btn-sm btn-ghost w-fit text-muted">
        <ArrowLeft size={16} aria-hidden="true" /> All scans
      </Link>

      <Card strong className="animate-rise">
        <CardHeader
          title="Multi-domain scan"
          icon={<Layers size={20} />}
          description={`${data.targets.length} domain(s) · started ${formatDateTime(data.created_at)}`}
          action={running ? <Badge tone="accent">{running} running</Badge> : <Badge tone="ok">complete</Badge>}
        />
        <div className="grid grid-cols-5 gap-1.5" aria-label="Combined findings by severity">
          {SEVERITIES.map((s) => (
            <div key={s} className={cn('chip flex min-w-0 flex-col justify-center gap-0 rounded-xl px-1 py-2 text-center', severityClass(s))}>
              <span className="font-mono text-lg font-bold">{totals[s]}</span>
              <span className="text-[0.7rem]">{SEVERITY_LABEL[s]}</span>
            </div>
          ))}
        </div>
      </Card>

      {data.errors.length > 0 && (
        <Alert tone="warning" title={`${data.errors.length} domain(s) were not scanned`}>
          {data.errors.map((e) => `${e.target}: ${e.message}`).join(' · ')}
        </Alert>
      )}

      {ranked.length === 0 ? (
        <Empty>No scans in this batch.</Empty>
      ) : (
        <ul className="grid gap-4 lg:grid-cols-2">
          {ranked.map((s) => (
            <li key={s.id}>
              <Card className="flex h-full flex-col">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="min-w-0">
                    <Link
                      to={`/scans/${s.id}`}
                      className="font-mono text-lg font-bold break-all text-accent-text underline-offset-4 hover:underline"
                    >
                      {s.domain}
                    </Link>
                    <p className="mt-1 flex flex-wrap items-center gap-2 text-sm text-muted">
                      <Badge tone={ACTIVE_STATUSES.has(s.status) ? 'accent' : s.status === 'completed' ? 'ok' : 'warn'}>
                        {s.status}
                      </Badge>
                      {s.cached && <Badge>cached</Badge>}
                      <span>{s.findings_count} findings</span>
                    </p>
                  </div>
                  <div className="text-right">
                    <p className="text-xs text-muted">Risk</p>
                    <Badge tone={riskTone(s.risk_score)} className="font-mono text-base">
                      {s.risk_score ?? '–'}
                    </Badge>
                  </div>
                </div>
                {s.top_findings.length > 0 ? (
                  <ul className="mt-4 flex flex-col gap-1.5">
                    {s.top_findings.map((f) => (
                      <li
                        key={f.id}
                        className="grid min-w-0 gap-1 rounded-xl bg-glass px-3 py-2 sm:grid-cols-[minmax(0,1fr)_6rem] sm:items-center"
                      >
                        <span className="min-w-0 text-sm [overflow-wrap:anywhere]">{f.title}</span>
                        <span className="sm:justify-self-end">
                          <SeverityBadge severity={f.severity} className="w-24 justify-center" />
                        </span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="mt-4 text-sm text-muted">
                    {ACTIVE_STATUSES.has(s.status) ? 'Scanning…' : 'No medium or higher findings.'}
                  </p>
                )}
                <Link to={`/scans/${s.id}`} className="btn btn-sm mt-4 w-fit self-end">
                  Full report
                </Link>
              </Card>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
