import { useState } from 'react'
import { Link } from 'react-router'
import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { ChevronLeft, ChevronRight, History as HistoryIcon, Radar } from 'lucide-react'

import { api, ApiError } from '../api/client'
import { Alert } from '../components/ui/Alert'
import { Badge, severityClass } from '../components/ui/Badge'
import { Button } from '../components/ui/Button'
import { Card, CardHeader } from '../components/ui/Card'
import { cn } from '../components/ui/cn'
import { formatDateTime } from '../components/ui/format'
import type { ScanStatus, ScanSummary, Severity } from '../types/scan'

const PAGE_SIZE = 15
const STATUS_TONE: Record<ScanStatus, 'accent' | 'ok' | 'danger' | 'warn' | 'neutral'> = {
  queued: 'neutral',
  running: 'accent',
  completed: 'ok',
  failed: 'danger',
  interrupted: 'warn',
}

function scoreLevel(score: number): Severity {
  if (score >= 70) return 'critical'
  if (score >= 45) return 'high'
  if (score >= 20) return 'medium'
  if (score > 0) return 'low'
  return 'info'
}

function Score({ s }: { s: ScanSummary }) {
  if (s.risk_score === null) return <span className="text-muted">n/a</span>
  return (
    <span className={cn('font-mono font-semibold tabular-nums', severityClass(scoreLevel(s.risk_score)))}>
      {s.risk_score}
      <span className="text-xs text-muted">/100</span>
    </span>
  )
}

export default function History() {
  const [page, setPage] = useState(1)
  const { data, error, isLoading, isFetching } = useQuery({
    queryKey: ['scans', page, PAGE_SIZE],
    queryFn: () => api.listScans(page, PAGE_SIZE),
    placeholderData: keepPreviousData,
  })
  const pages = data ? Math.max(1, Math.ceil(data.total / PAGE_SIZE)) : 1

  return (
    <div className="flex flex-col gap-5">
      <Card strong className="animate-rise">
        <CardHeader
          title={<span className="text-2xl font-bold">Scan history</span>}
          icon={<HistoryIcon size={20} />}
          description="Your scans from the last 30 days"
          action={
            <Link to="/" className="btn btn-primary btn-sm">
              <Radar size={16} aria-hidden="true" /> New scan
            </Link>
          }
        />
      </Card>

      {error && <Alert tone="danger" title="Couldn't load your scans">{error instanceof ApiError ? error.message : 'Please try again.'}</Alert>}

      {isLoading ? (
        <div className="flex flex-col gap-2" aria-busy="true">
          {Array.from({ length: 4 }, (_, i) => (
            <div key={i} className="skeleton h-16" />
          ))}
        </div>
      ) : data && data.items.length === 0 ? (
        <Card className="text-center">
          <p className="text-muted">No scans yet.</p>
          <Link to="/" className="btn btn-primary mt-4">
            Run your first scan
          </Link>
        </Card>
      ) : data ? (
        <Card padded={false} className={cn('overflow-hidden transition-opacity', isFetching && 'opacity-70')}>
          {/* Table on wide screens */}
          <table className="hidden w-full text-left text-sm md:table">
            <caption className="sr-only">Past scans</caption>
            <thead className="border-b border-glass-border text-xs tracking-wide text-muted uppercase">
              <tr>
                <th scope="col" className="px-6 py-3 font-semibold">Domain</th>
                <th scope="col" className="px-6 py-3 font-semibold">Date</th>
                <th scope="col" className="px-6 py-3 font-semibold">Risk</th>
                <th scope="col" className="px-6 py-3 font-semibold">Findings</th>
                <th scope="col" className="px-6 py-3 font-semibold">Status</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((s) => (
                <tr key={s.id} className="border-b border-glass-border/60 transition-colors last:border-0 hover:bg-glass">
                  <td className="max-w-xs px-6 py-3.5">
                    <Link to={`/scans/${s.id}`} className="font-mono font-semibold break-all text-accent-text underline-offset-4 hover:underline">
                      {s.domain}
                    </Link>
                  </td>
                  <td className="px-6 py-3.5 whitespace-nowrap text-muted">{formatDateTime(s.created_at)}</td>
                  <td className="px-6 py-3.5"><Score s={s} /></td>
                  <td className="px-6 py-3.5 tabular-nums">{s.findings_count}</td>
                  <td className="px-6 py-3.5">
                    <span className="flex flex-wrap gap-1.5">
                      <Badge tone={STATUS_TONE[s.status]}>{s.status}</Badge>
                      {s.cached && <Badge>cached</Badge>}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {/* Cards on small screens */}
          <ul className="flex flex-col md:hidden">
            {data.items.map((s) => (
              <li key={s.id} className="border-b border-glass-border/60 last:border-0">
                <Link to={`/scans/${s.id}`} className="flex flex-col gap-2 px-5 py-4 transition-colors hover:bg-glass">
                  <div className="flex items-start justify-between gap-3">
                    <span className="min-w-0 font-mono font-semibold break-all text-accent-text">{s.domain}</span>
                    <Score s={s} />
                  </div>
                  <div className="flex flex-wrap items-center gap-2 text-xs text-muted">
                    <Badge tone={STATUS_TONE[s.status]}>{s.status}</Badge>
                    <span>{formatDateTime(s.created_at)}</span>
                    <span>· {s.findings_count} findings</span>
                  </div>
                </Link>
              </li>
            ))}
          </ul>
        </Card>
      ) : null}

      {data && data.total > PAGE_SIZE && (
        <nav aria-label="Pagination" className="flex flex-wrap items-center justify-between gap-3">
          <Button size="sm" disabled={page <= 1} onClick={() => setPage((p) => p - 1)} icon={<ChevronLeft size={16} aria-hidden="true" />}>
            Previous
          </Button>
          <span className="text-sm text-muted" aria-live="polite">
            Page {page} of {pages}
          </span>
          <Button size="sm" disabled={page >= pages} onClick={() => setPage((p) => p + 1)}>
            Next <ChevronRight size={16} aria-hidden="true" />
          </Button>
        </nav>
      )}
    </div>
  )
}
