import { Link, useParams } from 'react-router'
import { ArrowLeft, CalendarClock } from 'lucide-react'

import { ApiError } from '../api/client'
import { ExportButtons } from '../components/report/ExportButtons'
import { Report } from '../components/report/Report'
import { ShareButton } from '../components/report/ShareButton'
import { ProgressTracker } from '../components/scan/ProgressTracker'
import { Alert } from '../components/ui/Alert'
import { Badge } from '../components/ui/Badge'
import { Card } from '../components/ui/Card'
import { formatDateTime } from '../components/ui/format'
import { useAuth } from '../hooks/useAuth'
import { ACTIVE_STATUSES, useScan } from '../hooks/useScan'
import type { ScanStatus } from '../types/scan'

const STATUS_TONE: Record<ScanStatus, 'accent' | 'ok' | 'danger' | 'warn' | 'neutral'> = {
  queued: 'neutral',
  running: 'accent',
  completed: 'ok',
  failed: 'danger',
  interrupted: 'warn',
}

function Skeleton() {
  return (
    <div className="flex flex-col gap-5" aria-busy="true" aria-label="Loading scan">
      <div className="skeleton h-24" />
      <div className="grid gap-5 lg:grid-cols-3">
        <div className="skeleton h-80" />
        <div className="skeleton h-80 lg:col-span-2" />
      </div>
    </div>
  )
}

export default function ScanResult() {
  const { isGuest } = useAuth()
  const { id } = useParams()
  const { data: scan, error, isLoading } = useScan(id)

  if (isLoading) return <Skeleton />
  if (error || !scan) {
    const notFound = error instanceof ApiError && error.status === 404
    return (
      <Alert
        tone="danger"
        title={notFound ? 'Scan not found' : "Couldn't load this scan"}
        action={
          <Link to={isGuest ? '/' : '/history'} className="btn btn-sm">
            {isGuest ? 'New scan' : 'Scan history'}
          </Link>
        }
      >
        {notFound
          ? 'It may have expired (scans are kept for 30 days) or belong to another account.'
          : error instanceof ApiError
            ? error.message
            : 'Please try again.'}
      </Alert>
    )
  }

  const active = ACTIVE_STATUSES.has(scan.status)
  const hasReport = scan.status === 'completed' || (scan.status !== 'queued' && scan.findings.length > 0 && !active)

  return (
    <div className="flex flex-col gap-5">
      <Link to={isGuest ? '/' : '/history'} className="no-print btn btn-sm btn-ghost w-fit text-muted">
        <ArrowLeft size={16} aria-hidden="true" /> {isGuest ? 'New scan' : 'All scans'}
      </Link>

      <Card strong className="animate-rise">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0">
            <p className="text-xs tracking-wide text-muted uppercase">Attack-surface report</p>
            <h1 className="mt-1 font-mono text-2xl font-bold break-all sm:text-3xl">{scan.domain}</h1>
            <div className="mt-2 flex flex-wrap items-center gap-2 text-sm text-muted">
              <Badge tone={STATUS_TONE[scan.status]}>{scan.status}</Badge>
              {scan.cached && <Badge title="Results reused from a scan of this domain in the last 24 hours">cached result</Badge>}
              <span className="inline-flex items-center gap-1.5">
                <CalendarClock size={14} aria-hidden="true" />
                {formatDateTime(scan.created_at)}
              </span>
              <span>Authorization confirmed {formatDateTime(scan.authorized_at)}</span>
            </div>
          </div>
          {!active && (
            <div className="flex flex-col items-start gap-2 sm:items-end">
              <ExportButtons scan={scan} />
              {!isGuest && scan.status === 'completed' && <ShareButton scanId={scan.id} />}
            </div>
          )}
        </div>
      </Card>

      {scan.status === 'interrupted' && (
        <Alert
          tone="warning"
          title="This scan was interrupted"
          action={
            <Link to="/" className="btn btn-sm btn-primary">
              Start a new scan
            </Link>
          }
        >
          {scan.error ?? 'The server restarted while the scan was running.'}
        </Alert>
      )}
      {scan.status === 'failed' && (
        <Alert tone="danger" title="The scan failed">
          {scan.error ?? 'Something went wrong. Please try again later.'}
        </Alert>
      )}

      {active && <ProgressTracker stages={scan.stages} queued={scan.status === 'queued'} />}
      {hasReport && <Report scan={scan} />}
    </div>
  )
}
