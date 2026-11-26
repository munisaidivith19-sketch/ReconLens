import { useQuery } from '@tanstack/react-query'
import { CalendarClock, Eye } from 'lucide-react'
import { Link, useParams } from 'react-router'

import { api, ApiError } from '../api/client'
import { Report } from '../components/report/Report'
import { Alert } from '../components/ui/Alert'
import { Badge } from '../components/ui/Badge'
import { Card } from '../components/ui/Card'
import { formatDateTime } from '../components/ui/format'
import { Spinner } from '../components/ui/Spinner'

/** Public, read-only view of a report shared by its owner. No account needed. */
export default function SharedScan() {
  const { token } = useParams()
  const { data, error, isLoading } = useQuery({
    queryKey: ['shared', token],
    queryFn: () => api.getShared(token!),
    enabled: Boolean(token),
    retry: (count, err) => !(err instanceof ApiError && err.status === 404) && count < 2,
  })

  if (isLoading)
    return (
      <div className="grid place-items-center py-24">
        <Spinner label="Loading shared report…" />
      </div>
    )
  if (error || !data)
    return (
      <Alert
        tone="danger"
        title="This shared report isn't available"
        action={
          <Link to="/" className="btn btn-sm">
            Go to ReconLens
          </Link>
        }
      >
        {error instanceof ApiError ? error.message : 'Please try again later.'}
      </Alert>
    )

  const scan = data.scan
  return (
    <div className="flex flex-col gap-5">
      <Card strong className="animate-rise">
        <p className="inline-flex items-center gap-1.5 text-xs tracking-wide text-muted uppercase">
          <Eye size={14} aria-hidden="true" /> Shared read-only report
        </p>
        <h1 className="mt-1 font-mono text-2xl font-bold break-all sm:text-3xl">{scan.domain}</h1>
        <div className="mt-2 flex flex-wrap items-center gap-2 text-sm text-muted">
          <Badge tone="ok">{scan.status}</Badge>
          <span className="inline-flex items-center gap-1.5">
            <CalendarClock size={14} aria-hidden="true" />
            {formatDateTime(scan.created_at)}
          </span>
          <span>Link expires {formatDateTime(data.expires_at)}</span>
        </div>
      </Card>
      <Report scan={scan} compare={false} />
    </div>
  )
}
