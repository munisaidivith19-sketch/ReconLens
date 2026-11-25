import { Link, useParams } from 'react-router'
import { ArrowLeft, CalendarClock, ShieldQuestion } from 'lucide-react'

import { ApiError } from '../api/client'
import { AiReport } from '../components/report/AiReport'
import { CveTable } from '../components/report/CveTable'
import { DnsPanel } from '../components/report/DnsPanel'
import { EmailSecurityPanel } from '../components/report/EmailSecurityPanel'
import { EndpointsPanel } from '../components/report/EndpointsPanel'
import { ExportButtons } from '../components/report/ExportButtons'
import { FindingsList } from '../components/report/FindingsList'
import { RiskScore } from '../components/report/RiskScore'
import { SubdomainsPanel } from '../components/report/SubdomainsPanel'
import { TechStackPanel } from '../components/report/TechStackPanel'
import { WebSecurityPanel } from '../components/report/WebSecurityPanel'
import { ProgressTracker } from '../components/scan/ProgressTracker'
import { Alert } from '../components/ui/Alert'
import { Badge } from '../components/ui/Badge'
import { Card, CardHeader } from '../components/ui/Card'
import { formatDateTime } from '../components/ui/format'
import { ACTIVE_STATUSES, useScan } from '../hooks/useScan'
import type { ScanDetail, ScanStatus, VirusTotalResult } from '../types/scan'

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

function ReputationCard({ data }: { data?: VirusTotalResult }) {
  const stats = data?.stats ?? {}
  return (
    <Card aria-labelledby="vt-title">
      <CardHeader id="vt-title" title="Reputation" icon={<ShieldQuestion size={20} />} description="VirusTotal domain report" />
      {!data || data.status !== 'ok' ? (
        <p className="text-sm text-muted">{data?.message ?? 'Reputation data unavailable.'}</p>
      ) : (
        <div className="flex flex-col gap-3">
          <div className="flex flex-wrap gap-2">
            <Badge tone={stats.malicious ? 'danger' : 'ok'}>{stats.malicious ?? 0} malicious</Badge>
            <Badge tone={stats.suspicious ? 'warn' : 'neutral'}>{stats.suspicious ?? 0} suspicious</Badge>
            <Badge>{stats.harmless ?? 0} harmless</Badge>
            {typeof data.reputation === 'number' && <Badge>reputation {data.reputation}</Badge>}
          </div>
          {data.permalink && (
            <a
              href={data.permalink}
              target="_blank"
              rel="noopener noreferrer"
              className="text-sm font-semibold text-accent-text underline-offset-4 hover:underline"
            >
              View on VirusTotal
            </a>
          )}
        </div>
      )}
    </Card>
  )
}

function Report({ scan }: { scan: ScanDetail }) {
  const r = scan.results
  const failed = scan.stages.filter((s) => s.status === 'failed')
  return (
    <div className="flex flex-col gap-5">
      {failed.length > 0 && (
        <Alert tone="warning" title={`${failed.length} check(s) did not complete`}>
          {failed.map((s) => `${s.label}: ${s.error ?? 'failed'}`).join(' · ')}. The rest of the report is unaffected.
        </Alert>
      )}
      <div className="grid items-start gap-5 lg:grid-cols-3">
        <div className="flex min-w-0 flex-col gap-5">
          <RiskScore score={scan.risk_score ?? 0} factors={scan.score_factors} />
          <ReputationCard data={r.virustotal} />
        </div>
        <div className="min-w-0 lg:col-span-2">
          <AiReport report={scan.ai_report} />
        </div>
      </div>
      <FindingsList findings={scan.findings} />
      <EmailSecurityPanel data={r.email_security} />
      <div className="grid items-start gap-5 lg:grid-cols-2">
        <TechStackPanel data={r.tech_stack} />
        <CveTable data={r.cve_lookup} />
      </div>
      <WebSecurityPanel tls={r.tls_check} headers={r.security_headers} />
      <div className="grid items-start gap-5 lg:grid-cols-2">
        <EndpointsPanel data={r.endpoints} robots={r.robots_sitemap} />
        <SubdomainsPanel data={r.subdomains} />
      </div>
      <DnsPanel data={r.dns_records} whois={r.whois_rdap} />
    </div>
  )
}

export default function ScanResult() {
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
          <Link to="/history" className="btn btn-sm">
            Scan history
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
      <Link to="/history" className="no-print btn btn-sm btn-ghost w-fit text-muted">
        <ArrowLeft size={16} aria-hidden="true" /> All scans
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
          {!active && <ExportButtons scanId={scan.id} domain={scan.domain} />}
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
