import { useQuery } from '@tanstack/react-query'
import { GitCompareArrows } from 'lucide-react'
import { Link } from 'react-router'

import { api } from '../../api/client'
import type { Finding, ScanDetail } from '../../types/scan'
import { Badge, SeverityBadge } from '../ui/Badge'
import { Card, CardHeader } from '../ui/Card'
import { Disclosure } from '../ui/Disclosure'
import { formatDateTime } from '../ui/format'
import { bySeverity } from './taxonomy'

function FindingRows({ items }: { items: Finding[] }) {
  return (
    <ul className="flex max-h-64 flex-col gap-1.5 overflow-y-auto pr-1 print:max-h-none">
      {items.map((f) => (
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
  )
}

/** What changed since the previous completed scan of the same domain. Hidden when there is none. */
export function ScanComparison({ scan }: { scan: ScanDetail }) {
  const { data } = useQuery({
    queryKey: ['scan-previous', scan.id],
    queryFn: () => api.previousScan(scan.id),
    staleTime: 5 * 60_000,
  })
  const prev = data?.previous
  if (!prev) return null

  const prevIds = new Set(prev.findings.map((f) => f.id))
  const curIds = new Set(scan.findings.map((f) => f.id))
  const added = scan.findings.filter((f) => !prevIds.has(f.id) && f.severity !== 'info').sort(bySeverity)
  const fixed = prev.findings.filter((f) => !curIds.has(f.id) && f.severity !== 'info').sort(bySeverity)
  const prevSubs = new Set(prev.results.subdomains?.subdomains ?? [])
  const newSubs = (scan.results.subdomains?.subdomains ?? []).filter((s) => !prevSubs.has(s))
  const delta = (scan.risk_score ?? 0) - (prev.risk_score ?? 0)

  return (
    <Card aria-labelledby="compare-title">
      <CardHeader
        id="compare-title"
        title="Changes since last scan"
        icon={<GitCompareArrows size={20} />}
        description={
          <>
            Compared with{' '}
            <Link to={`/scans/${prev.id}`} className="text-accent-text underline-offset-4 hover:underline">
              the scan from {formatDateTime(prev.created_at)}
            </Link>
            .
          </>
        }
        action={
          <Badge tone={delta > 0 ? 'danger' : delta < 0 ? 'ok' : 'neutral'}>
            risk {prev.risk_score ?? 0} → {scan.risk_score ?? 0}
          </Badge>
        }
      />
      <div className="grid gap-3 sm:grid-cols-3">
        <div className="rounded-xl bg-glass px-3 py-2.5">
          <p className="font-mono text-xl font-bold text-danger">{added.length}</p>
          <p className="text-xs text-muted">new issues</p>
        </div>
        <div className="rounded-xl bg-glass px-3 py-2.5">
          <p className="font-mono text-xl font-bold text-ok">{fixed.length}</p>
          <p className="text-xs text-muted">fixed issues</p>
        </div>
        <div className="rounded-xl bg-glass px-3 py-2.5">
          <p className="font-mono text-xl font-bold">{newSubs.length}</p>
          <p className="text-xs text-muted">new subdomains</p>
        </div>
      </div>
      <div className="mt-4 flex flex-col gap-2">
        {added.length > 0 && (
          <Disclosure summary={<span className="font-medium">New issues ({added.length})</span>}>
            <FindingRows items={added} />
          </Disclosure>
        )}
        {fixed.length > 0 && (
          <Disclosure summary={<span className="font-medium">Fixed issues ({fixed.length})</span>}>
            <FindingRows items={fixed} />
          </Disclosure>
        )}
        {newSubs.length > 0 && (
          <Disclosure summary={<span className="font-medium">New subdomains ({newSubs.length})</span>}>
            <ul className="flex max-h-64 flex-col gap-1 overflow-y-auto pr-1 print:max-h-none">
              {newSubs.map((s) => (
                <li key={s} className="font-mono text-xs text-muted [overflow-wrap:anywhere]">
                  {s}
                </li>
              ))}
            </ul>
          </Disclosure>
        )}
      </div>
    </Card>
  )
}
