import { Network } from 'lucide-react'

import type { OriginHintsResult } from '../../types/scan'
import { Badge } from '../ui/Badge'
import { Card, CardHeader } from '../ui/Card'
import { Disclosure, Empty } from '../ui/Disclosure'

export function OriginHintsPanel({ data }: { data?: OriginHintsResult }) {
  const candidates = data?.candidates ?? []
  const groups = (data?.ip_groups ?? []).filter((g) => g.count > 1)
  return (
    <Card aria-labelledby="origin-title" className="flex flex-col">
      <CardHeader
        id="origin-title"
        title="CDN bypass / origin hints"
        icon={<Network size={20} />}
        description="Subdomains that resolve to addresses other than the main site's. Built from DNS answers already collected."
        action={
          data ? (
            <Badge tone={data.behind_cdn ? 'accent' : 'neutral'}>
              {data.behind_cdn ? `behind ${data.cdn.join(', ')}` : 'no CDN detected'}
            </Badge>
          ) : undefined
        }
      />
      {!data ? (
        <Empty>Not checked in this scan.</Empty>
      ) : (
        <div className="flex flex-col gap-4">
          {data.main_ips.length > 0 && (
            <p className="text-sm text-muted [overflow-wrap:anywhere]">
              Main site: <span className="font-mono text-fg">{data.main_ips.join(', ')}</span>
            </p>
          )}
          {candidates.length === 0 ? (
            <Empty>
              {data.resolved_count === 0
                ? 'No subdomain addresses were resolved.'
                : 'Every resolved subdomain shares the main site’s addresses or a CDN.'}
            </Empty>
          ) : (
            <section aria-label="Subdomains outside the main site">
              <h3 className="mb-2 text-sm font-semibold text-muted">
                {data.behind_cdn ? 'Resolve outside the CDN' : 'Other servers'} ({candidates.length})
              </h3>
              <ul className="flex max-h-72 flex-col gap-1.5 overflow-y-auto pr-1 print:max-h-none">
                {candidates.map((c) => (
                  <li
                    key={c.name}
                    className="grid min-w-0 gap-1 rounded-xl bg-glass px-3 py-2 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-center"
                  >
                    <span className="min-w-0">
                      <span className="block font-mono text-xs font-semibold [overflow-wrap:anywhere]">{c.name}</span>
                      <span className="block font-mono text-xs text-muted [overflow-wrap:anywhere]">
                        {c.ips.join(', ')}
                      </span>
                    </span>
                    <span className="flex flex-wrap gap-1.5 sm:justify-self-end">
                      {c.hint && <Badge tone={data.behind_cdn ? 'warn' : 'neutral'}>{c.hint}</Badge>}
                      {c.same_network && <Badge title="Same /24 network as the main site">same network</Badge>}
                    </span>
                  </li>
                ))}
              </ul>
            </section>
          )}
          {groups.length > 0 && (
            <Disclosure
              summary={
                <span className="flex min-w-0 items-center justify-between gap-3">
                  <span className="font-medium">Shared hosting map</span>
                  <Badge>{groups.length} IPs</Badge>
                </span>
              }
            >
              <ul className="flex max-h-64 flex-col gap-2 overflow-y-auto pr-1 print:max-h-none">
                {groups.map((g) => (
                  <li key={g.ip} className="min-w-0 text-xs">
                    <span className="font-mono font-semibold">{g.ip}</span>{' '}
                    <span className="text-faint">({g.count})</span>
                    <span className="block font-mono text-muted [overflow-wrap:anywhere]">{g.names.join(', ')}</span>
                  </li>
                ))}
              </ul>
            </Disclosure>
          )}
          <p className="mt-auto text-xs text-faint">
            {data.resolved_count} subdomains resolved to {data.unique_ips} unique address(es).
          </p>
        </div>
      )}
    </Card>
  )
}
