import { Ban, ExternalLink } from 'lucide-react'

import type { BlocklistsResult } from '../../types/scan'
import { Badge } from '../ui/Badge'
import { Card, CardHeader } from '../ui/Card'
import { Empty } from '../ui/Disclosure'

function StatusBadge({ status }: { status: string }) {
  if (status === 'listed') return <Badge tone="danger">listed</Badge>
  if (status === 'not_listed') return <Badge tone="ok">not listed</Badge>
  if (status === 'skipped') return <Badge>not configured</Badge>
  return <Badge tone="warn">unavailable</Badge>
}

export function BlocklistsPanel({ data }: { data?: BlocklistsResult }) {
  const urlhaus = data?.urlhaus
  return (
    <Card aria-labelledby="blocklists-title" className="flex flex-col">
      <CardHeader
        id="blocklists-title"
        title="Blocklists"
        icon={<Ban size={20} />}
        description="Community blocklists used by mail servers, browsers and security tools. A listing means links and email from the domain are being blocked."
      />
      {!data ? (
        <Empty>Not checked in this scan.</Empty>
      ) : (
        <ul className="flex flex-col gap-1.5">
          {Object.entries(data.spamhaus_dbl).map(([name, r]) => (
            <li key={name} className="min-w-0 rounded-xl bg-glass px-3 py-2">
              <span className="flex flex-wrap items-center justify-between gap-2">
                <span className="text-sm">
                  <span className="font-semibold">Spamhaus DBL</span>{' '}
                  <code className="font-mono text-xs text-muted">{name}</code>
                </span>
                <StatusBadge status={r.status} />
              </span>
              {r.reasons.length > 0 && <span className="block text-xs text-danger">{r.reasons.join(', ')}</span>}
              {r.message && <span className="block text-xs text-muted">{r.message}</span>}
            </li>
          ))}
          {urlhaus && (
            <li className="min-w-0 rounded-xl bg-glass px-3 py-2">
              <span className="flex flex-wrap items-center justify-between gap-2">
                <span className="text-sm font-semibold">abuse.ch URLhaus</span>
                <StatusBadge status={urlhaus.status} />
              </span>
              {urlhaus.message && <span className="block text-xs text-muted">{urlhaus.message}</span>}
              {urlhaus.status === 'listed' && (
                <>
                  <span className="block text-xs text-muted">
                    {urlhaus.url_count} malware URL(s), {urlhaus.online ?? 0} online
                  </span>
                  <ul className="mt-1.5 flex flex-col gap-1">
                    {(urlhaus.urls ?? []).map((u) => (
                      <li key={u.url} className="font-mono text-xs [overflow-wrap:anywhere]">
                        <span className={u.status === 'online' ? 'text-danger' : 'text-faint'}>{u.status}</span> {u.url}
                      </li>
                    ))}
                  </ul>
                  {urlhaus.reference && (
                    <a
                      href={urlhaus.reference}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="mt-1.5 inline-flex items-center gap-1 text-xs font-semibold text-accent-text hover:underline"
                    >
                      URLhaus report <ExternalLink size={12} aria-hidden="true" />
                      <span className="sr-only">(opens in a new tab)</span>
                    </a>
                  )}
                </>
              )}
            </li>
          )}
        </ul>
      )}
    </Card>
  )
}
