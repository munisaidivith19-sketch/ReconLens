import { Server } from 'lucide-react'

import type { DnsResult, WhoisResult } from '../../types/scan'
import { Badge } from '../ui/Badge'
import { Card, CardHeader } from '../ui/Card'
import { Empty, KeyValue } from '../ui/Disclosure'
import { formatDate } from '../ui/format'

const ORDER = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'CAA']

export function DnsPanel({ data, whois }: { data?: DnsResult; whois?: WhoisResult }) {
  const records = data?.records ?? {}
  const present = ORDER.filter((t) => (records[t] ?? []).length > 0)
  return (
    <Card aria-labelledby="dns-title">
      <CardHeader id="dns-title" title="DNS & registration" icon={<Server size={20} />} />

      {whois?.available ? (
        <div className="mb-5 rounded-2xl border border-glass-border bg-glass p-4">
          <KeyValue
            items={[
              { label: 'Registrar', value: whois.registrar ?? 'n/a' },
              { label: 'Registered domain', value: <span className="font-mono">{whois.registrable_domain}</span> },
              { label: 'Created', value: formatDate(whois.created) },
              {
                label: 'Expires',
                value: (
                  <span className="flex flex-wrap items-center gap-2">
                    {formatDate(whois.expires)}
                    {whois.days_until_expiry !== null && whois.days_until_expiry !== undefined && (
                      <Badge tone={whois.days_until_expiry < 30 ? 'danger' : whois.days_until_expiry < 90 ? 'warn' : 'ok'}>
                        {whois.days_until_expiry} days
                      </Badge>
                    )}
                  </span>
                ),
              },
            ]}
          />
        </div>
      ) : (
        <p className="mb-4 text-sm text-muted">{whois?.message ?? 'Registration data unavailable.'}</p>
      )}

      {present.length === 0 ? (
        <Empty>No DNS records were returned.</Empty>
      ) : (
        <dl className="flex flex-col gap-3">
          {present.map((t) => (
            <div key={t} className="grid gap-2 sm:grid-cols-[4.5rem_1fr]">
              <dt>
                <Badge tone="accent">{t}</Badge>
              </dt>
              <dd className="flex min-w-0 flex-col gap-1">
                {records[t].map((v) => (
                  <code key={v} className="rounded-lg bg-glass px-2.5 py-1.5 text-xs text-muted [overflow-wrap:anywhere]">
                    {v}
                  </code>
                ))}
              </dd>
            </div>
          ))}
        </dl>
      )}
    </Card>
  )
}
