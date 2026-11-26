import type { ReactNode } from 'react'
import { Server } from 'lucide-react'

import type { DnsResult, WhoisResult } from '../../types/scan'
import { Badge } from '../ui/Badge'
import { Card, CardHeader } from '../ui/Card'
import { Empty, KeyValue } from '../ui/Disclosure'
import { formatDate } from '../ui/format'

const ORDER = [
  'A',
  'AAAA',
  'CNAME',
  'MX',
  'NS',
  'SOA',
  'TXT',
  'CAA',
  'DS',
  'DNSKEY',
  'HTTPS',
  'SVCB',
  'TLSA',
  'SSHFP',
  'NAPTR',
  'URI',
  'LOC',
  'CERT',
]

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="min-w-0">
      <h3 className="mb-2 text-sm font-semibold text-muted">{title}</h3>
      {children}
    </section>
  )
}

function Status({ data }: { data: DnsResult }) {
  const dnssec = data.dnssec
  return (
    <div className="flex flex-wrap gap-2">
      {dnssec && (
        <Badge
          tone={dnssec.signed ? 'ok' : dnssec.ds ? 'danger' : 'warn'}
          title="DNSSEC protects DNS answers against forgery"
        >
          DNSSEC {dnssec.signed ? 'signed' : dnssec.ds ? 'broken' : 'not enabled'}
        </Badge>
      )}
      {data.wildcard !== undefined && (
        <Badge tone={data.wildcard ? 'warn' : 'neutral'} title="Whether any random subdomain name resolves">
          {data.wildcard ? 'Wildcard DNS' : 'No wildcard'}
        </Badge>
      )}
      {(data.mail_providers ?? []).map((m) => (
        <Badge key={m} tone="accent" title="Mail provider, from MX records">
          Mail: {m}
        </Badge>
      ))}
    </div>
  )
}

export function DnsPanel({ data, whois }: { data?: DnsResult; whois?: WhoisResult }) {
  const records = data?.records ?? {}
  const present = ORDER.filter((t) => (records[t] ?? []).length > 0)
  const services = data?.services ?? []
  const srv = data?.srv ?? []
  const ptr = data?.ptr ?? []

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

      {data && (data.dnssec || data.mail_providers?.length || data.wildcard !== undefined) && (
        <div className="mb-5">
          <Status data={data} />
        </div>
      )}

      <div className="flex flex-col gap-6">
        {services.length > 0 && (
          <Section title={`Services verified in TXT records (${services.length})`}>
            <ul className="grid gap-1.5 sm:grid-cols-2">
              {services.map((s) => (
                <li key={s.service} className="min-w-0 rounded-xl bg-glass px-3 py-2 text-sm" title={s.record}>
                  {s.service}
                </li>
              ))}
            </ul>
          </Section>
        )}

        <Section title="Records">
          {present.length === 0 ? (
            <Empty>No DNS records were returned.</Empty>
          ) : (
            <dl className="flex flex-col gap-3">
              {present.map((t) => (
                <div key={t} className="grid gap-2 sm:grid-cols-[5rem_minmax(0,1fr)]">
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
        </Section>

        {srv.length > 0 && (
          <Section title={`Service (SRV) records (${srv.length})`}>
            <dl className="flex flex-col gap-2">
              {srv.map((s) => (
                <div key={s.service} className="grid gap-1.5 sm:grid-cols-[11rem_minmax(0,1fr)]">
                  <dt className="font-mono text-xs font-semibold [overflow-wrap:anywhere]">{s.service}</dt>
                  <dd className="flex min-w-0 flex-col gap-1">
                    {s.records.map((r) => (
                      <code key={r} className="text-xs text-muted [overflow-wrap:anywhere]">
                        {r}
                      </code>
                    ))}
                  </dd>
                </div>
              ))}
            </dl>
          </Section>
        )}

        {ptr.length > 0 && (
          <Section title="Reverse DNS (PTR)">
            <dl className="flex flex-col gap-1.5">
              {ptr.map((p) => (
                <div key={p.ip} className="grid gap-1 sm:grid-cols-[minmax(0,16rem)_minmax(0,1fr)]">
                  <dt className="font-mono text-xs [overflow-wrap:anywhere]">{p.ip}</dt>
                  <dd className="font-mono text-xs text-muted [overflow-wrap:anywhere]">{p.names.join(', ')}</dd>
                </div>
              ))}
            </dl>
          </Section>
        )}
      </div>
    </Card>
  )
}
