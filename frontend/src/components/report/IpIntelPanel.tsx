import { Network } from 'lucide-react'

import type { IpIntelResult, NetworkKind } from '../../types/scan'
import { Badge } from '../ui/Badge'
import { Card, CardHeader } from '../ui/Card'
import { Disclosure, Empty } from '../ui/Disclosure'

const KIND_LABEL: Record<NetworkKind, string> = {
  cdn: 'CDN / WAF',
  cloud: 'Cloud',
  hosting: 'Hosting',
  saas: 'SaaS',
  other: 'Network',
  unknown: 'Unknown',
}
const KIND_TONE: Record<NetworkKind, 'accent' | 'ok' | 'neutral' | 'warn'> = {
  cdn: 'ok',
  cloud: 'accent',
  hosting: 'neutral',
  saas: 'accent',
  other: 'neutral',
  unknown: 'neutral',
}

export function IpIntelPanel({ data }: { data?: IpIntelResult }) {
  return (
    <Card aria-labelledby="ip-intel-title" className="flex flex-col">
      <CardHeader
        id="ip-intel-title"
        title="IP ownership & hosting"
        icon={<Network size={20} />}
        description="Which network (ASN) and which cloud, CDN or hosting company runs each address the domain and its subdomains resolve to."
        action={data && <Badge>{data.asn_count} ASN(s)</Badge>}
      />
      {!data ? (
        <Empty>Not checked in this scan.</Empty>
      ) : data.hosts.length === 0 ? (
        <Empty>No resolved addresses to look up.</Empty>
      ) : (
        <div className="flex flex-col gap-4">
          {data.main_provider && (
            <p className="text-sm">
              Main site runs on <strong>{data.main_provider}</strong>
              {data.main_kind && <span className="text-muted"> ({KIND_LABEL[data.main_kind].toLowerCase()})</span>}.
            </p>
          )}
          <ul className="flex flex-col gap-1.5" aria-label="Providers">
            {data.providers.map((p) => (
              <li
                key={p.provider}
                className="grid min-w-0 gap-1 rounded-xl bg-glass px-3 py-2 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-center"
              >
                <span className="min-w-0 text-sm font-semibold [overflow-wrap:anywhere]">{p.provider}</span>
                <span className="flex flex-wrap items-center gap-1.5 text-xs text-muted sm:justify-self-end">
                  <Badge tone={KIND_TONE[p.kind]}>{KIND_LABEL[p.kind]}</Badge>
                  {p.ips} IP · {p.names} name{p.names === 1 ? '' : 's'}
                </span>
              </li>
            ))}
          </ul>
          <Disclosure
            summary={
              <span className="flex min-w-0 items-center justify-between gap-3">
                <span className="font-medium">Every address</span>
                <Badge>{data.hosts.length} IPs</Badge>
              </span>
            }
          >
            <ul className="flex flex-col gap-1.5">
              {data.hosts.map((h) => (
                <li key={h.ip} className="min-w-0 rounded-xl bg-glass px-3 py-2">
                  <span className="flex flex-wrap items-center justify-between gap-2">
                    <code className="font-mono text-xs font-semibold">{h.ip}</code>
                    <span className="text-xs text-muted">
                      {h.asn ? `AS${h.asn}` : 'no ASN'}
                      {h.country ? ` · ${h.country}` : ''}
                    </span>
                  </span>
                  {h.as_name && <span className="block text-xs text-muted [overflow-wrap:anywhere]">{h.as_name}</span>}
                  <span className="block font-mono text-xs text-faint [overflow-wrap:anywhere]">{h.names.join(', ')}</span>
                </li>
              ))}
            </ul>
          </Disclosure>
          <p className="mt-auto text-xs text-faint">Source: {data.source}.</p>
        </div>
      )}
    </Card>
  )
}
