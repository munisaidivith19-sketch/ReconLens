import { Lock, ShieldCheck, ShieldX } from 'lucide-react'

import type { HeadersResult, TlsResult } from '../../types/scan'
import { Badge } from '../ui/Badge'
import { Card, CardHeader } from '../ui/Card'
import { Empty, KeyValue } from '../ui/Disclosure'
import { formatDate } from '../ui/format'

const HEADER_LABELS: Record<string, string> = {
  'content-security-policy': 'Content-Security-Policy',
  'strict-transport-security': 'Strict-Transport-Security',
  'x-frame-options': 'X-Frame-Options',
  'x-content-type-options': 'X-Content-Type-Options',
  'referrer-policy': 'Referrer-Policy',
  'permissions-policy': 'Permissions-Policy',
  'cross-origin-opener-policy': 'Cross-Origin-Opener-Policy',
}

function legacyLabel(v: boolean | null | undefined) {
  if (v === true) return <Badge tone="danger">accepted</Badge>
  if (v === false) return <Badge tone="ok">rejected</Badge>
  return <Badge>not testable</Badge>
}

export function WebSecurityPanel({ tls, headers }: { tls?: TlsResult; headers?: HeadersResult }) {
  return (
    <Card aria-labelledby="web-title">
      <CardHeader id="web-title" title="TLS & HTTP security" icon={<Lock size={20} />} />
      <div className="grid gap-5 lg:grid-cols-2">
        <section aria-label="TLS certificate" className="min-w-0">
          <h3 className="mb-3 font-semibold">Certificate</h3>
          {!tls?.available ? (
            <Empty>{tls?.message ?? 'TLS data unavailable.'}</Empty>
          ) : (
            <KeyValue
              items={[
                {
                  label: 'Trust',
                  value: tls.trusted ? (
                    <Badge tone="ok">
                      <ShieldCheck size={12} aria-hidden="true" /> trusted
                    </Badge>
                  ) : (
                    <Badge tone="danger" title={tls.verify_error ?? undefined}>
                      <ShieldX size={12} aria-hidden="true" /> untrusted
                    </Badge>
                  ),
                },
                {
                  label: 'Hostname',
                  value: tls.hostname_match ? <Badge tone="ok">matches</Badge> : <Badge tone="danger">mismatch</Badge>,
                },
                { label: 'Issuer', value: tls.issuer ?? 'n/a' },
                { label: 'Protocol', value: `${tls.protocol ?? 'n/a'}${tls.cipher ? ` · ${tls.cipher}` : ''}` },
                {
                  label: 'Valid until',
                  value: (
                    <span className="flex flex-wrap items-center gap-2">
                      {formatDate(tls.not_after)}
                      {tls.days_until_expiry !== null && tls.days_until_expiry !== undefined && (
                        <Badge tone={tls.days_until_expiry < 14 ? 'danger' : tls.days_until_expiry < 30 ? 'warn' : 'ok'}>
                          {tls.days_until_expiry} days
                        </Badge>
                      )}
                    </span>
                  ),
                },
                {
                  label: 'Legacy TLS 1.0 / 1.1',
                  value: (
                    <span className="flex flex-wrap gap-1.5">
                      {legacyLabel(tls.legacy_protocols?.tls1_0)}
                      {legacyLabel(tls.legacy_protocols?.tls1_1)}
                    </span>
                  ),
                },
              ]}
            />
          )}
        </section>

        <section aria-label="Security headers" className="min-w-0">
          <h3 className="mb-3 font-semibold">Security headers</h3>
          {!headers ? (
            <Empty>Header check did not complete.</Empty>
          ) : (
            <>
              <ul className="flex flex-col gap-1.5">
                {Object.entries(HEADER_LABELS).map(([key, label]) => {
                  const present = key in headers.headers_present
                  return (
                    <li key={key} className="flex flex-wrap items-center justify-between gap-2 rounded-xl bg-glass px-3 py-2 text-sm">
                      <span className="min-w-0 font-mono text-xs [overflow-wrap:anywhere]">{label}</span>
                      <Badge tone={present ? 'ok' : 'warn'}>{present ? 'present' : 'missing'}</Badge>
                    </li>
                  )
                })}
              </ul>
              <div className="mt-3 flex flex-wrap gap-1.5 text-sm">
                {headers.waf_cdn.map((w) => (
                  <Badge key={w} tone="accent">
                    {w}
                  </Badge>
                ))}
                {headers.http_redirects_to_https === true && <Badge tone="ok">HTTP → HTTPS</Badge>}
                {headers.http_redirects_to_https === false && <Badge tone="warn">no HTTPS redirect</Badge>}
                {headers.cookies.length > 0 && <Badge>{headers.cookies.length} cookie(s)</Badge>}
              </div>
            </>
          )}
        </section>
      </div>
    </Card>
  )
}
