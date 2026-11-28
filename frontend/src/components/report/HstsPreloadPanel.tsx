import { Check, Lock, X } from 'lucide-react'

import type { HstsPreloadResult } from '../../types/scan'
import { Badge } from '../ui/Badge'
import { Card, CardHeader } from '../ui/Card'
import { Empty } from '../ui/Disclosure'

function Req({ ok, children }: { ok: boolean; children: string }) {
  return (
    <li className="flex items-center gap-2 text-sm">
      {ok ? (
        <Check size={14} className="text-ok" aria-label="met" />
      ) : (
        <X size={14} className="text-danger" aria-label="not met" />
      )}
      {children}
    </li>
  )
}

export function HstsPreloadPanel({ data }: { data?: HstsPreloadResult }) {
  return (
    <Card aria-labelledby="hsts-preload-title" className="flex flex-col">
      <CardHeader
        id="hsts-preload-title"
        title="HSTS preload"
        icon={<Lock size={20} />}
        description="Preloaded domains are HTTPS-only in browsers from the very first visit, so nobody can strip TLS on a hostile network."
        action={
          data && (
            <Badge tone={data.covered ? 'ok' : data.status === 'pending' ? 'accent' : 'warn'}>
              {data.covered ? 'preloaded' : data.status}
            </Badge>
          )
        }
      />
      {!data ? (
        <Empty>Not checked in this scan.</Empty>
      ) : (
        <div className="flex flex-col gap-3">
          <p className="text-sm">
            <code className="font-mono">{data.domain}</code>{' '}
            {data.covered
              ? data.preloaded_domain && data.preloaded_domain !== data.domain
                ? `is covered by the preload entry for ${data.preloaded_domain}.`
                : 'is on the browser preload list.'
              : data.status === 'pending'
                ? 'has been submitted and is waiting to ship in browsers.'
                : 'is not on the browser preload list.'}
          </p>
          {!data.covered && (
            <ul className="flex flex-col gap-1 rounded-xl bg-glass px-3 py-2.5" aria-label="Preload requirements">
              <Req ok={data.https}>Serves HTTPS</Req>
              <Req ok={data.header.present}>Sends Strict-Transport-Security</Req>
              <Req ok={(data.header.max_age ?? 0) >= 31536000}>max-age of at least one year</Req>
              <Req ok={data.header.include_subdomains}>includeSubDomains</Req>
              <Req ok={data.header.preload}>preload directive</Req>
            </ul>
          )}
          <p className="mt-auto text-xs text-faint">Source: hstspreload.org.</p>
        </div>
      )}
    </Card>
  )
}
