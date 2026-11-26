import { Copy as CopyIcon } from 'lucide-react'

import type { LookalikesResult } from '../../types/scan'
import { Badge } from '../ui/Badge'
import { Card, CardHeader } from '../ui/Card'
import { Empty } from '../ui/Disclosure'

export function LookalikesPanel({ data }: { data?: LookalikesResult }) {
  const registered = data?.registered ?? []
  const total = data?.registered_count ?? registered.length
  return (
    <Card aria-labelledby="lookalikes-title" className="flex flex-col">
      <CardHeader
        id="lookalikes-title"
        title="Lookalike domains"
        icon={<CopyIcon size={20} />}
        description="Misspellings and look-alikes of the domain that are already registered. DNS lookups only; these sites are never visited."
        action={
          data ? (
            <Badge tone={data.with_mail ? 'warn' : total ? 'neutral' : 'ok'}>
              {total ? `${total} registered` : 'none registered'}
            </Badge>
          ) : undefined
        }
      />
      {!data ? (
        <Empty>Not checked in this scan.</Empty>
      ) : registered.length === 0 ? (
        <Empty>
          {data.checked ? `None of ${data.checked} variants of ${data.base} are registered.` : 'No variants were checked.'}
        </Empty>
      ) : (
        <ul className="flex max-h-80 flex-col gap-1.5 overflow-y-auto pr-1 print:max-h-none">
          {registered.map((r) => (
            <li
              key={r.domain}
              className="grid min-w-0 gap-1 rounded-xl bg-glass px-3 py-2 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-center"
            >
              <span className="min-w-0">
                <span className="block font-mono text-xs font-semibold [overflow-wrap:anywhere]">{r.domain}</span>
                <span className="block text-xs text-muted [overflow-wrap:anywhere]">
                  {r.technique}
                  {r.ips.length > 0 && ` · ${r.ips.join(', ')}`}
                </span>
              </span>
              <span className="flex flex-wrap gap-1.5 sm:justify-self-end">
                {r.mx.length > 0 && (
                  <Badge tone="warn" title={`MX: ${r.mx.join(', ')}`}>
                    receives mail
                  </Badge>
                )}
                {r.ips.length === 0 && <Badge title="Registered, but no website address">no website</Badge>}
              </span>
            </li>
          ))}
        </ul>
      )}
      {data && (
        <p className="mt-auto pt-3 text-xs text-faint">
          Checked {data.checked} of {data.generated} variants of {data.base}
          {data.timed_out ? ' (stopped early: DNS was slow)' : ''}. A registered lookalike isn't necessarily
          malicious; it may belong to the same organisation.
        </p>
      )}
    </Card>
  )
}
