import { Unlink } from 'lucide-react'

import type { TakeoverEntry, TakeoverResult } from '../../types/scan'
import { Badge } from '../ui/Badge'
import { Card, CardHeader } from '../ui/Card'
import { Empty } from '../ui/Disclosure'

function Row({ e, tone, label }: { e: TakeoverEntry; tone: 'danger' | 'warn' | 'neutral'; label: string }) {
  return (
    <li className="grid min-w-0 gap-1 rounded-xl bg-glass px-3 py-2 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-center">
      <span className="min-w-0">
        <span className="block font-mono text-xs font-semibold [overflow-wrap:anywhere]">{e.name}</span>
        <span className="block font-mono text-xs text-muted [overflow-wrap:anywhere]">→ {e.cname}</span>
      </span>
      <span className="sm:justify-self-end">
        <Badge tone={tone}>{label}</Badge>
      </span>
    </li>
  )
}

export function TakeoverPanel({ data }: { data?: TakeoverResult }) {
  const risky = [...(data?.takeover ?? []), ...(data?.dangling ?? [])]
  const others = (data?.cnames ?? []).filter((c) => c.target_exists !== false)
  return (
    <Card aria-labelledby="takeover-title" className="flex flex-col">
      <CardHeader
        id="takeover-title"
        title="Subdomain takeover"
        icon={<Unlink size={20} />}
        description="CNAME records whose target no longer exists. DNS lookups only."
        action={
          data ? (
            <Badge tone={risky.length ? 'danger' : 'ok'}>{risky.length ? `${risky.length} at risk` : 'none found'}</Badge>
          ) : undefined
        }
      />
      {!data ? (
        <Empty>Not checked in this scan.</Empty>
      ) : (
        <div className="flex flex-col gap-4">
          {risky.length > 0 && (
            <ul className="flex flex-col gap-1.5">
              {(data.takeover ?? []).map((e) => (
                <Row key={e.name} e={e} tone="danger" label={`takeover: ${e.service}`} />
              ))}
              {(data.dangling ?? []).map((e) => (
                <Row key={e.name} e={e} tone="warn" label="dangling" />
              ))}
            </ul>
          )}
          {others.length > 0 ? (
            <div>
              <h3 className="mb-2 text-sm font-semibold text-muted">Other CNAMEs ({others.length})</h3>
              <ul className="flex max-h-60 flex-col gap-1.5 overflow-y-auto pr-1 print:max-h-none">
                {others.map((e) => (
                  <Row key={e.name} e={e} tone="neutral" label={e.service ?? 'resolves'} />
                ))}
              </ul>
            </div>
          ) : (
            risky.length === 0 && <Empty>No subdomains use CNAME records.</Empty>
          )}
          <p className="text-xs text-faint">
            Checked {data.checked} of {data.total} subdomains{data.timed_out ? ' (stopped early: DNS was slow)' : ''}.
          </p>
        </div>
      )}
    </Card>
  )
}
