import { FileCode2 } from 'lucide-react'

import type { ClientSideResult } from '../../types/scan'
import { Badge, SeverityBadge } from '../ui/Badge'
import { Card, CardHeader } from '../ui/Card'
import { Disclosure, Empty } from '../ui/Disclosure'

function shortUrl(u: string) {
  try {
    const url = new URL(u)
    return url.pathname.length > 1 ? url.pathname : url.host
  } catch {
    return u
  }
}

function ListBlock({ title, items }: { title: string; items: string[] }) {
  if (items.length === 0) return null
  return (
    <Disclosure
      summary={
        <span className="flex min-w-0 items-center justify-between gap-3">
          <span className="font-medium">{title}</span>
          <Badge>{items.length}</Badge>
        </span>
      }
    >
      <ul className="flex max-h-64 flex-col gap-1 overflow-y-auto pr-1 print:max-h-none">
        {items.map((i) => (
          <li key={i} className="font-mono text-xs text-muted [overflow-wrap:anywhere]">
            {i}
          </li>
        ))}
      </ul>
    </Disclosure>
  )
}

export function ClientSidePanel({ data }: { data?: ClientSideResult }) {
  const secrets = data?.secrets ?? []
  const buckets = data?.buckets ?? []
  return (
    <Card aria-labelledby="clientside-title" className="flex flex-col">
      <CardHeader
        id="clientside-title"
        title="JavaScript analysis"
        icon={<FileCode2 size={20} />}
        description="Secrets, cloud buckets and API routes in the homepage and the same-site scripts it loads. Nothing found here is requested."
        action={
          data?.status === 'ok' ? (
            <Badge tone={secrets.length ? 'danger' : 'ok'}>
              {secrets.length ? `${secrets.length} secret type(s)` : 'no secrets'}
            </Badge>
          ) : undefined
        }
      />
      {!data ? (
        <Empty>Not checked in this scan.</Empty>
      ) : data.status !== 'ok' ? (
        <Empty>{data.message ?? 'The homepage could not be fetched.'}</Empty>
      ) : (
        <div className="flex flex-col gap-4">
          {secrets.length > 0 && (
            <section aria-label="Secrets">
              <h3 className="mb-2 text-sm font-semibold text-muted">Possible secrets (masked)</h3>
              <ul className="flex flex-col gap-1.5">
                {secrets.map((s) => (
                  <li
                    key={s.type}
                    className="grid min-w-0 gap-2 rounded-xl bg-glass px-3 py-2 sm:grid-cols-[minmax(0,1fr)_6rem] sm:items-center"
                  >
                    <span className="min-w-0">
                      <span className="block text-sm font-semibold">{s.label}</span>
                      {s.matches.slice(0, 3).map((m) => (
                        <span key={m.value} className="block font-mono text-xs text-muted [overflow-wrap:anywhere]">
                          {m.value} <span className="text-faint">in {shortUrl(m.source)}</span>
                        </span>
                      ))}
                    </span>
                    <span className="sm:justify-self-end">
                      <SeverityBadge severity={s.severity} className="w-24 justify-center" />
                    </span>
                  </li>
                ))}
              </ul>
            </section>
          )}

          {buckets.length > 0 && (
            <section aria-label="Cloud storage">
              <h3 className="mb-2 text-sm font-semibold text-muted">Cloud storage referenced</h3>
              <ul className="flex flex-col gap-1.5">
                {buckets.map((b) => (
                  <li
                    key={`${b.provider}:${b.name}`}
                    className="grid min-w-0 gap-1 rounded-xl bg-glass px-3 py-2 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-center"
                  >
                    <span className="font-mono text-xs font-semibold [overflow-wrap:anywhere]">{b.name}</span>
                    <span className="sm:justify-self-end">
                      <Badge>{b.provider}</Badge>
                    </span>
                  </li>
                ))}
              </ul>
            </section>
          )}

          <div className="flex flex-col gap-2">
            <ListBlock title="API routes in code" items={(data.endpoints ?? []).map((e) => e.path)} />
            <ListBlock title="In-scope hosts in code" items={data.in_scope_hosts ?? []} />
            <ListBlock title="Third-party hosts" items={data.third_party_hosts ?? []} />
            <ListBlock title="Source maps referenced" items={(data.source_maps ?? []).map((s) => s.url)} />
          </div>

          {secrets.length === 0 && buckets.length === 0 && (data.endpoints ?? []).length === 0 && (
            <Empty>No secrets, buckets or API routes found in client-side code.</Empty>
          )}

          <p className="mt-auto text-xs text-faint">
            Read {(data.scripts ?? []).filter((s) => s.status === 200).length} of {data.scripts_found ?? 0} same-site
            script(s); {data.scripts_external ?? 0} third-party script(s) skipped.
          </p>
        </div>
      )}
    </Card>
  )
}
