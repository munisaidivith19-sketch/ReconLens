import { useMemo, useState } from 'react'
import { Network, Search } from 'lucide-react'

import type { SubdomainsResult } from '../../types/scan'
import { Badge } from '../ui/Badge'
import { Card, CardHeader } from '../ui/Card'
import { Empty } from '../ui/Disclosure'

export function SubdomainsPanel({ data }: { data?: SubdomainsResult }) {
  const [q, setQ] = useState('')
  const list = useMemo(() => {
    const all = data?.subdomains ?? []
    const needle = q.trim().toLowerCase()
    return needle ? all.filter((s) => s.includes(needle)) : all
  }, [data, q])
  const interesting = new Set(data?.interesting ?? [])

  return (
    <Card aria-labelledby="subs-title">
      <CardHeader
        id="subs-title"
        title="Subdomains"
        icon={<Network size={20} />}
        description="From certificate transparency logs (crt.sh). No brute-forcing."
        action={data?.available ? <Badge tone="accent">{data.count} found</Badge> : undefined}
      />
      {!data || !data.available ? (
        <Empty>{data?.message ?? 'Subdomain data unavailable.'}</Empty>
      ) : data.count === 0 ? (
        <Empty>No subdomains appear in certificate transparency logs.</Empty>
      ) : (
        <>
          <div className="no-print relative mb-3">
            <Search aria-hidden="true" size={16} className="pointer-events-none absolute top-1/2 left-3.5 -translate-y-1/2 text-faint" />
            <label htmlFor="sub-filter" className="sr-only">
              Filter subdomains
            </label>
            <input
              id="sub-filter"
              className="field min-h-11 pl-10 text-sm"
              placeholder="Filter subdomains"
              value={q}
              onChange={(e) => setQ(e.target.value)}
            />
          </div>
          <ul className="grid max-h-80 gap-1.5 overflow-y-auto pr-1 sm:grid-cols-2 print:max-h-none">
            {list.map((s) => (
              <li
                key={s}
                className="flex min-w-0 items-center justify-between gap-2 rounded-xl bg-glass px-3 py-2 font-mono text-xs"
              >
                <span className="min-w-0 [overflow-wrap:anywhere]">{s}</span>
                {interesting.has(s) && <Badge tone="warn">review</Badge>}
              </li>
            ))}
          </ul>
          {list.length === 0 && <Empty>No subdomains match "{q}".</Empty>}
          {data.truncated && <p className="mt-3 text-xs text-faint">Showing the first {data.subdomains.length} results.</p>}
        </>
      )}
    </Card>
  )
}
