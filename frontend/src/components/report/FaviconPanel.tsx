import { useState } from 'react'
import { Check, Copy, ExternalLink, Fingerprint } from 'lucide-react'

import type { FaviconResult } from '../../types/scan'
import { Card, CardHeader } from '../ui/Card'
import { Empty } from '../ui/Disclosure'
import { copyText } from './taxonomy'

function CopyQuery({ value }: { value: string }) {
  const [done, setDone] = useState(false)
  return (
    <button
      type="button"
      onClick={async () => {
        if (await copyText(value)) {
          setDone(true)
          window.setTimeout(() => setDone(false), 1500)
        }
      }}
      className="no-print inline-flex cursor-pointer items-center gap-1 text-xs text-accent-text hover:underline"
      aria-label={`Copy ${value}`}
    >
      {done ? <Check size={12} aria-hidden="true" /> : <Copy size={12} aria-hidden="true" />}
      {done ? 'Copied' : 'Copy'}
    </button>
  )
}

export function FaviconPanel({ data }: { data?: FaviconResult }) {
  return (
    <Card aria-labelledby="favicon-title" className="flex flex-col">
      <CardHeader
        id="favicon-title"
        title="Favicon fingerprint"
        icon={<Fingerprint size={20} />}
        description="Search engines like Shodan index servers by favicon hash. The same icon elsewhere often means the origin server, staging copies or related assets."
      />
      {!data ? (
        <Empty>Not checked in this scan.</Empty>
      ) : !data.found ? (
        <Empty>{data.message || 'No favicon found.'}</Empty>
      ) : (
        <div className="flex flex-col gap-4">
          <div className="rounded-xl bg-glass px-3 py-2.5">
            <p className="text-xs text-muted">Shodan hash (MurmurHash3)</p>
            <p className="font-mono text-xl font-bold">{data.mmh3}</p>
            <p className="mt-1 font-mono text-xs text-faint [overflow-wrap:anywhere]">MD5 {data.md5}</p>
          </div>
          <ul className="flex flex-col gap-1.5">
            {(data.searches ?? []).map((s) => (
              <li
                key={s.engine}
                className="grid min-w-0 gap-1 rounded-xl bg-glass px-3 py-2 sm:grid-cols-[5rem_minmax(0,1fr)_auto] sm:items-center"
              >
                <span className="text-sm font-semibold">{s.engine}</span>
                <code className="min-w-0 font-mono text-xs text-muted [overflow-wrap:anywhere]">{s.query}</code>
                <span className="flex items-center gap-3 sm:justify-self-end">
                  <CopyQuery value={s.query} />
                  <a
                    href={s.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 text-xs font-semibold text-accent-text hover:underline"
                  >
                    Search <ExternalLink size={12} aria-hidden="true" />
                    <span className="sr-only">on {s.engine} (opens in a new tab)</span>
                  </a>
                </span>
              </li>
            ))}
          </ul>
          <p className="mt-auto text-xs text-faint [overflow-wrap:anywhere]">
            Source: {data.url} ({data.bytes} bytes). ReconLens only builds these searches; it does not query them.
          </p>
        </div>
      )}
    </Card>
  )
}
