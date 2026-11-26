import { RadioTower } from 'lucide-react'

import type { ExposedServicesResult } from '../../types/scan'
import { Badge } from '../ui/Badge'
import { Card, CardHeader } from '../ui/Card'
import { Empty } from '../ui/Disclosure'

// Ports worth a second look; anything else is shown neutral.
const RISKY = new Set([21, 23, 161, 445, 1433, 1521, 2049, 2375, 3306, 3389, 5432, 5900, 5984, 6379, 9042, 9200, 11211, 27017])

export function ExposedServicesPanel({ data }: { data?: ExposedServicesResult }) {
  const hosts = data?.hosts ?? []
  return (
    <Card aria-labelledby="exposed-title" className="flex flex-col">
      <CardHeader
        id="exposed-title"
        title="Exposed services"
        icon={<RadioTower size={20} />}
        description="Open ports seen by Shodan's own scans (InternetDB). ReconLens does not scan ports."
      />
      {!data ? (
        <Empty>Not checked in this scan.</Empty>
      ) : hosts.length === 0 ? (
        <Empty>{data.message ?? 'No data for this domain.'}</Empty>
      ) : (
        <ul className="flex flex-col gap-3">
          {hosts.map((h) => (
            <li key={h.ip} className="min-w-0 rounded-2xl border border-glass-border bg-glass p-3.5">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <code className="font-mono text-sm font-semibold [overflow-wrap:anywhere]">{h.ip}</code>
                <span className="flex flex-wrap gap-1.5">
                  {h.tags.map((t) => (
                    <Badge key={t}>{t}</Badge>
                  ))}
                </span>
              </div>
              {!h.known ? (
                <p className="mt-2 text-sm text-muted">Shodan has no data for this IP.</p>
              ) : (
                <>
                  <div className="mt-2.5 flex flex-wrap gap-1.5" aria-label="Open ports">
                    {h.ports.length === 0 ? (
                      <span className="text-sm text-muted">No open ports recorded.</span>
                    ) : (
                      h.ports.map((p) => (
                        <Badge key={p} tone={RISKY.has(p) ? 'danger' : 'neutral'}>
                          {p}
                        </Badge>
                      ))
                    )}
                  </div>
                  {h.vulns.length > 0 && (
                    <p className="mt-2.5 text-xs text-muted [overflow-wrap:anywhere]">
                      <span className="font-semibold text-warn">{h.vulns.length} CVE(s) inferred: </span>
                      {h.vulns.slice(0, 12).join(', ')}
                      {h.vulns.length > 12 ? ' …' : ''}
                    </p>
                  )}
                  {h.cpes.length > 0 && (
                    <p className="mt-1.5 text-xs text-faint [overflow-wrap:anywhere]">Software: {h.cpes.slice(0, 6).join(', ')}</p>
                  )}
                </>
              )}
            </li>
          ))}
        </ul>
      )}
      {data && data.errors.length > 0 && <p className="mt-3 text-xs text-faint">{data.errors.join('; ')}</p>}
      <p className="mt-auto pt-3 text-xs text-faint">
        Data:{' '}
        <a
          href="https://internetdb.shodan.io/"
          target="_blank"
          rel="noopener noreferrer"
          className="underline underline-offset-4 hover:text-fg"
        >
          Shodan InternetDB
        </a>{' '}
        (free, non-commercial use).
      </p>
    </Card>
  )
}
