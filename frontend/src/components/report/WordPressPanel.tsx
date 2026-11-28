import { ExternalLink, Puzzle } from 'lucide-react'

import type { WordPressResult } from '../../types/scan'
import { Badge, SeverityBadge } from '../ui/Badge'
import { Card, CardHeader } from '../ui/Card'
import { Empty } from '../ui/Disclosure'

export function WordPressPanel({ data }: { data?: WordPressResult }) {
  if (data && !data.detected) return null
  const comps = [...(data?.components ?? [])].sort(
    (a, b) => b.cves.length - a.cves.length || Number(!a.version) - Number(!b.version) || a.slug.localeCompare(b.slug),
  )
  return (
    <Card aria-labelledby="wp-title" className="flex flex-col">
      <CardHeader
        id="wp-title"
        title="WordPress plugins & themes"
        icon={<Puzzle size={20} />}
        description={`Read from the ?ver= values on the homepage's asset URLs${data?.core_version ? ` (WordPress ${data.core_version})` : ''}. Versions are matched to NVD CVEs.`}
        action={
          data && (
            <Badge tone={data.vulnerable_count ? 'danger' : 'ok'}>
              {data.vulnerable_count ? `${data.vulnerable_count} vulnerable` : 'none vulnerable'}
            </Badge>
          )
        }
      />
      {!data ? (
        <Empty>Not checked in this scan.</Empty>
      ) : comps.length === 0 ? (
        <Empty>No plugins or themes referenced on the homepage.</Empty>
      ) : (
        <ul className="flex flex-col gap-1.5">
          {comps.map((c) => (
            <li key={`${c.type}:${c.slug}`} className="min-w-0 rounded-xl bg-glass px-3 py-2">
              <span className="flex flex-wrap items-center justify-between gap-2">
                <span className="min-w-0 text-sm">
                  <a
                    href={`https://wordpress.org/${c.type}s/${c.slug}/`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="font-mono font-semibold [overflow-wrap:anywhere] hover:underline"
                  >
                    {c.slug}
                    <span className="sr-only"> on wordpress.org (opens in a new tab)</span>
                  </a>{' '}
                  <span className="font-mono text-xs text-muted">{c.version ?? 'version hidden'}</span>
                </span>
                <span className="flex items-center gap-1.5">
                  <Badge>{c.type}</Badge>
                  {c.cves.length > 0 ? (
                    <SeverityBadge severity={c.cves[0].severity} />
                  ) : (
                    c.status && c.status !== 'ok' && <span className="text-xs text-faint">{c.status}</span>
                  )}
                </span>
              </span>
              {c.cves.length > 0 && (
                <ul className="mt-1.5 flex flex-wrap gap-x-3 gap-y-1">
                  {c.cves.slice(0, 8).map((v) => (
                    <li key={v.id}>
                      <a
                        href={v.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        title={v.description}
                        className="inline-flex items-center gap-1 font-mono text-xs text-accent-text hover:underline"
                      >
                        {v.id}
                        {v.cvss !== null && <span className="text-muted">({v.cvss})</span>}
                        {v.kev && <span className="text-danger">KEV</span>}
                        <ExternalLink size={10} aria-hidden="true" />
                      </a>
                    </li>
                  ))}
                  {c.cves.length > 8 && <li className="text-xs text-faint">+{c.cves.length - 8} more</li>}
                </ul>
              )}
            </li>
          ))}
        </ul>
      )}
    </Card>
  )
}
