import { Bug, ExternalLink, Flame } from 'lucide-react'

import type { CveResult } from '../../types/scan'
import { Badge, SeverityBadge } from '../ui/Badge'
import { Card, CardHeader } from '../ui/Card'
import { Empty } from '../ui/Disclosure'
import { percent } from '../ui/format'

export function CveTable({ data }: { data?: CveResult }) {
  const cves = data?.cves ?? []
  const skipped = data?.skipped ?? []
  return (
    <Card aria-labelledby="cve-title">
      <CardHeader
        id="cve-title"
        title="Known vulnerabilities"
        icon={<Bug size={20} />}
        description="NVD matches for detected versions, with CISA KEV and FIRST EPSS context"
        action={data && data.kev_count > 0 ? <Badge tone="danger">{data.kev_count} actively exploited</Badge> : undefined}
      />

      {cves.length === 0 ? (
        <Empty>
          {data
            ? 'No CVEs matched. CVEs are only listed when a component version is actually exposed.'
            : 'The CVE check did not complete.'}
        </Empty>
      ) : (
        <div className="scroll-x -mx-1 px-1">
          <table className="w-full min-w-[640px] border-separate border-spacing-y-1.5 text-left text-sm">
            <caption className="sr-only">CVEs affecting detected technology versions</caption>
            <thead className="text-xs tracking-wide text-muted uppercase">
              <tr>
                <th scope="col" className="px-3 py-1 font-semibold">CVE</th>
                <th scope="col" className="px-3 py-1 font-semibold">Component</th>
                <th scope="col" className="px-3 py-1 font-semibold">CVSS</th>
                <th scope="col" className="px-3 py-1 font-semibold">Severity</th>
                <th scope="col" className="px-3 py-1 font-semibold">Exploitation</th>
              </tr>
            </thead>
            <tbody>
              {cves.map((c) => (
                <tr key={`${c.id}-${c.technology}`} className="bg-glass">
                  <td className="rounded-l-xl px-3 py-2.5 align-top">
                    <a
                      href={c.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 font-mono font-semibold whitespace-nowrap text-accent-text underline-offset-4 hover:underline"
                      title={c.description}
                    >
                      {c.id}
                      <ExternalLink size={12} aria-hidden="true" />
                      <span className="sr-only">(NVD, opens in a new tab)</span>
                    </a>
                  </td>
                  <td className="px-3 py-2.5 align-top whitespace-nowrap">
                    {c.technology} <span className="text-muted">{c.version}</span>
                  </td>
                  <td className="px-3 py-2.5 align-top font-mono tabular-nums">{c.cvss ?? 'n/a'}</td>
                  <td className="px-3 py-2.5 align-top">
                    <SeverityBadge severity={c.severity} />
                  </td>
                  <td className="rounded-r-xl px-3 py-2.5 align-top">
                    <div className="flex flex-wrap gap-1.5">
                      {c.kev && (
                        <Badge tone="danger" title={`Added to CISA KEV ${c.kev_date_added ?? ''}`}>
                          <Flame size={12} aria-hidden="true" /> KEV
                        </Badge>
                      )}
                      {c.ransomware && <Badge tone="danger">ransomware</Badge>}
                      <Badge
                        tone={c.epss !== null && c.epss >= 0.1 ? 'warn' : 'neutral'}
                        title={c.epss_percentile !== null ? `Percentile ${percent(c.epss_percentile, 0)}` : undefined}
                      >
                        EPSS {percent(c.epss)}
                      </Badge>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {skipped.length > 0 && (
        <details className="mt-4 text-sm">
          <summary className="cursor-pointer text-muted hover:text-fg">
            {skipped.length} component(s) not checked
          </summary>
          <ul className="mt-2 flex flex-col gap-1 pl-4 text-muted">
            {skipped.map((s) => (
              <li key={s.technology} className="[overflow-wrap:anywhere]">
                <span className="text-fg">{s.technology}</span>: {s.reason}
              </li>
            ))}
          </ul>
        </details>
      )}
      <p className="mt-4 text-xs text-faint">
        Data: NIST NVD, CISA Known Exploited Vulnerabilities catalog, FIRST EPSS. Verify versions before reporting.
      </p>
    </Card>
  )
}
