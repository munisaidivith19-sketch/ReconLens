import { ClipboardList, Zap } from 'lucide-react'

import { SEVERITIES, type ScanDetail, type Severity } from '../../types/scan'
import { SEVERITY_LABEL, SeverityBadge, severityClass } from '../ui/Badge'
import { Card, CardHeader } from '../ui/Card'
import { cn } from '../ui/cn'
import { Empty } from '../ui/Disclosure'
import { bySeverity, taxonomyFor } from './taxonomy'

function Stat({ label, value }: { label: string; value: number | string }) {
  return (
    <div className="min-w-0 rounded-xl bg-glass px-3 py-2.5">
      <p className="font-mono text-xl font-bold">{value}</p>
      <p className="text-xs text-muted">{label}</p>
    </div>
  )
}

/** One-page overview: severity counts, size of the attack surface and the top fixes. */
export function SummaryPanel({ scan }: { scan: ScanDetail }) {
  const r = scan.results
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  scan.findings.forEach((f) => (counts[f.severity] += 1))
  const top = [...scan.findings].filter((f) => f.severity !== 'info').sort(bySeverity).slice(0, 3)
  const ports = (r.exposed_services?.hosts ?? []).reduce((n, h) => n + h.ports.length, 0)

  const surface: [string, number][] = [
    ['subdomains', r.subdomains?.count ?? 0],
    ['archived URLs', r.endpoints?.wayback?.total_urls ?? 0],
    ['forms', r.endpoints?.forms?.length ?? 0],
    ['technologies', r.tech_stack?.count ?? 0],
    ['CVEs', r.cve_lookup?.cves?.length ?? 0],
    ['open ports (Shodan)', ports],
    ['API routes in JS', r.client_side?.endpoints?.length ?? 0],
    ['CNAMEs', r.takeover?.cnames?.length ?? 0],
  ]

  return (
    <Card aria-labelledby="summary-title" className="flex flex-col">
      <CardHeader
        id="summary-title"
        title="Summary"
        icon={<ClipboardList size={20} />}
        description="Severity counts, attack surface and the three issues to fix first."
      />
      <div className="flex flex-col gap-5">
        <div className="grid grid-cols-5 gap-1.5" aria-label="Findings by severity">
          {SEVERITIES.map((s) => (
            <div key={s} className={cn('chip flex min-w-0 flex-col justify-center gap-0 rounded-xl px-1 py-2 text-center', severityClass(s))}>
              <span className="font-mono text-lg font-bold">{counts[s]}</span>
              <span className="text-[0.7rem]">{SEVERITY_LABEL[s]}</span>
            </div>
          ))}
        </div>
        <div className="grid grid-cols-2 gap-1.5 sm:grid-cols-4">
          {surface.map(([label, value]) => (
            <Stat key={label} label={label} value={value} />
          ))}
        </div>
        <section aria-label="Fix first">
          <h3 className="mb-2 text-sm font-semibold text-muted">Fix first</h3>
          {top.length === 0 ? (
            <Empty>No issues above informational.</Empty>
          ) : (
            <ol className="flex flex-col gap-1.5">
              {top.map((f, i) => (
                <li
                  key={f.id}
                  className="grid min-w-0 grid-cols-[1.5rem_minmax(0,1fr)] items-center gap-2 rounded-xl bg-glass px-3 py-2 sm:grid-cols-[1.5rem_minmax(0,1fr)_6rem]"
                >
                  <span className="font-mono text-sm text-faint">{i + 1}</span>
                  <span className="min-w-0 text-sm font-medium [overflow-wrap:anywhere]">{f.title}</span>
                  <span className="col-start-2 sm:col-start-auto sm:justify-self-end">
                    <SeverityBadge severity={f.severity} className="w-24 justify-center" />
                  </span>
                </li>
              ))}
            </ol>
          )}
        </section>
      </div>
    </Card>
  )
}

/** Findings whose fix is a small configuration change. */
export function QuickWins({ scan }: { scan: ScanDetail }) {
  const seen = new Set<string>()
  const wins = [...scan.findings]
    .sort(bySeverity)
    .map((f) => ({ f, fix: taxonomyFor(f.id).quickWin }))
    .filter((w): w is { f: typeof w.f; fix: string } => {
      if (!w.fix || seen.has(w.fix)) return false
      seen.add(w.fix)
      return true
    })

  return (
    <Card aria-labelledby="quickwins-title" className="flex flex-col">
      <CardHeader
        id="quickwins-title"
        title="Quick wins"
        icon={<Zap size={20} />}
        description="Configuration changes that take minutes and close real findings."
      />
      {wins.length === 0 ? (
        <Empty>No quick configuration fixes needed.</Empty>
      ) : (
        <ul className="flex flex-col gap-1.5">
          {wins.map(({ f, fix }) => (
            <li
              key={f.id}
              className="grid min-w-0 gap-1 rounded-xl bg-glass px-3 py-2 sm:grid-cols-[minmax(0,1fr)_6rem] sm:items-center"
            >
              <span className="min-w-0">
                <span className="block text-sm font-medium [overflow-wrap:anywhere]">{fix}</span>
                <span className="block text-xs text-muted [overflow-wrap:anywhere]">{f.title}</span>
              </span>
              <span className="sm:justify-self-end">
                <SeverityBadge severity={f.severity} className="w-24 justify-center" />
              </span>
            </li>
          ))}
        </ul>
      )}
    </Card>
  )
}
