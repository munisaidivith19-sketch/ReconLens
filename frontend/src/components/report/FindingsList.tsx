import { useMemo, useState } from 'react'
import { ListFilter, Search } from 'lucide-react'

import { SEVERITIES, type Finding, type Severity } from '../../types/scan'
import { SEVERITY_LABEL, severityClass } from '../ui/Badge'
import { Card, CardHeader } from '../ui/Card'
import { cn } from '../ui/cn'
import { Empty } from '../ui/Disclosure'
import { RESOLVED, type TriageApi } from '../../hooks/useTriage'
import { FindingCard } from './FindingCard'
import { taxonomyFor } from './taxonomy'

export function FindingsList({ findings, domain, triage }: { findings: Finding[]; domain?: string; triage?: TriageApi }) {
  const [active, setActive] = useState<Set<Severity>>(() => new Set(SEVERITIES.filter((s) => s !== 'info')))
  const [query, setQuery] = useState('')
  const [quickOnly, setQuickOnly] = useState(false)
  const [hideResolved, setHideResolved] = useState(false)

  const counts = useMemo(() => {
    const c: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    findings.forEach((f) => (c[f.severity] += 1))
    return c
  }, [findings])

  const groups = useMemo(() => {
    const map = new Map<string, Finding[]>()
    const q = query.trim().toLowerCase()
    findings
      .filter((f) => active.has(f.severity))
      .filter((f) => !quickOnly || Boolean(taxonomyFor(f.id).quickWin))
      .filter((f) => {
        const st = triage?.items[f.id]?.status
        return !hideResolved || !st || !RESOLVED.has(st)
      })
      .filter((f) => {
        if (!q) return true
        const tax = taxonomyFor(f.id)
        const hay = [f.title, f.evidence, f.recommendation, f.category, f.id, tax.cwe ? `cwe-${tax.cwe.id}` : '', tax.owasp?.id ?? '']
          .join(' ')
          .toLowerCase()
        return hay.includes(q)
      })
      .forEach((f) => {
        const list = map.get(f.category) ?? []
        list.push(f)
        map.set(f.category, list)
      })
    return [...map.entries()].sort((a, b) => b[1].length - a[1].length)
  }, [findings, active, query, quickOnly, hideResolved, triage])

  const toggle = (s: Severity) =>
    setActive((prev) => {
      const next = new Set(prev)
      if (next.has(s)) next.delete(s)
      else next.add(s)
      return next
    })

  const shown = groups.reduce((n, [, list]) => n + list.length, 0)

  return (
    <Card aria-labelledby="findings-title">
      <CardHeader
        id="findings-title"
        title="Findings"
        icon={<ListFilter size={20} />}
        description={`${shown} of ${findings.length} shown, grouped by category`}
      />

      <div className="no-print mb-3 flex flex-col gap-2 sm:flex-row sm:items-center">
        <label className="relative min-w-0 flex-1">
          <span className="sr-only">Search findings</span>
          <Search size={16} aria-hidden="true" className="pointer-events-none absolute top-1/2 left-3.5 -translate-y-1/2 text-faint" />
          <input
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search title, evidence, CWE-79, A05…"
            className="field min-h-10 pl-10 text-sm"
          />
        </label>
        <button
          type="button"
          aria-pressed={quickOnly}
          onClick={() => setQuickOnly((v) => !v)}
          className={cn('btn btn-sm', quickOnly ? 'btn-primary' : '')}
        >
          Quick wins only
        </button>
        {triage && (
          <button
            type="button"
            aria-pressed={hideResolved}
            onClick={() => setHideResolved((v) => !v)}
            className={cn('btn btn-sm', hideResolved ? 'btn-primary' : '')}
            title="Hide findings marked fixed, false positive or accepted risk"
          >
            Hide resolved
          </button>
        )}
      </div>

      <div role="group" aria-label="Filter by severity" className="no-print mb-5 flex flex-wrap gap-2">
        {SEVERITIES.map((s) => (
          <button
            key={s}
            type="button"
            aria-pressed={active.has(s)}
            onClick={() => toggle(s)}
            className={cn(
              'chip min-h-9 cursor-pointer px-3 text-sm transition-all duration-200',
              severityClass(s),
              active.has(s) ? 'opacity-100' : 'opacity-45 grayscale-[40%] hover:opacity-80',
            )}
          >
            {SEVERITY_LABEL[s]}
            <span className="font-mono">{counts[s]}</span>
          </button>
        ))}
      </div>

      {groups.length === 0 ? (
        <Empty>No findings match the current filters.</Empty>
      ) : (
        <div className="flex flex-col gap-6">
          {groups.map(([category, list]) => (
            <section key={category} aria-label={category}>
              <h3 className="mb-2 text-sm font-semibold tracking-wide text-muted uppercase">
                {category} <span className="font-mono">({list.length})</span>
              </h3>
              <ul className="flex flex-col gap-2">
                {list.map((f) => (
                  <li key={f.id}>
                    <FindingCard
                      finding={f}
                      domain={domain}
                      triage={
                        triage
                          ? { item: triage.items[f.id], save: (st, note) => triage.save(f.id, st, note) }
                          : undefined
                      }
                    />
                  </li>
                ))}
              </ul>
            </section>
          ))}
        </div>
      )}
    </Card>
  )
}
