import { useMemo, useState } from 'react'
import { ListFilter } from 'lucide-react'

import { SEVERITIES, type Finding, type Severity } from '../../types/scan'
import { SEVERITY_LABEL, severityClass } from '../ui/Badge'
import { Card, CardHeader } from '../ui/Card'
import { cn } from '../ui/cn'
import { Empty } from '../ui/Disclosure'
import { FindingCard } from './FindingCard'

export function FindingsList({ findings }: { findings: Finding[] }) {
  const [active, setActive] = useState<Set<Severity>>(() => new Set(SEVERITIES.filter((s) => s !== 'info')))

  const counts = useMemo(() => {
    const c: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    findings.forEach((f) => (c[f.severity] += 1))
    return c
  }, [findings])

  const groups = useMemo(() => {
    const map = new Map<string, Finding[]>()
    findings
      .filter((f) => active.has(f.severity))
      .forEach((f) => {
        const list = map.get(f.category) ?? []
        list.push(f)
        map.set(f.category, list)
      })
    return [...map.entries()].sort((a, b) => b[1].length - a[1].length)
  }, [findings, active])

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
        <Empty>No findings match the selected severities.</Empty>
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
                    <FindingCard finding={f} />
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
