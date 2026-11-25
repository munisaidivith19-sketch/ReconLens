import { Layers } from 'lucide-react'

import type { TechStackResult } from '../../types/scan'
import { Badge } from '../ui/Badge'
import { Card, CardHeader } from '../ui/Card'
import { Empty } from '../ui/Disclosure'

export function TechStackPanel({ data }: { data?: TechStackResult }) {
  const techs = data?.technologies ?? []
  return (
    <Card aria-labelledby="tech-title">
      <CardHeader
        id="tech-title"
        title="Technology stack"
        icon={<Layers size={20} />}
        description="Detected passively from the homepage response"
      />
      {techs.length === 0 ? (
        <Empty>No technologies were identified{data ? '' : ' (check did not complete)'}.</Empty>
      ) : (
        <ul className="grid gap-2 sm:grid-cols-2">
          {techs.map((t) => (
            <li key={t.name} className="flex min-w-0 flex-col gap-1.5 rounded-2xl border border-glass-border bg-glass px-3.5 py-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="min-w-0 font-medium [overflow-wrap:anywhere]">{t.name}</span>
                {t.version !== 'unknown' ? (
                  <Badge tone="warn" title="Version exposed">
                    v{t.version}
                  </Badge>
                ) : (
                  <Badge title="Version not exposed">version hidden</Badge>
                )}
              </div>
              <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted">
                <span className="[overflow-wrap:anywhere]">{t.categories.slice(0, 3).join(' · ') || 'Uncategorized'}</span>
                <span aria-hidden="true">·</span>
                <span>{t.confidence}% confidence</span>
              </div>
            </li>
          ))}
        </ul>
      )}
      <p className="mt-4 text-xs text-faint">
        Fingerprints from{' '}
        <a
          href="https://github.com/enthec/webappanalyzer"
          target="_blank"
          rel="noopener noreferrer"
          className="underline underline-offset-4"
        >
          enthec/webappanalyzer
        </a>{' '}
        (GPL-3.0).
      </p>
    </Card>
  )
}
