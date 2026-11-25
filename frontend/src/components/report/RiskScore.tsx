import { PolarAngleAxis, RadialBar, RadialBarChart, ResponsiveContainer } from 'recharts'
import { Gauge } from 'lucide-react'

import type { ScoreFactor, Severity } from '../../types/scan'
import { SEVERITY_LABEL, severityClass } from '../ui/Badge'
import { Card, CardHeader } from '../ui/Card'
import { cn } from '../ui/cn'

function levelFor(score: number): Severity {
  if (score >= 70) return 'critical'
  if (score >= 45) return 'high'
  if (score >= 20) return 'medium'
  if (score > 0) return 'low'
  return 'info'
}

const LEVEL_TEXT: Record<Severity, string> = {
  critical: 'Critical exposure: act now',
  high: 'High exposure',
  medium: 'Moderate exposure',
  low: 'Low exposure',
  info: 'No significant issues found',
}

export function RiskScore({ score, factors }: { score: number; factors: ScoreFactor[] }) {
  const level = levelFor(score)
  const color = `var(--sev-${level === 'info' ? 'info' : level})`
  return (
    <Card className="flex flex-col" aria-labelledby="risk-title">
      <CardHeader id="risk-title" title="Risk score" icon={<Gauge size={20} />} description="0 = minimal, 100 = severe" />

      {/* Semi-circle gauge; the number sits below it in normal flow (no overlap). */}
      <div className="mx-auto h-[120px] w-full max-w-[240px]" aria-hidden="true">
        <ResponsiveContainer width="100%" height="100%">
          <RadialBarChart
            data={[{ value: score }]}
            startAngle={180}
            endAngle={0}
            innerRadius="140%"
            outerRadius="190%"
            cy="100%"
            barSize={18}
          >
            <PolarAngleAxis type="number" domain={[0, 100]} tick={false} axisLine={false} />
            <RadialBar
              dataKey="value"
              cornerRadius={12}
              fill={color}
              background={{ fill: 'var(--glass-strong)' }}
              isAnimationActive={!window.matchMedia('(prefers-reduced-motion: reduce)').matches}
            />
          </RadialBarChart>
        </ResponsiveContainer>
      </div>
      <div className="mt-3 text-center">
        <p className="font-mono text-5xl font-bold tabular-nums" aria-label={`Risk score ${score} out of 100`}>
          {score}
          <span className="text-xl text-muted">/100</span>
        </p>
        <p className={cn('mt-1 font-semibold', severityClass(level))}>{LEVEL_TEXT[level]}</p>
      </div>

      {factors.length > 0 && (
        <div className="mt-5 border-t border-glass-border pt-4">
          <h3 className="mb-2 text-sm font-semibold text-muted">Top factors</h3>
          <ul className="flex flex-col gap-2">
            {factors.map((f) => (
              <li key={f.label} className="flex items-start justify-between gap-3 text-sm">
                <span className="flex min-w-0 items-start gap-2">
                  <span
                    aria-hidden="true"
                    className={cn('mt-1.5 size-2 shrink-0 rounded-full bg-current', severityClass((f.severity ?? 'info') as Severity))}
                  />
                  <span className="min-w-0 [overflow-wrap:anywhere]">
                    {f.label}
                    <span className="sr-only"> ({SEVERITY_LABEL[(f.severity ?? 'info') as Severity]})</span>
                  </span>
                </span>
                <span className="shrink-0 font-mono text-muted tabular-nums">+{f.points}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </Card>
  )
}
