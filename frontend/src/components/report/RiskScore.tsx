import type { ReactNode } from 'react'
import { PolarAngleAxis, RadialBar, RadialBarChart, ResponsiveContainer } from 'recharts'
import { Gauge, ListOrdered } from 'lucide-react'

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

/** Square box: the risk gauge on top, the reputation summary underneath. */
export function RiskScore({ score, reputation }: { score: number; reputation?: ReactNode }) {
  const level = levelFor(score)
  const color = `var(--sev-${level})`
  return (
    <Card className="flex aspect-square flex-col" aria-labelledby="risk-title">
      <CardHeader id="risk-title" title="Risk score" icon={<Gauge size={20} />} description="0 = minimal, 100 = severe" />

      <div className="flex flex-1 flex-col justify-center">
        {/* Semi-circle gauge; the number sits below it in normal flow (no overlap). */}
        <div className="mx-auto h-[100px] w-full max-w-[200px]" aria-hidden="true">
          <ResponsiveContainer width="100%" height="100%">
            <RadialBarChart
              data={[{ value: score }]}
              startAngle={180}
              endAngle={0}
              innerRadius="140%"
              outerRadius="190%"
              cy="100%"
              barSize={16}
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
        <div className="mt-2 text-center">
          <p className="font-mono text-4xl font-bold tabular-nums" aria-label={`Risk score ${score} out of 100`}>
            {score}
            <span className="text-lg text-muted">/100</span>
          </p>
          <p className={cn('mt-1 font-semibold', severityClass(level))}>{LEVEL_TEXT[level]}</p>
        </div>
      </div>

      {reputation && (
        <div className="mt-4 border-t border-glass-border pt-4">
          <h3 className="mb-2 text-sm font-semibold text-muted">Reputation (VirusTotal)</h3>
          {reputation}
        </div>
      )}
    </Card>
  )
}

/** The findings that raised the score most, highest first (up to 10). */
export function RiskFactors({ factors, className }: { factors: ScoreFactor[]; className?: string }) {
  if (factors.length === 0) return null
  return (
    <Card aria-labelledby="factors-title" className={className}>
      <CardHeader
        id="factors-title"
        title={`Top ${factors.length} risk factors`}
        icon={<ListOrdered size={20} />}
        description="Points each finding adds to the score"
      />
      <ol className="flex flex-col gap-2.5">
        {factors.map((f, i) => {
          const sev = (f.severity ?? 'info') as Severity
          return (
            <li key={`${f.label}-${i}`} className="flex items-start justify-between gap-3 text-sm">
              <span className="flex min-w-0 items-start gap-2.5">
                <span className="w-5 shrink-0 text-right font-mono text-xs leading-5 text-faint">{i + 1}</span>
                <span aria-hidden="true" className={cn('mt-1.5 size-2 shrink-0 rounded-full bg-current', severityClass(sev))} />
                <span className="min-w-0 [overflow-wrap:anywhere]">
                  {f.label}
                  <span className="sr-only"> ({SEVERITY_LABEL[sev]})</span>
                </span>
              </span>
              <span className="shrink-0 font-mono text-muted tabular-nums">+{f.points}</span>
            </li>
          )
        })}
      </ol>
    </Card>
  )
}
