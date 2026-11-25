import { CircleCheck, CircleDashed, CircleX, LoaderCircle, MinusCircle } from 'lucide-react'

import type { Stage, StageStatus } from '../../types/scan'
import { Card, CardHeader } from '../ui/Card'
import { cn } from '../ui/cn'
import { duration } from '../ui/format'

const ICON: Record<StageStatus, typeof CircleCheck> = {
  pending: CircleDashed,
  running: LoaderCircle,
  done: CircleCheck,
  failed: CircleX,
  skipped: MinusCircle,
}
const TONE: Record<StageStatus, string> = {
  pending: 'text-faint',
  running: 'text-accent-text',
  done: 'text-ok',
  failed: 'text-danger',
  skipped: 'text-muted',
}
const LABEL: Record<StageStatus, string> = {
  pending: 'Waiting',
  running: 'Running',
  done: 'Done',
  failed: 'Failed',
  skipped: 'Skipped',
}

export function ProgressTracker({ stages, queued }: { stages: Stage[]; queued?: boolean }) {
  const finished = stages.filter((s) => s.status === 'done' || s.status === 'failed' || s.status === 'skipped').length
  const pct = stages.length ? Math.round((finished / stages.length) * 100) : 0
  const running = stages.filter((s) => s.status === 'running').map((s) => s.label)

  return (
    <Card aria-labelledby="progress-title">
      <CardHeader
        id="progress-title"
        title={queued ? 'Waiting for a free scan slot…' : 'Scan in progress'}
        description={
          queued
            ? 'Up to two scans run at once. Yours will start automatically.'
            : `${finished} of ${stages.length} checks complete`
        }
        icon={<LoaderCircle size={20} className="animate-spin motion-reduce:animate-none" />}
      />

      <div
        className="h-2.5 w-full overflow-hidden rounded-full bg-glass-strong"
        role="progressbar"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={pct}
        aria-label="Scan progress"
      >
        <div
          className="h-full rounded-full bg-gradient-to-r from-accent to-accent-2 transition-[width] duration-700 ease-out"
          style={{ width: `${Math.max(pct, 3)}%` }}
        />
      </div>
      <p className="sr-only" aria-live="polite">
        {running.length ? `Running: ${running.join(', ')}` : `${pct}% complete`}
      </p>

      <ol className="mt-5 grid gap-2 sm:grid-cols-2">
        {stages.map((s) => {
          const Icon = ICON[s.status]
          const took = duration(s.started_at, s.finished_at)
          return (
            <li
              key={s.name}
              className={cn(
                'flex min-w-0 items-start gap-3 rounded-2xl border border-glass-border px-3.5 py-3 transition-colors duration-300',
                s.status === 'running' ? 'bg-glass-strong' : 'bg-glass',
              )}
            >
              <Icon
                aria-hidden="true"
                size={18}
                className={cn('mt-0.5 shrink-0', TONE[s.status], s.status === 'running' && 'animate-spin motion-reduce:animate-none')}
              />
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-baseline justify-between gap-x-2">
                  <span className="font-medium">{s.label}</span>
                  <span className={cn('text-xs', TONE[s.status])}>
                    {LABEL[s.status]}
                    {took ? ` · ${took}` : ''}
                  </span>
                </div>
                {s.error && <p className="mt-0.5 text-xs text-muted [overflow-wrap:anywhere]">{s.error}</p>}
              </div>
            </li>
          )
        })}
      </ol>
    </Card>
  )
}
