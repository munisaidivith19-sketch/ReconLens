import type { ReactNode } from 'react'

import type { Severity } from '../../types/scan'
import { cn } from './cn'

const SEVERITY_CLASS: Record<Severity, string> = {
  critical: 'text-sev-critical',
  high: 'text-sev-high',
  medium: 'text-sev-medium',
  low: 'text-sev-low',
  info: 'text-sev-info',
}

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
}

export function severityClass(s: Severity): string {
  return SEVERITY_CLASS[s] ?? SEVERITY_CLASS.info
}

export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  return (
    <span className={cn('chip', severityClass(severity), className)}>
      <span aria-hidden="true" className="size-1.5 rounded-full bg-current" />
      {SEVERITY_LABEL[severity] ?? severity}
    </span>
  )
}

type Tone = 'neutral' | 'accent' | 'ok' | 'danger' | 'warn'

const TONE_CLASS: Record<Tone, string> = {
  neutral: 'text-muted',
  accent: 'text-accent-text',
  ok: 'text-ok',
  danger: 'text-danger',
  warn: 'text-warn',
}

interface BadgeProps {
  tone?: Tone
  children: ReactNode
  className?: string
  title?: string
}

export function Badge({ tone = 'neutral', children, className, title }: BadgeProps) {
  return (
    <span className={cn('chip', TONE_CLASS[tone], className)} title={title}>
      {children}
    </span>
  )
}
