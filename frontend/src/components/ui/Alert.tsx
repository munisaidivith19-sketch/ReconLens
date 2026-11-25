import type { ReactNode } from 'react'
import { CircleAlert, CircleCheck, Info, TriangleAlert } from 'lucide-react'

import { cn } from './cn'

type Tone = 'info' | 'success' | 'warning' | 'danger'

const ICONS = { info: Info, success: CircleCheck, warning: TriangleAlert, danger: CircleAlert }
const TONES: Record<Tone, string> = {
  info: 'text-accent-text',
  success: 'text-ok',
  warning: 'text-warn',
  danger: 'text-danger',
}

interface AlertProps {
  tone?: Tone
  title?: ReactNode
  children?: ReactNode
  action?: ReactNode
  className?: string
}

export function Alert({ tone = 'info', title, children, action, className }: AlertProps) {
  const Icon = ICONS[tone]
  return (
    <div
      role={tone === 'danger' || tone === 'warning' ? 'alert' : 'status'}
      className={cn('glass flex flex-wrap items-start gap-3 rounded-2xl p-4', className)}
    >
      <Icon aria-hidden="true" size={20} className={cn('mt-0.5 shrink-0', TONES[tone])} />
      <div className="min-w-0 flex-1 basis-56">
        {title && <p className="font-semibold">{title}</p>}
        {children && <div className="text-sm text-muted [overflow-wrap:anywhere]">{children}</div>}
      </div>
      {action && <div className="shrink-0">{action}</div>}
    </div>
  )
}
