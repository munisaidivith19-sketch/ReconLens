import type { HTMLAttributes, ReactNode } from 'react'

import { cn } from './cn'

interface CardProps extends HTMLAttributes<HTMLElement> {
  as?: 'section' | 'div' | 'article'
  strong?: boolean
  interactive?: boolean
  padded?: boolean
}

export function Card({ as: Tag = 'section', strong, interactive, padded = true, className, children, ...rest }: CardProps) {
  return (
    <Tag
      className={cn(
        'glass min-w-0',
        strong && 'glass-strong',
        interactive && 'glass-interactive',
        padded && 'p-5 sm:p-6',
        className,
      )}
      {...rest}
    >
      {children}
    </Tag>
  )
}

interface CardHeaderProps {
  title: ReactNode
  icon?: ReactNode
  description?: ReactNode
  action?: ReactNode
  id?: string
}

export function CardHeader({ title, icon, description, action, id }: CardHeaderProps) {
  return (
    <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
      <div className="flex min-w-0 flex-1 items-start gap-3">
        {icon && (
          <span
            aria-hidden="true"
            className="grid size-10 shrink-0 place-items-center rounded-2xl border border-glass-border bg-glass-strong text-accent-text"
          >
            {icon}
          </span>
        )}
        <div className="min-w-0">
          <h2 id={id} className="text-lg font-semibold">
            {title}
          </h2>
          {description && <p className="mt-0.5 text-sm text-muted">{description}</p>}
        </div>
      </div>
      {action && <div className="shrink-0">{action}</div>}
    </div>
  )
}
