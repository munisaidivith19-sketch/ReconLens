import { useId, useState, type ReactNode } from 'react'
import { ChevronDown } from 'lucide-react'

import { cn } from './cn'

interface DisclosureProps {
  summary: ReactNode
  children: ReactNode
  defaultOpen?: boolean
  className?: string
}

/** Accessible expand/collapse. Content is always shown when printing. */
export function Disclosure({ summary, children, defaultOpen = false, className }: DisclosureProps) {
  const [open, setOpen] = useState(defaultOpen)
  const id = useId()
  return (
    <div className={cn('rounded-2xl border border-glass-border bg-glass', className)}>
      <button
        type="button"
        aria-expanded={open}
        aria-controls={id}
        onClick={() => setOpen((o) => !o)}
        className="flex min-h-12 w-full cursor-pointer items-center gap-3 rounded-2xl px-4 py-3 text-left transition-colors hover:bg-glass-strong"
      >
        <div className="min-w-0 flex-1">{summary}</div>
        <ChevronDown
          aria-hidden="true"
          size={18}
          className={cn('no-print shrink-0 text-muted transition-transform duration-300', open && 'rotate-180')}
        />
      </button>
      <div id={id} className={cn('px-4 pb-4', open ? 'block' : 'hidden print:block')}>
        {children}
      </div>
    </div>
  )
}

export function KeyValue({ items }: { items: { label: string; value: ReactNode }[] }) {
  return (
    <dl className="grid gap-x-6 gap-y-3 sm:grid-cols-2">
      {items.map((it) => (
        <div key={it.label} className="min-w-0">
          <dt className="text-xs tracking-wide text-muted uppercase">{it.label}</dt>
          <dd className="mt-0.5 [overflow-wrap:anywhere]">{it.value}</dd>
        </div>
      ))}
    </dl>
  )
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="rounded-2xl border border-dashed border-glass-border px-4 py-6 text-center text-sm text-muted">{children}</p>
}
