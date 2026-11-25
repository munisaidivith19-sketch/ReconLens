import { LoaderCircle } from 'lucide-react'

import { cn } from './cn'

export function Spinner({ size = 20, className, label }: { size?: number; className?: string; label?: string }) {
  return (
    <span role={label ? 'status' : undefined} className={cn('inline-flex items-center gap-2', className)}>
      <LoaderCircle aria-hidden="true" size={size} className="animate-spin motion-reduce:animate-none" />
      {label && <span className="text-sm text-muted">{label}</span>}
    </span>
  )
}
