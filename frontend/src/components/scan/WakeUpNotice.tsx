import { useEffect, useState } from 'react'
import { Coffee } from 'lucide-react'

import { api } from '../../api/client'
import { Spinner } from '../ui/Spinner'

/**
 * Render's free tier sleeps after 15 idle minutes and takes 30–60s to wake.
 * If /api/health is slow, explain that instead of showing an error.
 */
export function WakeUpNotice({ slowAfterMs = 2500 }: { slowAfterMs?: number }) {
  const [state, setState] = useState<'checking' | 'slow' | 'ready' | 'down'>('checking')

  useEffect(() => {
    let cancelled = false
    const ctrl = new AbortController()
    const slowTimer = window.setTimeout(() => !cancelled && setState((s) => (s === 'checking' ? 'slow' : s)), slowAfterMs)

    const attempt = async (n: number): Promise<void> => {
      try {
        await api.health(ctrl.signal)
        if (!cancelled) setState('ready')
      } catch {
        if (cancelled) return
        if (n < 8) {
          setState('slow')
          await new Promise((r) => window.setTimeout(r, 6000))
          if (!cancelled) return attempt(n + 1)
        } else setState('down')
      }
    }
    void attempt(0)
    return () => {
      cancelled = true
      ctrl.abort()
      window.clearTimeout(slowTimer)
    }
  }, [slowAfterMs])

  if (state === 'slow')
    return (
      <div role="status" className="glass flex items-center gap-3 rounded-2xl p-4">
        <Coffee aria-hidden="true" size={20} className="shrink-0 text-warn" />
        <div className="min-w-0 flex-1">
          <p className="font-semibold">Waking up the scan engine…</p>
          <p className="text-sm text-muted">The free server sleeps when idle. This usually takes 30–60 seconds.</p>
        </div>
        <Spinner size={18} />
      </div>
    )
  if (state === 'down')
    return (
      <div role="alert" className="glass rounded-2xl p-4 text-sm">
        <p className="font-semibold text-danger">The scan engine isn't responding.</p>
        <p className="text-muted">Please try again in a minute.</p>
      </div>
    )
  return null
}
