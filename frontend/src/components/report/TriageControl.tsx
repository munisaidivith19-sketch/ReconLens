import { useId, useState } from 'react'

import { ApiError } from '../../api/client'
import { TRIAGE_LABEL } from '../../hooks/useTriage'
import type { TriageItem, TriageStatus } from '../../types/scan'
import { Button } from '../ui/Button'
import { formatDateTime } from '../ui/format'

const ORDER: TriageStatus[] = ['open', 'reported', 'fixed', 'accepted_risk', 'false_positive']

export function TriageControl({
  item,
  onSave,
}: {
  item?: TriageItem
  onSave: (status: TriageStatus, note: string) => Promise<void>
}) {
  const id = useId()
  const [status, setStatus] = useState<TriageStatus>(item?.status ?? 'open')
  const [note, setNote] = useState(item?.note ?? '')
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null)
  const dirty = status !== (item?.status ?? 'open') || note !== (item?.note ?? '')

  const save = async () => {
    setBusy(true)
    setMsg(null)
    try {
      await onSave(status, note)
      setMsg({ ok: true, text: 'Saved' })
    } catch (err) {
      setMsg({ ok: false, text: err instanceof ApiError ? err.message : 'Could not save.' })
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="no-print rounded-xl border border-glass-border bg-glass p-3">
      <p className="mb-2 font-semibold">Triage</p>
      <div className="grid gap-2 sm:grid-cols-[11rem_minmax(0,1fr)_auto] sm:items-center">
        <label className="sr-only" htmlFor={`${id}-status`}>
          Status
        </label>
        <select
          id={`${id}-status`}
          value={status}
          onChange={(e) => setStatus(e.target.value as TriageStatus)}
          className="field min-h-10 py-2 text-sm"
        >
          {ORDER.map((s) => (
            <option key={s} value={s}>
              {TRIAGE_LABEL[s]}
            </option>
          ))}
        </select>
        <label className="sr-only" htmlFor={`${id}-note`}>
          Note
        </label>
        <input
          id={`${id}-note`}
          value={note}
          maxLength={1000}
          onChange={(e) => setNote(e.target.value)}
          placeholder="Note (e.g. HackerOne #12345, or why it's not an issue)"
          className="field min-h-10 py-2 text-sm"
        />
        <Button size="sm" onClick={save} loading={busy} disabled={!dirty}>
          Save
        </Button>
      </div>
      <p className="mt-1.5 text-xs text-faint" aria-live="polite">
        {msg ? (
          <span className={msg.ok ? 'text-ok' : 'text-danger'}>{msg.text}</span>
        ) : item ? (
          `Updated ${formatDateTime(item.updated_at)}. Applies to future scans of this domain too.`
        ) : (
          'Your decision carries over to future scans of this domain.'
        )}
      </p>
    </div>
  )
}
