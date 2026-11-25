import { useState } from 'react'
import { FileJson, Printer } from 'lucide-react'

import { api, ApiError } from '../../api/client'
import { Button } from '../ui/Button'

export function ExportButtons({ scanId, domain }: { scanId: string; domain: string }) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const downloadJson = async () => {
    setBusy(true)
    setError(null)
    try {
      const data = await api.exportScan(scanId)
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `reconlens-${domain.replace(/[^a-z0-9.-]/gi, '_')}.json`
      document.body.appendChild(a)
      a.click()
      a.remove()
      window.setTimeout(() => URL.revokeObjectURL(url), 1000)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Export failed.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="no-print flex flex-col items-start gap-1 sm:items-end">
      <div className="flex flex-wrap gap-2">
        <Button size="sm" onClick={downloadJson} loading={busy} icon={<FileJson size={16} aria-hidden="true" />}>
          Export JSON
        </Button>
        <Button size="sm" onClick={() => window.print()} icon={<Printer size={16} aria-hidden="true" />}>
          Save as PDF
        </Button>
      </div>
      {error && (
        <p role="alert" className="text-xs text-danger">
          {error}
        </p>
      )}
    </div>
  )
}
