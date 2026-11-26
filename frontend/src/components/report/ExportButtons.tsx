import { useState } from 'react'
import { FileJson, FileSpreadsheet, FileText, Printer } from 'lucide-react'

import { api, ApiError } from '../../api/client'
import type { ScanDetail } from '../../types/scan'
import { Button } from '../ui/Button'
import { downloadText, scanCsv, scanMarkdown } from './taxonomy'

export function ExportButtons({ scan }: { scan: ScanDetail }) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const base = `reconlens-${scan.domain.replace(/[^a-z0-9.-]/gi, '_')}`

  const downloadJson = async () => {
    setBusy(true)
    setError(null)
    try {
      const data = await api.exportScan(scan.id)
      downloadText(JSON.stringify(data, null, 2), `${base}.json`, 'application/json')
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
          JSON
        </Button>
        <Button
          size="sm"
          onClick={() => downloadText('﻿' + scanCsv(scan), `${base}-findings.csv`, 'text/csv;charset=utf-8')}
          icon={<FileSpreadsheet size={16} aria-hidden="true" />}
        >
          CSV
        </Button>
        <Button
          size="sm"
          onClick={() => downloadText(scanMarkdown(scan), `${base}.md`, 'text/markdown;charset=utf-8')}
          icon={<FileText size={16} aria-hidden="true" />}
        >
          Markdown
        </Button>
        <Button size="sm" onClick={() => window.print()} icon={<Printer size={16} aria-hidden="true" />}>
          PDF
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
