import { useState } from 'react'
import { Check, ClipboardCopy, ExternalLink } from 'lucide-react'

import type { Finding } from '../../types/scan'
import { Badge, SeverityBadge } from '../ui/Badge'
import { Disclosure } from '../ui/Disclosure'
import { copyText, findingMarkdown, taxonomyFor } from './taxonomy'

export function FindingCard({ finding, domain }: { finding: Finding; domain?: string }) {
  const tax = taxonomyFor(finding.id)
  const [copied, setCopied] = useState<'ok' | 'fail' | null>(null)

  const copy = async () => {
    const ok = await copyText(findingMarkdown(finding, domain ?? ''))
    setCopied(ok ? 'ok' : 'fail')
    window.setTimeout(() => setCopied(null), 2000)
  }

  return (
    <Disclosure
      summary={
        <span className="grid grid-cols-1 items-center gap-x-3 gap-y-2 sm:grid-cols-[minmax(0,1fr)_6rem]">
          <span className="min-w-0 font-medium [overflow-wrap:anywhere]">{finding.title}</span>
          <span className="sm:justify-self-end">
            <SeverityBadge severity={finding.severity} className="w-24 justify-center" />
          </span>
        </span>
      }
    >
      <div className="flex flex-col gap-3 text-sm">
        {(tax.cwe || tax.owasp) && (
          <div className="flex flex-wrap gap-1.5">
            {tax.cwe && (
              <a
                href={`https://cwe.mitre.org/data/definitions/${tax.cwe.id}.html`}
                target="_blank"
                rel="noopener noreferrer"
                title={tax.cwe.name}
              >
                <Badge>CWE-{tax.cwe.id}</Badge>
              </a>
            )}
            {tax.owasp && <Badge title={tax.owasp.name}>OWASP {tax.owasp.id}</Badge>}
            {tax.quickWin && <Badge tone="ok">quick win</Badge>}
          </div>
        )}
        {finding.evidence && (
          <div>
            <p className="font-semibold">Evidence</p>
            <p className="mt-1 rounded-xl bg-glass-strong px-3 py-2 font-mono text-xs leading-relaxed text-muted [overflow-wrap:anywhere]">
              {finding.evidence}
            </p>
          </div>
        )}
        {finding.recommendation && (
          <div>
            <p className="font-semibold">Recommendation</p>
            <p className="mt-1 text-muted [overflow-wrap:anywhere]">{finding.recommendation}</p>
          </div>
        )}
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-faint">
          <span>Check: {finding.scanner}</span>
          {finding.references.map((r) => (
            <a
              key={r}
              href={r}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 text-accent-text underline-offset-4 hover:underline"
            >
              Reference <ExternalLink size={12} aria-hidden="true" />
              <span className="sr-only">(opens in a new tab)</span>
            </a>
          ))}
          <button
            type="button"
            onClick={copy}
            className="no-print ml-auto inline-flex cursor-pointer items-center gap-1 font-semibold text-accent-text underline-offset-4 hover:underline"
          >
            {copied === 'ok' ? <Check size={12} aria-hidden="true" /> : <ClipboardCopy size={12} aria-hidden="true" />}
            {copied === 'ok' ? 'Copied' : copied === 'fail' ? 'Copy failed' : 'Copy as report'}
          </button>
        </div>
      </div>
    </Disclosure>
  )
}
