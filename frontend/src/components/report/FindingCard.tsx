import { ExternalLink } from 'lucide-react'

import type { Finding } from '../../types/scan'
import { SeverityBadge } from '../ui/Badge'
import { Disclosure } from '../ui/Disclosure'

export function FindingCard({ finding }: { finding: Finding }) {
  return (
    <Disclosure
      summary={
        <span className="flex flex-wrap items-center gap-x-3 gap-y-1.5">
          <SeverityBadge severity={finding.severity} />
          <span className="min-w-0 flex-1 basis-60 font-medium [overflow-wrap:anywhere]">{finding.title}</span>
        </span>
      }
    >
      <div className="flex flex-col gap-3 text-sm">
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
        </div>
      </div>
    </Disclosure>
  )
}
