import { FileCheck } from 'lucide-react'

import type { SecurityTxtResult } from '../../types/scan'
import { Badge } from '../ui/Badge'
import { Card, CardHeader } from '../ui/Card'
import { Empty } from '../ui/Disclosure'

const LABELS: Record<string, string> = {
  contact: 'Contact',
  expires: 'Expires',
  policy: 'Policy',
  encryption: 'Encryption',
  acknowledgments: 'Acknowledgments',
  acknowledgements: 'Acknowledgments',
  'preferred-languages': 'Languages',
  canonical: 'Canonical',
  hiring: 'Hiring',
  csaf: 'CSAF',
}

function isLink(v: string) {
  return /^https:\/\//i.test(v)
}

export function SecurityTxtPanel({ data }: { data?: SecurityTxtResult }) {
  return (
    <Card aria-labelledby="sectxt-title" className="flex flex-col">
      <CardHeader
        id="sectxt-title"
        title="security.txt"
        icon={<FileCheck size={20} />}
        description="How the organisation asks for vulnerability reports (RFC 9116)."
        action={
          data ? (
            <Badge tone={!data.found ? 'warn' : data.expired ? 'danger' : 'ok'}>
              {!data.found ? 'missing' : data.expired ? 'expired' : 'present'}
            </Badge>
          ) : undefined
        }
      />
      {!data ? (
        <Empty>Not checked in this scan.</Empty>
      ) : !data.found ? (
        <Empty>No security.txt was published. Look for a disclosure or bug bounty page before reporting.</Empty>
      ) : (
        <div className="flex flex-col gap-3">
          {data.bug_bounty_hint && <Badge tone="accent">Mentions a bug bounty or disclosure program</Badge>}
          <dl className="flex flex-col gap-2.5">
            {Object.entries(data.fields ?? {}).map(([key, values]) => (
              <div key={key} className="grid gap-1 sm:grid-cols-[7.5rem_minmax(0,1fr)]">
                <dt className="text-sm text-muted">{LABELS[key] ?? key}</dt>
                <dd className="flex min-w-0 flex-col gap-0.5 text-sm">
                  {values.map((v) =>
                    isLink(v) ? (
                      <a
                        key={v}
                        href={v}
                        target="_blank"
                        rel="noopener noreferrer nofollow"
                        className="text-accent-text underline-offset-4 [overflow-wrap:anywhere] hover:underline"
                      >
                        {v}
                      </a>
                    ) : (
                      <span key={v} className="[overflow-wrap:anywhere]">
                        {v}
                      </span>
                    ),
                  )}
                </dd>
              </div>
            ))}
          </dl>
          {data.url && <p className="text-xs text-faint [overflow-wrap:anywhere]">Source: {data.url}</p>}
        </div>
      )}
    </Card>
  )
}
