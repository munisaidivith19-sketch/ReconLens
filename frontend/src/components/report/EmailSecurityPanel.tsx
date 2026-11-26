import { MailCheck, MailWarning, MailX } from 'lucide-react'

import type { EmailHardening, EmailSecurityResult } from '../../types/scan'
import { Badge } from '../ui/Badge'
import { Card, CardHeader } from '../ui/Card'
import { cn } from '../ui/cn'
import { Empty } from '../ui/Disclosure'

const VERDICT = {
  protected: { tone: 'ok' as const, icon: MailCheck, label: 'Protected', cls: 'text-ok' },
  partial: { tone: 'warn' as const, icon: MailWarning, label: 'Partially protected', cls: 'text-warn' },
  spoofable: { tone: 'danger' as const, icon: MailX, label: 'Spoofable', cls: 'text-danger' },
}

interface RowProps {
  label: string
  ok: boolean
  record: string | null
  issues: string[]
  /** Missing is not a weakness (shown neutral instead of red). */
  optional?: boolean
}

function Row({ label, ok, record, issues, optional }: RowProps) {
  const tone = ok ? 'ok' : record ? 'warn' : optional ? 'neutral' : 'danger'
  return (
    <div className="min-w-0 rounded-2xl border border-glass-border bg-glass p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="font-semibold">{label}</span>
        <Badge tone={tone}>{ok ? 'OK' : record ? 'Weak' : optional ? 'Not set' : 'Missing'}</Badge>
      </div>
      {record && (
        <p className="mt-2 rounded-xl bg-glass-strong px-3 py-2 font-mono text-xs text-muted [overflow-wrap:anywhere]">{record}</p>
      )}
      {issues.length > 0 && (
        <ul className="mt-2 list-disc space-y-1 pl-5 text-sm text-muted">
          {issues.map((i) => (
            <li key={i}>{i}</li>
          ))}
        </ul>
      )}
    </div>
  )
}

export function EmailSecurityPanel({ data }: { data?: EmailSecurityResult }) {
  if (!data)
    return (
      <Card>
        <CardHeader title="Email security" icon={<MailWarning size={20} />} />
        <Empty>The email security check did not complete.</Empty>
      </Card>
    )
  const v = VERDICT[data.verdict_level] ?? VERDICT.spoofable
  const dmarcOk = data.dmarc.policy === 'reject' || data.dmarc.policy === 'quarantine'
  return (
    <Card aria-labelledby="email-title">
      <CardHeader
        id="email-title"
        title="Email security"
        icon={<v.icon size={20} />}
        description="Can this domain be spoofed in phishing emails?"
        action={<Badge tone={v.tone}>{v.label}</Badge>}
      />
      <p className={cn('mb-4 rounded-2xl border border-glass-border bg-glass-strong p-4 font-medium', v.cls)}>{data.verdict}</p>
      <div className="grid gap-3 lg:grid-cols-3">
        <Row
          label="SPF"
          ok={Boolean(data.spf.record) && data.spf.issues.length === 0}
          record={data.spf.record}
          issues={data.spf.issues}
        />
        <Row
          label={`DMARC${data.dmarc.inherited_from ? ` (from ${data.dmarc.inherited_from})` : ''}`}
          ok={dmarcOk && data.dmarc.issues.length === 0}
          record={data.dmarc.record}
          issues={data.dmarc.issues}
        />
        <Row
          label="DKIM"
          ok={data.dkim.selectors_found.length > 0}
          record={data.dkim.selectors_found.length ? `Selectors: ${data.dkim.selectors_found.join(', ')}` : null}
          issues={
            data.dkim.selectors_found.length
              ? []
              : data.dkim.wildcard
                ? ['A wildcard _domainkey record answers every selector, so DKIM keys cannot be verified passively']
                : [`None of ${data.dkim.selectors_checked.length} common selectors found (custom selectors can't be discovered passively)`]
          }
        />
      </div>
      {data.hardening && <Hardening h={data.hardening} />}
    </Card>
  )
}

function Hardening({ h }: { h: EmailHardening }) {
  const sts = h.mta_sts
  const mode = sts.policy?.mode
  return (
    <section aria-label="Mail transport security" className="mt-5">
      <h3 className="mb-2 text-sm font-semibold text-muted">Mail transport security</h3>
      <div className="grid gap-3 lg:grid-cols-3">
        <Row
          label="MTA-STS"
          ok={mode === 'enforce'}
          record={sts.policy ? `mode: ${mode}${sts.policy.mx.length ? ` · mx: ${sts.policy.mx.join(', ')}` : ''}` : sts.record}
          issues={
            !sts.record
              ? ['Sending servers may deliver mail to you without TLS, or to a forged MX']
              : sts.policy_error
                ? [`Policy file unavailable: ${sts.policy_error}`]
                : mode !== 'enforce'
                  ? ['Policy is not enforced yet']
                  : []
          }
        />
        <Row
          label="TLS-RPT"
          ok={Boolean(h.tls_rpt.record)}
          record={h.tls_rpt.record}
          issues={h.tls_rpt.record ? [] : ['No reports of failed TLS delivery to your mail servers']}
        />
        <Row
          label="BIMI"
          ok={Boolean(h.bimi.record)}
          optional
          record={h.bimi.record}
          issues={h.bimi.record ? [] : ['Optional: shows your verified logo in supporting inboxes']}
        />
      </div>
    </section>
  )
}
