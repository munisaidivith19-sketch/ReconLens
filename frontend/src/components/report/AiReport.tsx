import { Bot, Compass, FileWarning, ListChecks, Route, Sparkles } from 'lucide-react'

import type { AiReport as AiReportType } from '../../types/scan'
import { Badge, SeverityBadge } from '../ui/Badge'
import { Card, CardHeader } from '../ui/Card'
import { Disclosure } from '../ui/Disclosure'

export function AiReport({ report }: { report: AiReportType | null }) {
  if (!report)
    return (
      <Card>
        <CardHeader title="AI report" icon={<Bot size={20} />} description="The report was not generated for this scan." />
      </Card>
    )

  const isAi = report.generated_by.startsWith('groq:')
  return (
    <Card aria-labelledby="ai-title" className="flex flex-col gap-6">
      <CardHeader
        id="ai-title"
        title="Analyst report"
        icon={isAi ? <Sparkles size={20} /> : <Bot size={20} />}
        description={isAi ? 'Written by AI from the scan findings only' : 'Template report built from the scan findings'}
        action={
          <Badge tone={isAi ? 'accent' : 'neutral'} title={report.generated_by}>
            {isAi ? report.generated_by.replace('groq:', '') : 'template'}
          </Badge>
        }
      />

      <div>
        <div className="mb-2 flex flex-wrap items-center gap-2">
          <h3 className="font-semibold">Executive summary</h3>
          <SeverityBadge severity={report.risk_level} />
        </div>
        <p className="leading-relaxed text-muted [overflow-wrap:anywhere]">{report.executive_summary}</p>
      </div>

      {report.prioritized_findings.length > 0 && (
        <section aria-labelledby="pf-title">
          <h3 id="pf-title" className="mb-3 flex items-center gap-2 font-semibold">
            <ListChecks size={18} aria-hidden="true" className="text-accent-text" />
            Prioritized findings
          </h3>
          <ol className="flex flex-col gap-2">
            {report.prioritized_findings.map((f, i) => (
              <li key={`${f.title}-${i}`}>
                <Disclosure
                  defaultOpen={i === 0}
                  summary={
                    <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
                      <span className="font-mono text-sm text-faint">{String(i + 1).padStart(2, '0')}</span>
                      <span className="min-w-0 font-medium [overflow-wrap:anywhere]">{f.title}</span>
                      <SeverityBadge severity={f.severity} />
                    </span>
                  }
                >
                  <dl className="grid gap-3 text-sm md:grid-cols-3">
                    <div className="min-w-0">
                      <dt className="font-semibold">Why it matters</dt>
                      <dd className="mt-1 text-muted [overflow-wrap:anywhere]">{f.why_it_matters}</dd>
                    </div>
                    <div className="min-w-0">
                      <dt className="font-semibold">How it could be abused</dt>
                      <dd className="mt-1 text-muted [overflow-wrap:anywhere]">{f.abuse_scenario}</dd>
                    </div>
                    <div className="min-w-0">
                      <dt className="font-semibold">How to fix</dt>
                      <dd className="mt-1 text-muted [overflow-wrap:anywhere]">{f.remediation}</dd>
                    </div>
                  </dl>
                </Disclosure>
              </li>
            ))}
          </ol>
        </section>
      )}

      {report.attack_paths.length > 0 && (
        <section aria-labelledby="ap-title">
          <h3 id="ap-title" className="mb-3 flex items-center gap-2 font-semibold">
            <Route size={18} aria-hidden="true" className="text-accent-text" />
            Likely attack paths
          </h3>
          <div className="grid gap-3 md:grid-cols-2">
            {report.attack_paths.map((p) => (
              <div key={p.name} className="min-w-0 rounded-2xl border border-glass-border bg-glass p-4">
                <p className="font-medium [overflow-wrap:anywhere]">{p.name}</p>
                <ol className="mt-3 flex flex-col gap-2">
                  {p.steps.map((s, i) => (
                    <li key={i} className="flex items-start gap-3 text-sm">
                      <span
                        aria-hidden="true"
                        className="grid size-6 shrink-0 place-items-center rounded-full bg-glass-strong font-mono text-xs text-accent-text"
                      >
                        {i + 1}
                      </span>
                      <span className="min-w-0 pt-0.5 text-muted [overflow-wrap:anywhere]">{s}</span>
                    </li>
                  ))}
                </ol>
                {p.related_findings.length > 0 && (
                  <p className="mt-3 text-xs text-faint [overflow-wrap:anywhere]">Based on: {p.related_findings.join('; ')}</p>
                )}
              </div>
            ))}
          </div>
        </section>
      )}

      <div className="grid gap-4 md:grid-cols-2">
        {report.next_steps.length > 0 && (
          <section aria-labelledby="ns-title" className="min-w-0">
            <h3 id="ns-title" className="mb-2 flex items-center gap-2 font-semibold">
              <Compass size={18} aria-hidden="true" className="text-accent-text" />
              Next steps for a bug hunter
            </h3>
            <ul className="list-disc space-y-1.5 pl-5 text-sm text-muted">
              {report.next_steps.map((s, i) => (
                <li key={i} className="[overflow-wrap:anywhere]">
                  {s}
                </li>
              ))}
            </ul>
          </section>
        )}
        {report.data_gaps.length > 0 && (
          <section aria-labelledby="dg-title" className="min-w-0">
            <h3 id="dg-title" className="mb-2 flex items-center gap-2 font-semibold">
              <FileWarning size={18} aria-hidden="true" className="text-warn" />
              Data gaps
            </h3>
            <ul className="list-disc space-y-1.5 pl-5 text-sm text-muted">
              {report.data_gaps.map((s, i) => (
                <li key={i} className="[overflow-wrap:anywhere]">
                  {s}
                </li>
              ))}
            </ul>
          </section>
        )}
      </div>
    </Card>
  )
}
