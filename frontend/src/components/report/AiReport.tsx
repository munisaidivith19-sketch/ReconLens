import { Bot, Compass, FileWarning, ListChecks, Route, Sparkles } from 'lucide-react'

import type { AiReport as AiReportType, PrioritizedFinding } from '../../types/scan'
import { Badge, SeverityBadge } from '../ui/Badge'
import { Card, CardHeader } from '../ui/Card'
import { Disclosure } from '../ui/Disclosure'

export function AiReport({ report }: { report: AiReportType | null }) {
  if (!report)
    return (
      <Card className="h-full">
        <CardHeader title="AI report" icon={<Bot size={20} />} description="The report was not generated for this scan." />
      </Card>
    )

  const isAi = report.generated_by.startsWith('groq:')
  return (
    <Card aria-labelledby="ai-title" className="flex h-full flex-col gap-6">
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

/** The AI's ranked findings, shown as their own card. Each row: rank | title | severity. */
export function PrioritizedFindings({ findings }: { findings: PrioritizedFinding[] }) {
  if (findings.length === 0) return null
  return (
    <Card aria-labelledby="pf-title">
      <CardHeader
        id="pf-title"
        title="Prioritized findings"
        icon={<ListChecks size={20} />}
        description="Ranked by the analyst report, most urgent first. Open a row for details."
      />
      <ol className="flex flex-col gap-2">
        {findings.map((f, i) => (
          <li key={`${f.title}-${i}`}>
            <Disclosure
              defaultOpen={i === 0}
              summary={
                <span className="grid grid-cols-[1.75rem_minmax(0,1fr)] items-center gap-x-3 gap-y-2 sm:grid-cols-[1.75rem_minmax(0,1fr)_6rem]">
                  <span className="font-mono text-sm text-faint tabular-nums">{String(i + 1).padStart(2, '0')}</span>
                  <span className="min-w-0 font-medium [overflow-wrap:anywhere]">{f.title}</span>
                  <span className="col-start-2 sm:col-start-3 sm:justify-self-end">
                    <SeverityBadge severity={f.severity} className="w-24 justify-center" />
                  </span>
                </span>
              }
            >
              <dl className="grid gap-4 border-t border-glass-border pt-4 text-sm md:grid-cols-3">
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
    </Card>
  )
}
