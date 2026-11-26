import { Archive, FormInput, Route } from 'lucide-react'

import type { EndpointsResult, RobotsResult } from '../../types/scan'
import { Badge } from '../ui/Badge'
import { Card, CardHeader } from '../ui/Card'
import { Disclosure, Empty } from '../ui/Disclosure'

export function EndpointsPanel({ data, robots }: { data?: EndpointsResult; robots?: RobotsResult }) {
  const forms = data?.forms ?? []
  const wb = data?.wayback
  return (
    <Card aria-labelledby="endpoints-title">
      <CardHeader
        id="endpoints-title"
        title="Endpoints"
        icon={<Route size={20} />}
        description="Listed only. ReconLens never requests discovered endpoints."
      />
      <div className="flex flex-col gap-5">
        <section aria-labelledby="forms-title">
          <h3 id="forms-title" className="mb-2 flex items-center gap-2 font-semibold">
            <FormInput size={17} aria-hidden="true" className="text-accent-text" /> Homepage forms
          </h3>
          {forms.length === 0 ? (
            <Empty>No forms on the homepage.</Empty>
          ) : (
            <ul className="flex flex-col gap-2">
              {forms.map((f, i) => (
                <li key={i} className="min-w-0 rounded-2xl border border-glass-border bg-glass p-3.5">
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge tone={f.method === 'POST' ? 'accent' : 'neutral'}>{f.method}</Badge>
                    <code className="min-w-0 text-sm [overflow-wrap:anywhere]">{f.action}</code>
                    {f.has_password && <Badge tone="warn">password field</Badge>}
                    {f.insecure_action && <Badge tone="danger">submits over HTTP</Badge>}
                  </div>
                  {f.inputs.length > 0 && (
                    <p className="mt-2 text-xs text-muted [overflow-wrap:anywhere]">
                      Inputs: {f.inputs.map((x) => `${x.name} (${x.type})`).join(', ')}
                    </p>
                  )}
                </li>
              ))}
            </ul>
          )}
        </section>

        <section aria-labelledby="wb-title">
          <h3 id="wb-title" className="mb-2 flex items-center gap-2 font-semibold">
            <Archive size={17} aria-hidden="true" className="text-accent-text" /> Wayback Machine archive
          </h3>
          {!wb || !wb.available ? (
            <Empty>{wb?.message ?? 'Archive data unavailable.'}</Empty>
          ) : (
            <div className="flex flex-col gap-2">
              <p className="text-sm text-muted">
                {wb.total_urls} archived URLs · {wb.paths.length} unique paths · {wb.parameters.length} parameter names
              </p>
              {wb.interesting.length > 0 && (
                <Disclosure summary={<span className="font-medium">Interesting paths ({wb.interesting.length})</span>}>
                  <ul className="flex max-h-72 flex-col gap-1.5 overflow-y-auto pr-1 text-sm print:max-h-none">
                    {wb.interesting.map((it) => (
                      <li key={it.path} className="flex flex-wrap items-baseline gap-x-2">
                        <code className="min-w-0 [overflow-wrap:anywhere]">{it.path}</code>
                        <span className="text-xs text-muted">{it.reason}</span>
                      </li>
                    ))}
                  </ul>
                </Disclosure>
              )}
              {(wb.parameter_classes?.length ?? 0) > 0 && (
                <Disclosure
                  defaultOpen
                  summary={<span className="font-medium">Parameters by bug type ({wb.parameter_classes!.length})</span>}
                >
                  <p className="mb-3 text-xs text-muted">
                    Hints for manual testing, grouped by name. ReconLens did not send any requests with them.
                  </p>
                  <dl className="flex flex-col gap-3">
                    {wb.parameter_classes!.map((c) => (
                      <div key={c.class} className="grid gap-1.5 sm:grid-cols-[12rem_minmax(0,1fr)]">
                        <dt className="text-sm font-medium">{c.label}</dt>
                        <dd className="flex min-w-0 flex-wrap gap-1.5">
                          {c.params.map((p) => (
                            <code key={p} className="chip text-muted">
                              {p}
                            </code>
                          ))}
                        </dd>
                      </div>
                    ))}
                  </dl>
                </Disclosure>
              )}
              {wb.parameters.length > 0 && (
                <Disclosure summary={<span className="font-medium">GET parameters ({wb.parameters.length})</span>}>
                  <div className="flex flex-wrap gap-1.5">
                    {wb.parameters.map((p) => (
                      <code key={p} className="chip text-muted">
                        {p}
                      </code>
                    ))}
                  </div>
                </Disclosure>
              )}
              {wb.paths.length > 0 && (
                <Disclosure summary={<span className="font-medium">All paths ({wb.paths.length})</span>}>
                  <ul className="max-h-72 overflow-y-auto font-mono text-xs leading-6 text-muted print:max-h-none">
                    {wb.paths.map((p) => (
                      <li key={p} className="[overflow-wrap:anywhere]">
                        {p}
                      </li>
                    ))}
                  </ul>
                </Disclosure>
              )}
            </div>
          )}
        </section>

        {robots && (
          <section aria-labelledby="robots-title">
            <h3 id="robots-title" className="mb-2 font-semibold">
              robots.txt & sitemap
            </h3>
            <p className="text-sm text-muted">
              {robots.robots_found ? `${robots.disallowed.length} disallowed path(s)` : 'No robots.txt'} ·{' '}
              {robots.sitemap_url_count !== null ? `${robots.sitemap_url_count} sitemap URL(s)` : 'no sitemap found'}
            </p>
            {robots.disallowed.length > 0 && (
              <div className="mt-2 flex flex-wrap gap-1.5">
                {robots.disallowed.slice(0, 40).map((p) => (
                  <code key={p} className={`chip ${robots.interesting.includes(p) ? 'text-warn' : 'text-muted'}`}>
                    {p}
                  </code>
                ))}
              </div>
            )}
          </section>
        )}
      </div>
    </Card>
  )
}
