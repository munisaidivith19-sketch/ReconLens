import { useAuth } from '../../hooks/useAuth'
import { useTriage } from '../../hooks/useTriage'
import type { ScanDetail, VirusTotalResult } from '../../types/scan'
import { Alert } from '../ui/Alert'
import { Badge } from '../ui/Badge'
import { AiReport, PrioritizedFindings } from './AiReport'
import { BlocklistsPanel } from './BlocklistsPanel'
import { ClientSidePanel } from './ClientSidePanel'
import { CveTable } from './CveTable'
import { DnsPanel } from './DnsPanel'
import { EmailSecurityPanel } from './EmailSecurityPanel'
import { EndpointsPanel } from './EndpointsPanel'
import { ExposedServicesPanel } from './ExposedServicesPanel'
import { FaviconPanel } from './FaviconPanel'
import { HstsPreloadPanel } from './HstsPreloadPanel'
import { IpIntelPanel } from './IpIntelPanel'
import { FindingsList } from './FindingsList'
import { LookalikesPanel } from './LookalikesPanel'
import { OriginHintsPanel } from './OriginHintsPanel'
import { RiskFactors, RiskScore } from './RiskScore'
import { ScanComparison } from './ScanComparison'
import { SecurityTxtPanel } from './SecurityTxtPanel'
import { SubdomainsPanel } from './SubdomainsPanel'
import { QuickWins, SummaryPanel } from './SummaryPanel'
import { TakeoverPanel } from './TakeoverPanel'
import { TechStackPanel } from './TechStackPanel'
import { WebSecurityPanel } from './WebSecurityPanel'
import { WordPressPanel } from './WordPressPanel'

function ReputationSummary({ data }: { data?: VirusTotalResult }) {
  const stats = data?.stats ?? {}
  if (!data || data.status !== 'ok')
    return <p className="text-sm text-muted">{data?.message ?? 'Reputation data unavailable.'}</p>
  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-wrap gap-2">
        <Badge tone={stats.malicious ? 'danger' : 'ok'}>{stats.malicious ?? 0} malicious</Badge>
        <Badge tone={stats.suspicious ? 'warn' : 'neutral'}>{stats.suspicious ?? 0} suspicious</Badge>
        <Badge>{stats.harmless ?? 0} harmless</Badge>
        {typeof data.reputation === 'number' && <Badge>reputation {data.reputation}</Badge>}
      </div>
      {data.permalink && (
        <a
          href={data.permalink}
          target="_blank"
          rel="noopener noreferrer"
          className="w-fit text-sm font-semibold text-accent-text underline-offset-4 hover:underline"
        >
          View on VirusTotal
        </a>
      )}
    </div>
  )
}

/** The full report body, shared by the owner's page and the read-only share page. */
export function Report({ scan, compare = true }: { scan: ScanDetail; compare?: boolean }) {
  // compare=true means the owner's own view (not a shared link): triage is available to accounts.
  const { isGuest } = useAuth()
  const triage = useTriage(scan.id, compare && !isGuest)
  const r = scan.results
  const failed = scan.stages.filter((s) => s.status === 'failed')
  return (
    <div className="flex flex-col gap-5">
      {failed.length > 0 && (
        <Alert tone="warning" title={`${failed.length} check(s) did not complete`}>
          {failed.map((s) => `${s.label}: ${s.error ?? 'failed'}`).join(' · ')}. The rest of the report is unaffected.
        </Alert>
      )}
      <div className="grid gap-5 lg:grid-cols-3">
        <div className="flex min-w-0 flex-col gap-5">
          <RiskScore score={scan.risk_score ?? 0} reputation={<ReputationSummary data={r.virustotal} />} />
          <RiskFactors factors={scan.score_factors} className="flex-1" />
        </div>
        <div className="min-w-0 lg:col-span-2">
          <AiReport report={scan.ai_report} />
        </div>
      </div>
      {compare && <ScanComparison scan={scan} />}
      <div className="grid gap-5 lg:grid-cols-2">
        <SummaryPanel scan={scan} />
        <QuickWins scan={scan} />
      </div>
      <PrioritizedFindings findings={scan.ai_report?.prioritized_findings ?? []} />
      <FindingsList findings={scan.findings} domain={scan.domain} triage={triage} />
      <EmailSecurityPanel data={r.email_security} />
      <div className="grid gap-5 lg:grid-cols-2">
        <TechStackPanel data={r.tech_stack} />
        <CveTable data={r.cve_lookup} />
      </div>
      {r.wordpress?.detected && <WordPressPanel data={r.wordpress} />}
      <div className="grid gap-5 lg:grid-cols-3">
        <ExposedServicesPanel data={r.exposed_services} />
        <TakeoverPanel data={r.takeover} />
        <SecurityTxtPanel data={r.security_txt} />
      </div>
      <div className="grid gap-5 lg:grid-cols-2">
        <ClientSidePanel data={r.client_side} />
        <OriginHintsPanel data={r.origin_hints} />
      </div>
      <div className="grid gap-5 lg:grid-cols-3">
        <IpIntelPanel data={r.ip_intel} />
        <BlocklistsPanel data={r.blocklists} />
        <HstsPreloadPanel data={r.hsts_preload} />
      </div>
      <div className="grid gap-5 lg:grid-cols-2">
        <LookalikesPanel data={r.lookalikes} />
        <FaviconPanel data={r.favicon} />
      </div>
      <WebSecurityPanel tls={r.tls_check} headers={r.security_headers} />
      <div className="grid gap-5 lg:grid-cols-2">
        <EndpointsPanel data={r.endpoints} robots={r.robots_sitemap} />
        <SubdomainsPanel data={r.subdomains} />
      </div>
      <DnsPanel data={r.dns_records} whois={r.whois_rdap} />
    </div>
  )
}
