export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical'
export type ScanStatus = 'queued' | 'running' | 'completed' | 'failed' | 'interrupted'
export type StageStatus = 'pending' | 'running' | 'done' | 'failed' | 'skipped'

export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

export interface User {
  id: string
  email: string
  created_at: string
}

export interface GuestTokenResponse {
  access_token: string
  token_type: string
  expires_in: number
  guest_id: string
}

export interface Quota {
  limit: number
  used: number
  remaining: number
  /** True when the visitor is not signed in (limit is the free guest allowance). */
  guest: boolean
}

export interface TokenResponse {
  access_token: string
  token_type: string
  expires_in: number
  user: User
}

export interface Stage {
  name: string
  label: string
  status: StageStatus
  started_at: string | null
  finished_at: string | null
  error: string | null
}

export interface Finding {
  id: string
  title: string
  severity: Severity
  category: string
  scanner: string
  evidence: string
  recommendation: string
  references: string[]
}

export interface ScoreFactor {
  label: string
  points: number
  severity: string | null
}

export interface PrioritizedFinding {
  title: string
  severity: Severity
  why_it_matters: string
  abuse_scenario: string
  remediation: string
}

export interface AttackPath {
  name: string
  steps: string[]
  related_findings: string[]
}

export interface AiReport {
  executive_summary: string
  risk_level: Severity
  prioritized_findings: PrioritizedFinding[]
  attack_paths: AttackPath[]
  next_steps: string[]
  data_gaps: string[]
  generated_by: string
}

export interface ScanSummary {
  id: string
  domain: string
  input: string
  status: ScanStatus
  risk_score: number | null
  findings_count: number
  created_at: string
  finished_at: string | null
  cached: boolean
  batch_id?: string | null
}

/* Scanner result payloads (loose: scanners may add fields over time) */

export interface DnsResult {
  records: Record<string, string[]>
  errors?: Record<string, string>
  /* Added later; missing on older scans. */
  srv?: { service: string; records: string[] }[]
  ptr?: { ip: string; names: string[] }[]
  wildcard?: boolean
  dnssec?: { ds: boolean; dnskey: boolean; signed: boolean }
  mail_providers?: string[]
  services?: { service: string; record: string }[]
}

export interface TakeoverEntry {
  name: string
  cname: string
  target_exists: boolean | null
  service: string | null
  reference: string | null
}

export interface TakeoverResult {
  checked: number
  total: number
  timed_out: boolean
  cnames: TakeoverEntry[]
  takeover: TakeoverEntry[]
  dangling: TakeoverEntry[]
  cloud_hosted: TakeoverEntry[]
  resolved?: Record<string, string[]>
}

export interface ClientSecret {
  type: string
  label: string
  severity: Severity
  matches: { value: string; source: string }[]
}

export interface LibraryVuln {
  below: string | null
  at_or_above: string | null
  severity: Severity
  cves: string[]
  summary: string
  ghsa?: string | null
  info: string[]
}

export interface JsLibrary {
  component: string
  version: string
  source: string
  detected_by: string
  vulnerabilities: LibraryVuln[]
  severity: Severity | null
}

export interface SriReport {
  external_total: number
  with_integrity: number
  missing: { url: string; kind: 'script' | 'stylesheet'; dynamic: boolean }[]
  missing_pinnable: number
}

export interface FaviconResult {
  found: boolean
  message?: string
  url?: string
  bytes?: number
  content_type?: string | null
  mmh3?: number
  md5?: string
  sha256?: string
  searches?: { engine: string; query: string; url: string }[]
}

export interface Lookalike {
  domain: string
  technique: string
  ips: string[]
  mx: string[]
}

export interface LookalikesResult {
  base: string
  generated: number
  checked: number
  timed_out?: boolean
  registered: Lookalike[]
  registered_count?: number
  with_mail?: number
}

export interface ClientSideResult {
  status: 'ok' | 'unavailable'
  message?: string
  scripts_found?: number
  scripts_external?: number
  scripts?: { url: string; status: number | null; bytes?: number; truncated?: boolean; error?: string }[]
  secrets?: ClientSecret[]
  buckets?: { provider: string; name: string; url: string; source: string }[]
  endpoints?: { path: string; source: string }[]
  in_scope_hosts?: string[]
  third_party_hosts?: string[]
  source_maps?: { url: string; source: string }[]
  libraries?: JsLibrary[]
  sri?: SriReport
}

export interface OriginCandidate {
  name: string
  ips: string[]
  cname: string | null
  same_network: boolean
  hint: string | null
  provider?: string | null
}

export interface OriginHintsResult {
  behind_cdn: boolean
  cdn: string[]
  main_ips: string[]
  main_ptr: Record<string, string[]>
  resolved_count: number
  unique_ips: number
  ip_groups: { ip: string; names: string[]; count: number }[]
  candidates: OriginCandidate[]
}

export interface SecurityTxtResult {
  found: boolean
  url?: string
  fields?: Record<string, string[]>
  expired?: boolean | null
  bug_bounty_hint?: boolean
  message?: string | null
}

export interface ExposedHost {
  ip: string
  ports: number[]
  cpes: string[]
  hostnames: string[]
  tags: string[]
  vulns: string[]
  known: boolean
}

export interface ExposedServicesResult {
  source: string
  available: boolean
  hosts: ExposedHost[]
  errors: string[]
  message?: string | null
}

export interface WhoisResult {
  registrable_domain?: string
  registrar?: string | null
  created?: string | null
  expires?: string | null
  updated?: string | null
  nameservers?: string[]
  status?: string[]
  days_until_expiry?: number | null
  available?: boolean
  message?: string
}

export interface SubdomainsResult {
  source: string
  available: boolean
  count: number
  subdomains: string[]
  /** Names covered by a certificate that hasn't expired. Missing on scans made before this field existed. */
  current?: string[]
  truncated?: boolean
  interesting?: string[]
  message?: string
}

export interface EmailSecurityResult {
  spf: { record: string | null; all_qualifier: string | null; lookups?: number; issues: string[] }
  dmarc: { record: string | null; policy: string | null; pct: number | null; rua: string[]; issues: string[]; inherited_from?: string | null }
  dkim: { selectors_found: string[]; selectors_checked: string[]; wildcard?: boolean }
  mx: string[]
  spoofable: boolean
  verdict: string
  verdict_level: 'protected' | 'partial' | 'spoofable'
  /** Only present when the domain has MX records. */
  hardening?: EmailHardening | null
}

export interface EmailHardening {
  mta_sts: {
    record: string | null
    policy: { version: string | null; mode: string | null; max_age: number | null; mx: string[] } | null
    policy_error: string | null
  }
  tls_rpt: { record: string | null; rua: string | null }
  bimi: { record: string | null; logo: string | null; certificate: string | null }
}

export interface Technology {
  name: string
  categories: string[]
  version: string
  confidence: number
  website?: string
  cpe?: string | null
}

export interface TechStackResult {
  technologies: Technology[]
  count: number
}

export interface CveItem {
  id: string
  technology: string
  version: string
  cvss: number | null
  severity: Severity
  base_severity: string | null
  description: string
  published: string | null
  kev: boolean
  kev_date_added?: string | null
  ransomware?: boolean
  epss: number | null
  epss_percentile: number | null
  url: string
}

export interface CveResult {
  cves: CveItem[]
  checked: { technology: string; version: string; status: string; count?: number }[]
  skipped: { technology: string; reason: string }[]
  kev_count: number
}

export interface VirusTotalResult {
  status: 'ok' | 'skipped' | 'not_found'
  message?: string
  stats?: Record<string, number>
  reputation?: number
  categories?: { engine: string; category: string }[]
  permalink?: string
}

export interface FormInfo {
  method: string
  action: string
  inputs: { name: string; type: string }[]
  has_password: boolean
  insecure_action: boolean
}

export interface EndpointsResult {
  forms: FormInfo[]
  wayback: {
    available: boolean
    message?: string
    total_urls: number
    paths: string[]
    parameters: string[]
    parameter_classes?: { class: string; label: string; params: string[] }[]
    interesting: { path: string; reason: string }[]
  }
}

export interface HeadersResult {
  url: string
  final_url?: string
  status_code: number
  https: boolean
  http_redirects_to_https?: boolean | null
  headers_present: Record<string, string>
  missing: string[]
  cookies: { name: string; secure: boolean; httponly: boolean; samesite: string | null }[]
  waf_cdn: string[]
  disclosure: Record<string, string>
}

export interface TlsResult {
  available: boolean
  protocol?: string | null
  cipher?: string | null
  issuer?: string | null
  subject?: string | null
  sans?: string[]
  not_before?: string | null
  not_after?: string | null
  days_until_expiry?: number | null
  hostname_match?: boolean
  trusted?: boolean
  verify_error?: string | null
  chain?: { subject: string; issuer: string }[]
  legacy_protocols?: { tls1_0?: boolean | null; tls1_1?: boolean | null }
  message?: string
}

export interface RobotsResult {
  robots_found: boolean
  disallowed: string[]
  sitemaps: string[]
  sitemap_url_count: number | null
  interesting: string[]
}

export type NetworkKind = 'cdn' | 'cloud' | 'hosting' | 'saas' | 'other' | 'unknown'

export interface IpHost {
  ip: string
  names: string[]
  asn?: number | null
  prefix?: string | null
  country?: string | null
  as_name?: string | null
  provider?: string | null
  kind: NetworkKind
}

export interface IpIntelResult {
  hosts: IpHost[]
  providers: { provider: string; kind: NetworkKind; ips: number; names: number }[]
  asn_count: number
  main_kind: NetworkKind | null
  main_provider: string | null
  source: string
}

export interface DblResult {
  status: 'listed' | 'not_listed' | 'unavailable'
  reasons: string[]
  message?: string
}

export interface UrlhausResult {
  status: 'listed' | 'not_listed' | 'unavailable' | 'skipped'
  message?: string
  url_count?: number
  online?: number
  first_seen?: string | null
  reference?: string | null
  urls?: { url: string; status: string; threat: string; date_added?: string; tags: string[] }[]
}

export interface BlocklistsResult {
  spamhaus_dbl: Record<string, DblResult>
  urlhaus: UrlhausResult
}

export interface HstsPreloadResult {
  domain: string
  status: string
  preloaded_domain?: string | null
  bulk: boolean
  covered: boolean
  header: { present: boolean; max_age: number | null; include_subdomains: boolean; preload: boolean }
  eligible: boolean
  problems: string[]
  https: boolean
}

export interface WpCve {
  id: string
  cvss: number | null
  severity: Severity
  kev: boolean
  description: string
  url: string
}

export interface WpComponent {
  type: 'plugin' | 'theme'
  slug: string
  version: string | null
  status?: string
  cves: WpCve[]
}

export interface WordPressResult {
  detected: boolean
  core_version?: string | null
  components: WpComponent[]
  plugin_count?: number
  theme_count?: number
  vulnerable_count?: number
}

export interface ScanResults {
  dns_records?: DnsResult
  whois_rdap?: WhoisResult
  subdomains?: SubdomainsResult
  robots_sitemap?: RobotsResult
  security_headers?: HeadersResult
  tls_check?: TlsResult
  email_security?: EmailSecurityResult
  tech_stack?: TechStackResult
  cve_lookup?: CveResult
  virustotal?: VirusTotalResult
  endpoints?: EndpointsResult
  takeover?: TakeoverResult
  security_txt?: SecurityTxtResult
  exposed_services?: ExposedServicesResult
  client_side?: ClientSideResult
  origin_hints?: OriginHintsResult
  favicon?: FaviconResult
  lookalikes?: LookalikesResult
  ip_intel?: IpIntelResult
  blocklists?: BlocklistsResult
  hsts_preload?: HstsPreloadResult
  wordpress?: WordPressResult
  [key: string]: unknown
}

export interface ScanDetail extends ScanSummary {
  stages: Stage[]
  results: ScanResults
  findings: Finding[]
  score_factors: ScoreFactor[]
  ai_report: AiReport | null
  confirmed_authorized: boolean
  authorized_at: string
  started_at: string | null
  error: string | null
}

export type TriageStatus = 'open' | 'false_positive' | 'accepted_risk' | 'reported' | 'fixed'

export interface TriageItem {
  status: TriageStatus
  note: string
  updated_at: string
}

export interface BatchItem {
  target: string
  ok: boolean
  scan?: ScanSummary
  cached?: boolean
  error?: { code: string; message: string }
}

export interface BatchScan extends ScanSummary {
  severities: Partial<Record<Severity, number>>
  top_findings: { id: string; title: string; severity: Severity }[]
}

export interface BatchDetail {
  batch_id: string
  created_at: string
  targets: string[]
  errors: { target: string; code: string; message: string }[]
  scans: BatchScan[]
}

export interface ApiKey {
  id: string
  name: string
  prefix: string
  created_at: string
  last_used_at: string | null
  /** Only present in the response that created the key. */
  key?: string
}

export interface ShareLink {
  token: string
  expires_at: string
  created_at: string
}

export interface ScanPage {
  items: ScanSummary[]
  total: number
  page: number
  page_size: number
}

export interface ScanCreateResponse {
  scan: ScanSummary
  cached: boolean
  quota_remaining: number | null
}
