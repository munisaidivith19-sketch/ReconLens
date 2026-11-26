import type { Finding, ScanDetail, Severity } from '../../types/scan'

export interface Taxonomy {
  cwe?: { id: number; name: string }
  owasp?: { id: string; name: string }
  /** Set when the fix is a configuration change that takes minutes, not a code change. */
  quickWin?: string
}

const OWASP = {
  A01: 'Broken Access Control',
  A02: 'Cryptographic Failures',
  A04: 'Insecure Design',
  A05: 'Security Misconfiguration',
  A06: 'Vulnerable and Outdated Components',
  A07: 'Identification and Authentication Failures',
} as const

type OwaspId = keyof typeof OWASP

function t(cwe: [number, string] | null, owasp: OwaspId | null, quickWin?: string): Taxonomy {
  return {
    cwe: cwe ? { id: cwe[0], name: cwe[1] } : undefined,
    owasp: owasp ? { id: `${owasp}:2021`, name: OWASP[owasp] } : undefined,
    quickWin,
  }
}

const CLEARTEXT: [number, string] = [319, 'Cleartext Transmission of Sensitive Information']
const PROTECTION: [number, string] = [693, 'Protection Mechanism Failure']
const EXPOSURE: [number, string] = [200, 'Exposure of Sensitive Information to an Unauthorized Actor']
const CERT: [number, string] = [295, 'Improper Certificate Validation']
const SPOOFING: [number, string] = [290, 'Authentication Bypass by Spoofing']
const ACCESS: [number, string] = [284, 'Improper Access Control']
const VULN_COMPONENT: [number, string] = [1395, 'Dependency on Vulnerable Third-Party Component']

// Ordered: the first pattern that matches a finding id wins.
const RULES: [RegExp, Taxonomy][] = [
  [/^security_headers\.(missing|weak)_hsts$/, t(CLEARTEXT, 'A05', 'Add a Strict-Transport-Security header (max-age ≥ 1 year).')],
  [/^security_headers\.(missing|weak)_csp$/, t(PROTECTION, 'A05')],
  [/^security_headers\.missing_clickjacking$/, t([1021, 'Improper Restriction of Rendered UI Layers'], 'A05', "Send Content-Security-Policy: frame-ancestors 'self'.")],
  [/^security_headers\.missing_xcto$/, t(PROTECTION, 'A05', 'Send X-Content-Type-Options: nosniff.')],
  [/^security_headers\.missing_referrer_policy$/, t(EXPOSURE, 'A05', 'Send Referrer-Policy: strict-origin-when-cross-origin.')],
  [/^security_headers\.missing_permissions_policy$/, t(PROTECTION, 'A05', 'Send a Permissions-Policy that disables unused features.')],
  [/^security_headers\.cookie_no_secure$/, t([614, "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute"], 'A05', 'Add the Secure flag to cookies.')],
  [/^security_headers\.cookie_no_httponly$/, t([1004, "Sensitive Cookie Without 'HttpOnly' Flag"], 'A05', 'Add the HttpOnly flag to session cookies.')],
  [/^security_headers\.cookie_no_samesite$/, t([1275, 'Sensitive Cookie with Improper SameSite Attribute'], 'A01', 'Set SameSite=Lax (or Strict) on cookies.')],
  [/^security_headers\.(no_https|http_no_redirect)$/, t(CLEARTEXT, 'A02', 'Redirect all HTTP traffic to HTTPS.')],
  [/^security_headers\.version_disclosure$/, t(EXPOSURE, 'A05', 'Remove version numbers from Server / X-Powered-By headers.')],
  [/^security_headers\./, t(PROTECTION, 'A05')],
  [/^tls_check\.(expired|expiring|hostname_mismatch|untrusted)/, t(CERT, 'A02')],
  [/^tls_check\.legacy_tls$/, t([327, 'Use of a Broken or Risky Cryptographic Algorithm'], 'A02', 'Disable TLS 1.0 and 1.1 on the server.')],
  [/^tls_check\.weak_key$/, t([326, 'Inadequate Encryption Strength'], 'A02')],
  [/^tls_check\.weak_signature$/, t([328, 'Use of Weak Hash'], 'A02')],
  [/^email_security\.(no_dmarc|dmarc_none)$/, t(SPOOFING, 'A05', 'Publish a DMARC record, then move to p=quarantine.')],
  [/^email_security\.(no_spf|spf_plus_all|spf_issues)$/, t(SPOOFING, 'A05', 'Fix the SPF record and end it with -all or ~all.')],
  [/^email_security\./, t(SPOOFING, 'A05')],
  [/^cve_lookup\./, t(VULN_COMPONENT, 'A06')],
  [/^tech_stack\./, t(EXPOSURE, 'A05')],
  [/^takeover\./, t(ACCESS, 'A05')],
  [/^client_side\.secret\./, t([798, 'Use of Hard-coded Credentials'], 'A07')],
  [/^client_side\.source_maps$/, t([540, 'Inclusion of Sensitive Information in Source Code'], 'A05', 'Stop deploying .map files to production.')],
  [/^client_side\./, t(EXPOSURE, 'A05')],
  [/^endpoints\.archived_secrets_in_urls$/, t([598, 'Use of GET Request Method With Sensitive Query Strings'], 'A04')],
  [/^endpoints\.archived_redirect_params$/, t([601, "URL Redirection to Untrusted Site ('Open Redirect')"], 'A01')],
  [/^endpoints\.insecure_form$/, t(CLEARTEXT, 'A02')],
  [/^endpoints\.login_form$/, t(null, 'A07')],
  [/^endpoints\./, t([538, 'Insertion of Sensitive Information into Externally-Accessible File or Directory'], 'A05')],
  [/^robots_sitemap\./, t(EXPOSURE, 'A05')],
  [/^exposed_services\.vulns\./, t(VULN_COMPONENT, 'A06')],
  [/^exposed_services\./, t(ACCESS, 'A05')],
  [/^origin_hints\./, t(ACCESS, 'A05')],
  [/^dns_records\.no_caa$/, t(null, null, 'Add a CAA record naming the CAs you use.')],
  [/^dns_records\.(dnssec_broken|no_dnssec)$/, t([350, 'Reliance on Reverse DNS Resolution for a Security-Critical Action'], null)],
  [/^dns_records\.internal_srv$/, t(EXPOSURE, 'A05')],
  [/^whois_rdap\.no_transfer_lock$/, t(null, null, 'Turn on the registrar transfer lock.')],
  [/^security_txt\.missing$/, t(null, null, 'Publish /.well-known/security.txt with Contact and Expires.')],
  [/^security_txt\.expired$/, t(null, null, 'Update the Expires date in security.txt.')],
]

export function taxonomyFor(id: string): Taxonomy {
  for (const [rx, tax] of RULES) if (rx.test(id)) return tax
  return {}
}

export const SEVERITY_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }

export function bySeverity(a: Finding, b: Finding) {
  return SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || a.title.localeCompare(b.title)
}

// ------------------------------------------------------------------ text exports

export function findingMarkdown(f: Finding, domain: string): string {
  const tax = taxonomyFor(f.id)
  const lines = [
    `## ${f.title}`,
    '',
    `- **Target:** ${domain}`,
    `- **Severity:** ${f.severity}`,
    `- **Category:** ${f.category}`,
  ]
  if (tax.cwe) lines.push(`- **CWE:** CWE-${tax.cwe.id} (${tax.cwe.name})`)
  if (tax.owasp) lines.push(`- **OWASP Top 10:** ${tax.owasp.id} ${tax.owasp.name}`)
  lines.push(`- **Found by:** ReconLens passive check \`${f.id}\``, '')
  if (f.evidence) lines.push('### Evidence', '', '```', f.evidence, '```', '')
  if (f.recommendation) lines.push('### Recommendation', '', f.recommendation, '')
  if (f.references.length) lines.push('### References', '', ...f.references.map((r) => `- ${r}`), '')
  return lines.join('\n')
}

export function scanMarkdown(scan: ScanDetail): string {
  const findings = [...scan.findings].sort(bySeverity)
  const out = [
    `# ReconLens report: ${scan.domain}`,
    '',
    `- **Scanned:** ${scan.created_at}`,
    `- **Risk score:** ${scan.risk_score ?? 0}/100`,
    `- **Findings:** ${findings.length}`,
    '',
  ]
  if (scan.ai_report?.executive_summary) out.push('## Summary', '', scan.ai_report.executive_summary, '')
  out.push('# Findings', '')
  findings.forEach((f) => out.push(findingMarkdown(f, scan.domain)))
  out.push('---', 'Generated by ReconLens (passive checks only).')
  return out.join('\n')
}

function csvCell(v: string) {
  // Quote everything and neutralise spreadsheet formulas.
  const safe = /^[=+\-@\t\r]/.test(v) ? `'${v}` : v
  return `"${safe.replace(/"/g, '""')}"`
}

export function scanCsv(scan: ScanDetail): string {
  const header = ['severity', 'title', 'category', 'cwe', 'owasp', 'evidence', 'recommendation', 'id', 'references']
  const rows = [...scan.findings].sort(bySeverity).map((f) => {
    const tax = taxonomyFor(f.id)
    return [
      f.severity,
      f.title,
      f.category,
      tax.cwe ? `CWE-${tax.cwe.id}` : '',
      tax.owasp?.id ?? '',
      f.evidence,
      f.recommendation,
      f.id,
      f.references.join(' '),
    ]
  })
  return [header, ...rows].map((r) => r.map((c) => csvCell(String(c ?? ''))).join(',')).join('\r\n')
}

export function downloadText(text: string, filename: string, type: string) {
  const blob = new Blob([text], { type })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  window.setTimeout(() => URL.revokeObjectURL(url), 1000)
}

export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text)
    return true
  } catch {
    return false
  }
}
