import { Ban, Flag, Scale, ScanEye, ShieldCheck } from 'lucide-react'

import { Card, CardHeader } from '../components/ui/Card'

const SECTIONS = [
  {
    icon: ScanEye,
    title: 'Passive checks only',
    body: (
      <>
        <p>ReconLens collects only what a normal browser visit or a public data source provides:</p>
        <ul className="mt-2 list-disc space-y-1 pl-5">
          <li>DNS records, RDAP registration data and certificate-transparency logs (crt.sh)</li>
          <li>One homepage request, up to 10 same-site scripts and the favicon that page loads (as a browser would), plus robots.txt, sitemap.xml, security.txt and the MTA-STS mail policy if one is published</li>
          <li>A TLS handshake to read the certificate and supported protocol versions</li>
          <li>Public intelligence sources: NVD, CISA KEV, FIRST EPSS, VirusTotal, Shodan InternetDB, the Wayback Machine, Retire.js vulnerability data, Team Cymru IP-to-ASN, Spamhaus DBL, abuse.ch URLhaus and hstspreload.org</li>
        </ul>
        <p className="mt-2">
          It never sends exploit payloads, brute-forces, port-scans, fuzzes parameters, or requests the endpoints it
          discovers. Discovered endpoints are listed, not visited.
        </p>
      </>
    ),
  },
  {
    icon: ShieldCheck,
    title: 'Authorized targets only',
    body: (
      <p>
        Scan only domains you own or have explicit permission to test, such as an in-scope asset of a bug bounty program
        or a target covered by written authorization. Before every scan you must confirm this. The confirmation and its
        timestamp are stored with the scan.
      </p>
    ),
  },
  {
    icon: Ban,
    title: 'Not allowed',
    body: (
      <ul className="list-disc space-y-1 pl-5">
        <li>Scanning third-party domains without permission</li>
        <li>Using ReconLens to harass, profile or target individuals or organizations</li>
        <li>Trying to bypass the daily quota, rate limits or target restrictions</li>
        <li>Trying to reach private, internal or cloud-metadata addresses through ReconLens</li>
      </ul>
    ),
  },
  {
    icon: Scale,
    title: 'No warranty',
    body: (
      <p>
        ReconLens is provided as-is, without warranty of any kind. Results come from automated, passive checks and public
        data. They can be incomplete or wrong, and a clean result does not mean a target is secure. The AI report is
        generated from the scan findings and may contain mistakes. Verify everything before acting on it.
      </p>
    ),
  },
  {
    icon: Flag,
    title: 'Reporting misuse',
    body: (
      <p>
        If you believe ReconLens was used against your domain without authorization, or you've found a security issue in
        ReconLens itself, open an issue at{' '}
        <a
          className="font-semibold text-accent-text underline underline-offset-4"
          href="https://github.com/munisaidivith19-sketch/ReconLens/issues"
          target="_blank"
          rel="noopener noreferrer"
        >
          github.com/munisaidivith19-sketch/ReconLens
        </a>{' '}
        (for security issues, ask for a private contact channel instead of posting details publicly). Accounts used for
        abuse are removed.
      </p>
    ),
  },
]

export default function Terms() {
  return (
    <div className="mx-auto flex max-w-3xl flex-col gap-5">
      <header className="animate-rise">
        <p className="chip w-fit text-accent-text">Responsible use policy</p>
        <h1 className="mt-3 text-3xl font-bold tracking-tight">Use ReconLens responsibly</h1>
        <p className="mt-2 text-muted">
          ReconLens is a public demo for bug bounty hunters and security teams. By using it you agree to the terms below.
        </p>
      </header>
      {SECTIONS.map((s, i) => (
        <Card key={s.title} className="animate-rise" style={{ animationDelay: `${60 * (i + 1)}ms` }}>
          <CardHeader title={s.title} icon={<s.icon size={20} />} />
          <div className="text-muted [&_p]:leading-relaxed">{s.body}</div>
        </Card>
      ))}
    </div>
  )
}
