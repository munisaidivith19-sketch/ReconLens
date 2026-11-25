import type { ReactNode } from 'react'
import { Bug, Globe, MailWarning, ShieldCheck } from 'lucide-react'

const FEATURES = [
  { icon: Globe, title: 'Passive OSINT', text: 'DNS, RDAP, certificate transparency and archived URLs. Nothing intrusive.' },
  { icon: Bug, title: 'CVE intelligence', text: 'Detected versions matched to NVD, plus CISA KEV and EPSS context.' },
  { icon: MailWarning, title: 'Email spoofing', text: 'SPF, DMARC and DKIM checks with a plain-language verdict.' },
  { icon: ShieldCheck, title: 'AI report', text: 'A prioritized report grounded only in what the scan found.' },
]

export function AuthShell({ title, subtitle, children }: { title: string; subtitle: string; children: ReactNode }) {
  return (
    <div className="grid items-start gap-6 lg:grid-cols-[1.05fr_1fr] lg:gap-10">
      <section className="animate-rise order-2 flex flex-col gap-6 lg:order-1 lg:pt-6" aria-label="About ReconLens">
        <div>
          <p className="chip w-fit text-accent-text">Attack-surface analysis</p>
          <h1 className="mt-4 text-3xl font-bold tracking-tight sm:text-4xl">
            See your domain the way an{' '}
            <span className="bg-gradient-to-r from-accent to-accent-2 bg-clip-text text-transparent">attacker</span> does.
          </h1>
          <p className="mt-3 max-w-prose text-muted">
            ReconLens runs passive reconnaissance against domains you're authorized to test, scores the risk, and writes
            a prioritized report you can act on.
          </p>
        </div>
        <ul className="grid gap-3 sm:grid-cols-2">
          {FEATURES.map((f) => (
            <li key={f.title} className="glass flex items-start gap-3 rounded-2xl p-4">
              <span
                aria-hidden="true"
                className="grid size-9 shrink-0 place-items-center rounded-xl bg-glass-strong text-accent-text"
              >
                <f.icon size={18} />
              </span>
              <div className="min-w-0">
                <p className="font-semibold">{f.title}</p>
                <p className="text-sm text-muted">{f.text}</p>
              </div>
            </li>
          ))}
        </ul>
      </section>

      <section className="glass glass-strong animate-rise order-1 w-full p-6 sm:p-8 lg:order-2">
        <h2 className="text-2xl font-bold">{title}</h2>
        <p className="mt-1 text-sm text-muted">{subtitle}</p>
        <div className="mt-6">{children}</div>
      </section>
    </div>
  )
}
