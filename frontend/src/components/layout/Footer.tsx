import { Link } from 'react-router'
import { ShieldCheck } from 'lucide-react'

export function Footer() {
  return (
    <footer className="no-print mt-auto px-3 pb-6 sm:px-6">
      <div className="glass mx-auto flex max-w-6xl flex-col gap-3 rounded-3xl px-5 py-4 text-sm text-muted sm:flex-row sm:items-center sm:justify-between">
        <p className="flex items-center gap-2">
          <ShieldCheck size={16} aria-hidden="true" className="shrink-0 text-ok" />
          Passive checks only. Scan only domains you own or are authorized to test.
        </p>
        <div className="flex flex-wrap gap-x-4 gap-y-1">
          <Link to="/terms" className="underline-offset-4 hover:text-fg hover:underline">
            Responsible use
          </Link>
          <a
            href="https://github.com/munisaidivith19-sketch/ReconLens"
            target="_blank"
            rel="noopener noreferrer"
            className="underline-offset-4 hover:text-fg hover:underline"
          >
            Source
          </a>
        </div>
      </div>
    </footer>
  )
}
