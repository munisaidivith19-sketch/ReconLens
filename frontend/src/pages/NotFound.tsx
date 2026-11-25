import { Link } from 'react-router'
import { Compass } from 'lucide-react'

import { Card } from '../components/ui/Card'

export default function NotFound() {
  return (
    <Card className="animate-rise mx-auto max-w-lg text-center">
      <Compass aria-hidden="true" size={40} className="mx-auto text-accent-text" />
      <h1 className="mt-4 text-2xl font-bold">Page not found</h1>
      <p className="mt-2 text-muted">That page doesn't exist, or the scan has expired (scans are kept for 30 days).</p>
      <Link to="/" className="btn btn-primary mt-6">
        Back to ReconLens
      </Link>
    </Card>
  )
}
