import { Card } from '../components/ui/Card'

export default function Home() {
  return (
    <Card className="animate-rise">
      <h1 className="text-2xl font-bold">New scan</h1>
      <p className="mt-2 text-muted">The scan form arrives with the scan engine.</p>
    </Card>
  )
}
