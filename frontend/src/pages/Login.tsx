import { useState, type FormEvent } from 'react'
import { Link, useLocation, useNavigate } from 'react-router'
import { LogIn } from 'lucide-react'

import { ApiError } from '../api/client'
import { AuthShell } from '../components/layout/AuthShell'
import { WakeUpNotice } from '../components/scan/WakeUpNotice'
import { Alert } from '../components/ui/Alert'
import { Button } from '../components/ui/Button'
import { Field } from '../components/ui/Field'
import { useAuth } from '../hooks/useAuth'

export default function Login() {
  const { login, sessionExpired } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const from = (location.state as { from?: string } | null)?.from ?? '/'

  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault()
    setError(null)
    if (!email.trim() || !password) {
      setError('Enter your email and password.')
      return
    }
    setBusy(true)
    try {
      await login(email.trim(), password)
      navigate(from.startsWith('/') && !from.startsWith('//') ? from : '/', { replace: true })
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Sign in failed. Please try again.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <AuthShell title="Welcome back" subtitle="Sign in to start a scan or review past reports.">
      <div className="flex flex-col gap-4">
        <WakeUpNotice />
        {sessionExpired && (
          <Alert tone="warning" title="Your session expired">
            Sign in again to continue.
          </Alert>
        )}
        <form onSubmit={onSubmit} noValidate className="flex flex-col gap-4">
          <Field
            label="Email"
            type="email"
            autoComplete="email"
            inputMode="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />
          <Field
            label="Password"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
          {error && <Alert tone="danger">{error}</Alert>}
          <Button type="submit" variant="primary" loading={busy} icon={<LogIn size={18} aria-hidden="true" />} className="w-full">
            Sign in
          </Button>
        </form>
        <p className="text-center text-sm text-muted">
          New to ReconLens?{' '}
          <Link to="/register" className="font-semibold text-accent-text underline-offset-4 hover:underline">
            Create an account
          </Link>
        </p>
      </div>
    </AuthShell>
  )
}
