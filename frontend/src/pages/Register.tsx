import { useState, type FormEvent } from 'react'
import { Link, useNavigate } from 'react-router'
import { UserPlus } from 'lucide-react'

import { ApiError } from '../api/client'
import { AuthShell } from '../components/layout/AuthShell'
import { WakeUpNotice } from '../components/scan/WakeUpNotice'
import { Alert } from '../components/ui/Alert'
import { Button } from '../components/ui/Button'
import { Field } from '../components/ui/Field'
import { useAuth } from '../hooks/useAuth'

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

export default function Register() {
  const { register } = useAuth()
  const navigate = useNavigate()

  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [touched, setTouched] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const emailError = touched && !EMAIL_RE.test(email.trim()) ? 'Enter a valid email address.' : null
  const passwordError =
    touched && password.length < 10 ? 'Use at least 10 characters.' : touched && password.length > 128 ? 'Use at most 128 characters.' : null
  const confirmError = touched && confirm !== password ? 'Passwords do not match.' : null

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault()
    setTouched(true)
    setError(null)
    if (!EMAIL_RE.test(email.trim()) || password.length < 10 || password.length > 128 || confirm !== password) return
    setBusy(true)
    try {
      await register(email.trim(), password)
      navigate('/', { replace: true })
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Registration failed. Please try again.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <AuthShell title="Create your account" subtitle="Free for authorized testing. Scans are limited per day.">
      <div className="flex flex-col gap-4">
        <WakeUpNotice />
        <form onSubmit={onSubmit} noValidate className="flex flex-col gap-4">
          <Field
            label="Email"
            type="email"
            autoComplete="email"
            inputMode="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            error={emailError}
            required
          />
          <Field
            label="Password"
            type="password"
            autoComplete="new-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            hint="At least 10 characters. A passphrase works well."
            error={passwordError}
            required
          />
          <Field
            label="Confirm password"
            type="password"
            autoComplete="new-password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            error={confirmError}
            required
          />
          {error && <Alert tone="danger">{error}</Alert>}
          <Button type="submit" variant="primary" loading={busy} icon={<UserPlus size={18} aria-hidden="true" />} className="w-full">
            Create account
          </Button>
        </form>
        <p className="text-center text-sm text-muted">
          Already have an account?{' '}
          <Link to="/login" className="font-semibold text-accent-text underline-offset-4 hover:underline">
            Sign in
          </Link>
        </p>
      </div>
    </AuthShell>
  )
}
