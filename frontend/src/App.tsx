import { lazy, Suspense, useEffect, useState, type ReactNode } from 'react'
import { Navigate, Route, Routes, useLocation } from 'react-router'

import { Footer } from './components/layout/Footer'
import { Navbar } from './components/layout/Navbar'
import { WakeUpNotice } from './components/scan/WakeUpNotice'
import { Alert } from './components/ui/Alert'
import { Spinner } from './components/ui/Spinner'
import { useAuth } from './hooks/useAuth'
import Home from './pages/Home'
import Login from './pages/Login'
import NotFound from './pages/NotFound'
import Register from './pages/Register'
import Terms from './pages/Terms'

const ScanResult = lazy(() => import('./pages/ScanResult'))
const History = lazy(() => import('./pages/History'))
const SharedScan = lazy(() => import('./pages/SharedScan'))

function RequireAuth({ children }: { children: ReactNode }) {
  const { user } = useAuth()
  const location = useLocation()
  if (!user) return <Navigate to="/login" replace state={{ from: location.pathname }} />
  return <>{children}</>
}

/** Signed-in users pass through; visitors get a guest session (a few free scans). */
function RequireSession({ children }: { children: ReactNode }) {
  const { hasSession, ensureGuest } = useAuth()
  const [failed, setFailed] = useState(false)

  useEffect(() => {
    if (hasSession) return
    let cancelled = false
    // The free server may be asleep, so keep trying for about a minute.
    const attempt = async (n: number): Promise<void> => {
      try {
        await ensureGuest()
      } catch {
        if (cancelled) return
        if (n < 8) {
          await new Promise((r) => window.setTimeout(r, 6000))
          if (!cancelled) return attempt(n + 1)
        } else setFailed(true)
      }
    }
    void attempt(0)
    return () => {
      cancelled = true
    }
  }, [hasSession, ensureGuest])

  if (hasSession) return <>{children}</>
  return (
    <div className="mx-auto flex max-w-xl flex-col gap-4 py-10">
      <WakeUpNotice />
      {failed ? (
        <Alert tone="danger" title="ReconLens couldn't start a session">
          Refresh the page to try again, or sign in.
        </Alert>
      ) : (
        <div className="grid place-items-center py-10">
          <Spinner label="Getting ready…" />
        </div>
      )}
    </div>
  )
}

function GuestOnly({ children }: { children: ReactNode }) {
  const { user } = useAuth()
  if (user) return <Navigate to="/" replace />
  return <>{children}</>
}

export default function App() {
  return (
    <div className="flex min-h-dvh flex-col">
      <a
        href="#main"
        className="btn btn-primary sr-only focus:not-sr-only focus:fixed focus:top-3 focus:left-3 focus:z-50"
      >
        Skip to content
      </a>
      <Navbar />
      <main id="main" className="mx-auto w-full max-w-6xl flex-1 px-4 py-8 sm:px-6 sm:py-10">
        <Suspense
          fallback={
            <div className="grid place-items-center py-24">
              <Spinner label="Loading…" />
            </div>
          }
        >
          <Routes>
            <Route
              path="/"
              element={
                <RequireSession>
                  <Home />
                </RequireSession>
              }
            />
            <Route
              path="/scans/:id"
              element={
                <RequireSession>
                  <ScanResult />
                </RequireSession>
              }
            />
            <Route
              path="/history"
              element={
                <RequireAuth>
                  <History />
                </RequireAuth>
              }
            />
            <Route
              path="/login"
              element={
                <GuestOnly>
                  <Login />
                </GuestOnly>
              }
            />
            <Route
              path="/register"
              element={
                <GuestOnly>
                  <Register />
                </GuestOnly>
              }
            />
            <Route path="/shared/:token" element={<SharedScan />} />
            <Route path="/terms" element={<Terms />} />
            <Route path="*" element={<NotFound />} />
          </Routes>
        </Suspense>
      </main>
      <Footer />
    </div>
  )
}
