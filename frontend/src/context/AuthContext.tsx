import { createContext, useCallback, useEffect, useMemo, useState, type ReactNode } from 'react'
import { useQueryClient } from '@tanstack/react-query'

import { api, setAuthToken, setUnauthorizedHandler } from '../api/client'
import type { TokenResponse, User } from '../types/scan'

const STORAGE_KEY = 'reconlens-session'

interface StoredSession {
  token: string
  user: User
  expiresAt: number
}

export interface AuthContextValue {
  user: User | null
  ready: boolean
  sessionExpired: boolean
  login: (email: string, password: string) => Promise<void>
  register: (email: string, password: string) => Promise<void>
  logout: () => void
}

export const AuthContext = createContext<AuthContextValue | null>(null)

function readSession(): StoredSession | null {
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY)
    if (!raw) return null
    const s = JSON.parse(raw) as StoredSession
    if (!s.token || !s.user || Date.now() >= s.expiresAt) {
      sessionStorage.removeItem(STORAGE_KEY)
      return null
    }
    return s
  } catch {
    return null
  }
}

function writeSession(s: StoredSession | null) {
  try {
    if (s) sessionStorage.setItem(STORAGE_KEY, JSON.stringify(s))
    else sessionStorage.removeItem(STORAGE_KEY)
  } catch {
    /* storage may be unavailable (private mode); the in-memory token still works */
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient()
  const [session, setSession] = useState<StoredSession | null>(() => {
    const s = readSession()
    setAuthToken(s?.token ?? null)
    return s
  })
  const [sessionExpired, setSessionExpired] = useState(false)

  const clear = useCallback(
    (expired: boolean) => {
      setAuthToken(null)
      writeSession(null)
      setSession(null)
      setSessionExpired(expired)
      queryClient.clear()
    },
    [queryClient],
  )

  const accept = useCallback((res: TokenResponse) => {
    const s: StoredSession = { token: res.access_token, user: res.user, expiresAt: Date.now() + res.expires_in * 1000 }
    setAuthToken(s.token)
    writeSession(s)
    setSession(s)
    setSessionExpired(false)
  }, [])

  useEffect(() => {
    setUnauthorizedHandler(() => clear(true))
    return () => setUnauthorizedHandler(null)
  }, [clear])

  // Expire the session client-side at the token's expiry time.
  useEffect(() => {
    if (!session) return
    const ms = session.expiresAt - Date.now()
    const t = window.setTimeout(() => clear(true), Math.max(0, ms))
    return () => window.clearTimeout(t)
  }, [session, clear])

  const value = useMemo<AuthContextValue>(
    () => ({
      user: session?.user ?? null,
      ready: true,
      sessionExpired,
      login: async (email, password) => accept(await api.login(email, password)),
      register: async (email, password) => accept(await api.register(email, password)),
      logout: () => clear(false),
    }),
    [session, sessionExpired, accept, clear],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}
