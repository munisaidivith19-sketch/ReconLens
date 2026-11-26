import { createContext, useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { useQueryClient } from '@tanstack/react-query'

import { api, setAuthToken, setUnauthorizedHandler } from '../api/client'
import type { TokenResponse, User } from '../types/scan'

const STORAGE_KEY = 'reconlens-session'
// Guest tokens live in localStorage so a visitor keeps access to their free scans across visits.
const GUEST_KEY = 'reconlens-guest'

interface StoredSession {
  token: string
  user: User
  expiresAt: number
}

interface GuestSession {
  token: string
  expiresAt: number
}

export interface AuthContextValue {
  /** The signed-in account, or null for visitors (including guests). */
  user: User | null
  /** True when scans run on a guest token (not signed in). */
  isGuest: boolean
  /** True once there is a token to call the scan API with (account or guest). */
  hasSession: boolean
  ready: boolean
  sessionExpired: boolean
  /** Get a guest token if there is no session yet. Safe to call repeatedly. */
  ensureGuest: () => Promise<void>
  login: (email: string, password: string) => Promise<void>
  register: (email: string, password: string) => Promise<void>
  logout: () => void
}

export const AuthContext = createContext<AuthContextValue | null>(null)

function readJson<T extends { token: string; expiresAt: number }>(storage: Storage, key: string): T | null {
  try {
    const raw = storage.getItem(key)
    if (!raw) return null
    const s = JSON.parse(raw) as T
    if (!s.token || Date.now() >= s.expiresAt) {
      storage.removeItem(key)
      return null
    }
    return s
  } catch {
    return null
  }
}

function writeJson(storage: Storage, key: string, value: unknown) {
  try {
    if (value) storage.setItem(key, JSON.stringify(value))
    else storage.removeItem(key)
  } catch {
    /* storage may be unavailable (private mode); the in-memory token still works */
  }
}

function readSession(): StoredSession | null {
  const s = readJson<StoredSession>(sessionStorage, STORAGE_KEY)
  return s?.user ? s : null
}

function readGuest(): GuestSession | null {
  try {
    return readJson<GuestSession>(localStorage, GUEST_KEY)
  } catch {
    return null
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient()
  const [session, setSession] = useState<StoredSession | null>(() => readSession())
  const [guest, setGuest] = useState<GuestSession | null>(() => readGuest())
  const [sessionExpired, setSessionExpired] = useState(false)
  const guestRequest = useRef<Promise<void> | null>(null)

  // The account token always wins over the guest token.
  const activeToken = session?.token ?? guest?.token ?? null
  setAuthToken(activeToken)

  const clear = useCallback(
    (expired: boolean) => {
      writeJson(sessionStorage, STORAGE_KEY, null)
      setSession(null)
      setSessionExpired(expired)
      queryClient.clear()
    },
    [queryClient],
  )

  const clearGuest = useCallback(() => {
    try {
      writeJson(localStorage, GUEST_KEY, null)
    } catch {
      /* ignore */
    }
    setGuest(null)
    queryClient.clear()
  }, [queryClient])

  const accept = useCallback(
    (res: TokenResponse) => {
      const s: StoredSession = { token: res.access_token, user: res.user, expiresAt: Date.now() + res.expires_in * 1000 }
      setAuthToken(s.token)
      writeJson(sessionStorage, STORAGE_KEY, s)
      setSession(s)
      setSessionExpired(false)
      queryClient.clear() // drop guest quota and scan lists
    },
    [queryClient],
  )

  const ensureGuest = useCallback(async () => {
    if (session || guest) return
    if (!guestRequest.current) {
      guestRequest.current = api
        .guest()
        .then((res) => {
          const g: GuestSession = { token: res.access_token, expiresAt: Date.now() + res.expires_in * 1000 }
          try {
            writeJson(localStorage, GUEST_KEY, g)
          } catch {
            /* ignore */
          }
          setAuthToken(g.token)
          setGuest(g)
        })
        .finally(() => {
          guestRequest.current = null
        })
    }
    return guestRequest.current
  }, [session, guest])

  useEffect(() => {
    setUnauthorizedHandler(() => (session ? clear(true) : clearGuest()))
    return () => setUnauthorizedHandler(null)
  }, [session, clear, clearGuest])

  // Expire tokens client-side at their expiry time.
  useEffect(() => {
    if (!session) return
    const t = window.setTimeout(() => clear(true), Math.max(0, session.expiresAt - Date.now()))
    return () => window.clearTimeout(t)
  }, [session, clear])

  useEffect(() => {
    if (!guest) return
    const t = window.setTimeout(clearGuest, Math.max(0, guest.expiresAt - Date.now()))
    return () => window.clearTimeout(t)
  }, [guest, clearGuest])

  const value = useMemo<AuthContextValue>(
    () => ({
      user: session?.user ?? null,
      isGuest: !session && Boolean(guest),
      hasSession: Boolean(session || guest),
      ready: true,
      sessionExpired,
      ensureGuest,
      login: async (email, password) => accept(await api.login(email, password)),
      register: async (email, password) => accept(await api.register(email, password)),
      logout: () => clear(false),
    }),
    [session, guest, sessionExpired, ensureGuest, accept, clear],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}
