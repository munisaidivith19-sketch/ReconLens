import type {
  ScanCreateResponse,
  ScanDetail,
  ScanPage,
  TokenResponse,
  User,
} from '../types/scan'

const API_URL = (import.meta.env.VITE_API_URL ?? 'http://localhost:8000').replace(/\/+$/, '')

export class ApiError extends Error {
  status: number
  code: string
  fields: { field: string; message: string }[]

  constructor(status: number, code: string, message: string, fields: { field: string; message: string }[] = []) {
    super(message)
    this.status = status
    this.code = code
    this.fields = fields
  }
}

let authToken: string | null = null
let onUnauthorized: (() => void) | null = null

export function setAuthToken(token: string | null) {
  authToken = token
}

export function setUnauthorizedHandler(handler: (() => void) | null) {
  onUnauthorized = handler
}

interface RequestOptions {
  method?: 'GET' | 'POST'
  body?: unknown
  signal?: AbortSignal
  auth?: boolean
}

async function request<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json' }
  if (opts.body !== undefined) headers['Content-Type'] = 'application/json'
  if (opts.auth !== false && authToken) headers.Authorization = `Bearer ${authToken}`

  let res: Response
  try {
    res = await fetch(`${API_URL}${path}`, {
      method: opts.method ?? 'GET',
      headers,
      body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
      signal: opts.signal,
      credentials: 'omit',
    })
  } catch (err) {
    if (err instanceof DOMException && err.name === 'AbortError') throw err
    throw new ApiError(0, 'network_error', 'Could not reach the ReconLens server. Check your connection and try again.')
  }

  if (res.status === 204) return undefined as T
  let data: unknown = null
  try {
    data = await res.json()
  } catch {
    data = null
  }

  if (!res.ok) {
    const detail = (data as { detail?: unknown } | null)?.detail
    let code = 'error'
    let message = `Request failed (${res.status}).`
    let fields: { field: string; message: string }[] = []
    if (detail && typeof detail === 'object') {
      const d = detail as { code?: string; message?: string; errors?: { field: string; message: string }[] }
      code = d.code ?? code
      message = d.message ?? message
      fields = d.errors ?? []
    } else if (typeof detail === 'string') {
      message = detail
    }
    if (res.status === 401 && opts.auth !== false && authToken) onUnauthorized?.()
    throw new ApiError(res.status, code, message, fields)
  }
  return data as T
}

export const api = {
  baseUrl: API_URL,

  health: (signal?: AbortSignal) =>
    request<{ status: string; database: string }>('/api/health', { auth: false, signal }),

  register: (email: string, password: string) =>
    request<TokenResponse>('/api/auth/register', { method: 'POST', body: { email, password }, auth: false }),

  login: (email: string, password: string) =>
    request<TokenResponse>('/api/auth/login', { method: 'POST', body: { email, password }, auth: false }),

  me: () => request<User>('/api/auth/me'),

  createScan: (target: string) =>
    request<ScanCreateResponse>('/api/scans', { method: 'POST', body: { target, confirmed_authorized: true } }),

  listScans: (page = 1, pageSize = 20) => request<ScanPage>(`/api/scans?page=${page}&page_size=${pageSize}`),

  getScan: (id: string) => request<ScanDetail>(`/api/scans/${encodeURIComponent(id)}`),

  exportScan: (id: string) => request<unknown>(`/api/scans/${encodeURIComponent(id)}/export`),

  quota: () => request<{ limit: number; used: number; remaining: number }>('/api/scans/quota'),
}
