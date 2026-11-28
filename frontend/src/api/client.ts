import type {
  ApiKey,
  BatchDetail,
  BatchItem,
  GuestTokenResponse,
  Quota,
  ScanCreateResponse,
  ScanDetail,
  ScanPage,
  ShareLink,
  TriageItem,
  TriageStatus,
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
  method?: 'GET' | 'POST' | 'PUT' | 'DELETE'
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

  guest: () => request<GuestTokenResponse>('/api/auth/guest', { method: 'POST', auth: false }),

  me: () => request<User>('/api/auth/me'),

  createScan: (target: string) =>
    request<ScanCreateResponse>('/api/scans', { method: 'POST', body: { target, confirmed_authorized: true } }),

  listScans: (page = 1, pageSize = 20) => request<ScanPage>(`/api/scans?page=${page}&page_size=${pageSize}`),

  getScan: (id: string) => request<ScanDetail>(`/api/scans/${encodeURIComponent(id)}`),

  exportScan: (id: string) => request<unknown>(`/api/scans/${encodeURIComponent(id)}/export`),

  quota: () => request<Quota>('/api/scans/quota'),

  previousScan: (id: string) =>
    request<{ previous: ScanDetail | null }>(`/api/scans/${encodeURIComponent(id)}/previous`),

  getShare: (id: string) => request<{ share: ShareLink | null }>(`/api/scans/${encodeURIComponent(id)}/share`),

  createShare: (id: string) =>
    request<{ share: ShareLink }>(`/api/scans/${encodeURIComponent(id)}/share`, { method: 'POST' }),

  deleteShare: (id: string) => request<void>(`/api/scans/${encodeURIComponent(id)}/share`, { method: 'DELETE' }),

  createBatch: (targets: string[]) =>
    request<{ batch_id: string; items: BatchItem[] }>('/api/scans/batch', {
      method: 'POST',
      body: { targets, confirmed_authorized: true },
    }),

  getBatch: (id: string) => request<BatchDetail>(`/api/scans/batch/${encodeURIComponent(id)}`),

  getTriage: (scanId: string) =>
    request<{ items: Record<string, TriageItem> }>(`/api/scans/${encodeURIComponent(scanId)}/triage`),

  setTriage: (scanId: string, findingId: string, status: TriageStatus, note: string) =>
    request<{ finding_id: string; item: TriageItem | null }>(
      `/api/scans/${encodeURIComponent(scanId)}/triage/${encodeURIComponent(findingId)}`,
      { method: 'PUT', body: { status, note } },
    ),

  listKeys: () => request<{ items: ApiKey[]; max: number }>('/api/keys'),

  createKey: (name: string) => request<ApiKey>('/api/keys', { method: 'POST', body: { name } }),

  deleteKey: (id: string) => request<void>(`/api/keys/${encodeURIComponent(id)}`, { method: 'DELETE' }),

  getShared: (token: string) =>
    request<{ scan: ScanDetail; expires_at: string }>(`/api/shared/${encodeURIComponent(token)}`, { auth: false }),
}
