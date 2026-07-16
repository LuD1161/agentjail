import type { RequestLog, SessionInfo, StateSnapshot } from '@/types'

async function getJSON<T>(url: string): Promise<T> {
  const res = await fetch(url)
  if (!res.ok) {
    throw new Error(`${url} -> ${res.status} ${res.statusText}`)
  }
  return (await res.json()) as T
}

export interface RequestsListParams {
  session?: string | null
  limit?: number
  offset?: number
  host?: string
  method?: string
  status?: string
  policy?: string
}

export interface RequestsListResponse {
  requests: RequestLog[]
  count?: number
  total?: number
  unavailable?: boolean
}

export function fetchRequests(
  params: RequestsListParams,
): Promise<RequestsListResponse> {
  const q = new URLSearchParams()
  if (params.session) q.set('session', params.session)
  q.set('limit', String(params.limit ?? 50))
  q.set('offset', String(params.offset ?? 0))
  if (params.host) q.set('host', params.host)
  if (params.method) q.set('method', params.method)
  if (params.status) q.set('status', params.status)
  if (params.policy) q.set('policy', params.policy)
  return getJSON(`/api/requests?${q.toString()}`)
}

export function fetchRequestDetail(id: number | string): Promise<RequestLog> {
  return getJSON(`/api/requests/${id}`)
}

export interface NetworkSessionsResponse {
  sessions: SessionInfo[]
  count?: number
  unavailable?: boolean
}

export function fetchNetworkSessions(): Promise<NetworkSessionsResponse> {
  return getJSON('/api/network/sessions')
}

export function fetchState(): Promise<StateSnapshot> {
  return getJSON('/api/state')
}
