import { LIVE_REQUEST_LIMIT, mergeLiveRequests } from './live-requests'
import type { RequestLog } from '../types'
import type { RequestsListResponse } from './api'

export const networkPageSize = LIVE_REQUEST_LIMIT

export function mergeLiveRequestBatch(old: RequestsListResponse | undefined, incoming: Iterable<RequestLog>, session: string | null): RequestsListResponse | undefined {
  if (!old) return old
  const existing = new Set(old.requests.map((row) => row.id))
  const additions = [...incoming].filter((row) => (!session || row.session_id === session) && !existing.has(row.id))
  if (!additions.length) return old
  const requests = mergeLiveRequests(old.requests, additions)
  return { ...old, requests, count: requests.length, has_more: old.has_more || old.requests.length + additions.length > networkPageSize }
}

export function mergeLiveRequest(old: RequestsListResponse | undefined, incoming: RequestLog, session: string | null): RequestsListResponse | undefined {
  return mergeLiveRequestBatch(old, [incoming], session)
}

export function requestId(value: string | null): number | null {
  if (!value || !/^[1-9]\d*$/.test(value)) return null
  const id = Number(value)
  return Number.isSafeInteger(id) ? id : null
}
