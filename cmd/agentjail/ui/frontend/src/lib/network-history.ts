import type { RequestLog } from '../types'
import type { RequestsListResponse } from './api'

export const networkPageSize = 200

export function mergeLiveRequest(old: RequestsListResponse | undefined, incoming: RequestLog, session: string | null): RequestsListResponse | undefined {
  if (!old || (session && incoming.session_id !== session)) return old
  if (old.requests.some((row) => row.id === incoming.id)) return old
  const requests = [...old.requests, incoming].sort((a, b) => b.id - a.id)
  return { ...old, requests: requests.slice(0, networkPageSize), count: Math.min(requests.length, networkPageSize), has_more: old.has_more || requests.length > networkPageSize }
}

export function requestId(value: string | null): number | null {
  if (!value || !/^[1-9]\d*$/.test(value)) return null
  const id = Number(value)
  return Number.isSafeInteger(id) ? id : null
}
