import type { RequestLog } from '../types'

export const LIVE_REQUEST_LIMIT = 500

export function mergeLiveRequests(
  current: readonly RequestLog[],
  incoming: Iterable<RequestLog>,
): RequestLog[] {
  const byId = new Map(current.map((request) => [request.id, request]))
  for (const request of incoming) byId.set(request.id, request)
  return [...byId.values()]
    .sort((left, right) => right.id - left.id)
    .slice(0, LIVE_REQUEST_LIMIT)
}
