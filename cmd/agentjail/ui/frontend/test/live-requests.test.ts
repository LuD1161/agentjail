import { expect, test } from 'bun:test'
import { LIVE_REQUEST_LIMIT, mergeLiveRequests } from '../src/lib/live-requests'
import type { RequestLog } from '../src/types'

function request(id: number): RequestLog {
  return { id, ts: '2026-09-23T00:00:00Z', host: 'example.test', method: 'GET', path: '/', url: 'https://example.test/' }
}

test('retains the newest bounded window across long-lived burst traffic', () => {
  let rows: RequestLog[] = []
  for (let start = 1; start <= 10000; start += 100) {
    rows = mergeLiveRequests(rows, Array.from({ length: 100 }, (_, n) => request(start + n)))
    expect(rows.length).toBeLessThanOrEqual(LIVE_REQUEST_LIMIT)
  }
  expect(rows.map(row => row.id)).toEqual(Array.from({ length: LIVE_REQUEST_LIMIT }, (_, n) => 10000 - n))
})

test('deduplicates replay and preserves newest IDs for out-of-order input', () => {
  const rows = mergeLiveRequests([request(3), request(2)], [request(1), { ...request(3), method: 'POST' }])
  expect(rows.map(row => row.id)).toEqual([3, 2, 1])
  expect(rows[0].method).toBe('POST')
})
