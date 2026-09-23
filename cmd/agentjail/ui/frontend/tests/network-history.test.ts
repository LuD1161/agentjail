import { expect, test } from 'bun:test'
import { mergeLiveRequest, networkPageSize, requestId } from '../src/lib/network-history'
import type { RequestLog } from '../src/types'
function row(id: number, session = 'a'): RequestLog {
 return { id, session_id: session, ts: '2026-09-22T00:00:00Z', host: 'example.com', method: 'GET', path: '/', url: 'https://example.com/' }
}
test('long live stream stays bounded and preserves server totals', () => {
 let page = { requests: [row(1)], count: 1, total: 12345, has_more: false }
 for (let id = 2; id <= 2000; id++) page = mergeLiveRequest(page, row(id), 'a') as typeof page
 expect(page.requests).toHaveLength(networkPageSize)
 expect(page.requests[0].id).toBe(2000)
 expect(page.requests.at(-1)?.id).toBe(1801)
 expect(page.count).toBe(networkPageSize)
 expect(page.total).toBe(12345)
 expect(page.has_more).toBe(true)
})
test('duplicates and other sessions leave state intact; events before snapshot are safe', () => {
 const page = { requests: [row(3), row(1)], count: 2, total: 2, has_more: false }
 expect(mergeLiveRequest(page, row(3), 'a')).toBe(page)
 expect(mergeLiveRequest(page, row(4, 'b'), 'a')).toBe(page)
 expect(mergeLiveRequest(undefined, row(4), null)).toBeUndefined()
 expect(mergeLiveRequest(page, row(2), null)?.requests.map(r => r.id)).toEqual([3, 2, 1])
})
test('invalid and imprecise detail ids are rejected', () => {
 for (const id of [null, '', '0', '-1', '1.5', 'NaN', 'Infinity', '9007199254740993']) expect(requestId(id)).toBeNull()
 expect(requestId('12345')).toBe(12345)
})
