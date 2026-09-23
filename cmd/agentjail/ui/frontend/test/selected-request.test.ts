import { expect, spyOn, test } from 'bun:test'
import { QueryClient, QueryObserver } from '@tanstack/react-query'
import { selectedRequestQuery } from '../src/lib/selected-request'
import { LIVE_REQUEST_LIMIT, mergeLiveRequests } from '../src/lib/live-requests'
import type { RequestLog } from '../src/types'

function request(id: number): RequestLog {
  return { id, ts: '2026-09-23T00:00:00Z', host: 'example.test', method: 'GET', path: '/', url: 'https://example.test/' }
}

test('selected detail survives eviction and historical links resolve without growing the live window', async () => {
  const fetched: string[] = []
  const fetchSpy = spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    const url = String(input)
    fetched.push(url)
    return Response.json(request(Number(url.split('/').pop())))
  })
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  const observer = new QueryObserver(client, selectedRequestQuery(1, request(1)))
  const unsubscribe = observer.subscribe(() => {})
  try {
    expect(observer.getCurrentResult().data?.id).toBe(1)
    await observer.refetch()
    const live = mergeLiveRequests([request(1)], Array.from({ length: 600 }, (_, n) => request(n + 2)))
    expect(live).toHaveLength(LIVE_REQUEST_LIMIT)
    expect(live.find(row => row.id === 1)).toBeUndefined()
    observer.setOptions(selectedRequestQuery(1, live.find(row => row.id === 1)))
    expect(observer.getCurrentResult().data?.id).toBe(1)

    const released = new Promise<void>((resolve) => {
      const stop = client.getQueryCache().subscribe(event => {
        if (event.type === 'removed' && event.query.queryKey[1] === 1) {
          stop()
          resolve()
        }
      })
    })
    observer.setOptions(selectedRequestQuery(2))
    await observer.refetch()
    await released
    expect(observer.getCurrentResult().data?.id).toBe(2)
    expect(fetched).toContain('/api/requests/2')
    expect(client.getQueryCache().getAll()).toHaveLength(1)
    expect(live).toHaveLength(LIVE_REQUEST_LIMIT)
    expect(live.find(row => row.id === 2)).toBeUndefined()

    const closed = new Promise<void>((resolve) => {
      const stop = client.getQueryCache().subscribe(event => {
        if (event.type === 'removed') {
          stop()
          resolve()
        }
      })
    })
    unsubscribe()
    await closed
    expect(client.getQueryCache().getAll()).toHaveLength(0)
  } finally {
    unsubscribe()
    client.clear()
    fetchSpy.mockRestore()
  }
})
