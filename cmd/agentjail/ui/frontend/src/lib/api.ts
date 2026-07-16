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

/** A captured body, read up to a render cap. Bytes never arrive inline in
 * JSON -- they stream from /api/network/body. See ADR 0092 (D1). */
export interface BodyResult {
  /** Decoded text, empty when binary. Truncated to the cap. */
  text: string
  /** Bytes actually read (stops at the cap, so not the body's full size). */
  bytes: number
  /** The body is not valid UTF-8 text; `text` is not renderable. */
  binary: boolean
  /** More bytes remain on disk than were read. */
  truncated: boolean
}

/** Bodies are unbounded by design; painting one whole into the DOM is the OOM
 * ADR 0092 (D1) chose files to avoid. Read this much and say we stopped. */
export const BODY_RENDER_CAP = 1 << 20

/**
 * Streams one captured body, stopping at BODY_RENDER_CAP. The server decrypts
 * as it streams and reports a sealed body it cannot open as an error rather
 * than emitting ciphertext -- so a rejection here is surfaced, never rendered.
 */
export async function fetchBody(
  path: string,
  signal?: AbortSignal,
): Promise<BodyResult> {
  const res = await fetch(
    `/api/network/body?path=${encodeURIComponent(path)}`,
    { signal },
  )
  if (res.status === 404) {
    return { text: '', bytes: 0, binary: false, truncated: false }
  }
  if (!res.ok) {
    let msg = `${res.status} ${res.statusText}`
    try {
      const j = (await res.json()) as { error?: string }
      if (j.error) msg = j.error
    } catch {
      // non-JSON error body; keep the status line
    }
    throw new Error(msg)
  }
  if (!res.body) {
    const buf = new Uint8Array(await res.arrayBuffer())
    return decodeBody(buf.slice(0, BODY_RENDER_CAP), buf.length)
  }

  const reader = res.body.getReader()
  const chunks: Uint8Array[] = []
  let read = 0
  let truncated = false
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    if (!value) continue
    read += value.length
    chunks.push(value)
    if (read >= BODY_RENDER_CAP) {
      truncated = true
      // Stop pulling: the rest of an unbounded body must not reach the heap.
      await reader.cancel()
      break
    }
  }
  const joined = new Uint8Array(read)
  let off = 0
  for (const c of chunks) {
    joined.set(c, off)
    off += c.length
  }
  const capped = joined.slice(0, BODY_RENDER_CAP)
  const out = decodeBody(capped, read)
  return { ...out, truncated: truncated || out.truncated }
}

/** Decodes bytes as UTF-8, reporting binary rather than corrupting the page.
 * D1 stores raw bytes, so a body is not text until proven so. */
function decodeBody(buf: Uint8Array, total: number): BodyResult {
  const truncated = total > buf.length
  if (buf.byteLength === 0) {
    return { text: '', bytes: total, binary: false, truncated }
  }
  try {
    // A cap can split a multi-byte rune, so a truncated tail is not proof of
    // binary: retry non-fatally before calling it.
    const text = new TextDecoder('utf-8', { fatal: true }).decode(buf)
    if (text.includes('\u0000')) {
      return { text: '', bytes: total, binary: true, truncated }
    }
    return { text, bytes: total, binary: false, truncated }
  } catch {
    if (!truncated) return { text: '', bytes: total, binary: true, truncated }
  }
  const lenient = new TextDecoder('utf-8').decode(buf)
  // U+FFFD only en masse means the bytes were never text.
  const bad = (lenient.match(/�/g) ?? []).length
  if (bad > 4 || lenient.includes('\u0000')) {
    return { text: '', bytes: total, binary: true, truncated }
  }
  return { text: lenient.replace(/�+$/, ''), bytes: total, binary: false, truncated }
}
