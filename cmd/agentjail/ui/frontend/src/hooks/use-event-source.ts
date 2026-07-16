import * as React from 'react'

/**
 * Subscribes to a Server-Sent Events endpoint and invokes `onMessage` for
 * every event parsed as JSON. Reconnects automatically on error (the
 * browser's EventSource already retries; this just re-creates the object
 * if the URL changes).
 */
export function useEventSource<T>(
  url: string | null,
  onMessage: (data: T) => void,
  options?: { enabled?: boolean; onOpen?: () => void; onError?: () => void },
) {
  const onMessageRef = React.useRef(onMessage)
  onMessageRef.current = onMessage
  const enabled = options?.enabled ?? true

  React.useEffect(() => {
    if (!url || !enabled) return
    const source = new EventSource(url)

    source.onopen = () => options?.onOpen?.()
    source.onerror = () => options?.onError?.()
    source.onmessage = (event) => {
      if (!event.data || event.data === 'ok') return
      try {
        const parsed = JSON.parse(event.data) as T
        onMessageRef.current(parsed)
      } catch {
        // ignore malformed/comment frames
      }
    }

    return () => {
      source.close()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [url, enabled])
}
