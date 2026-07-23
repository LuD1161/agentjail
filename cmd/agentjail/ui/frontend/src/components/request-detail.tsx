import * as React from 'react'
import { Highlight, themes, type Token } from 'prism-react-renderer'
import { Braces, ChevronDown, ChevronUp, Search, X } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  ResizableHandle,
  ResizablePanel,
  ResizablePanelGroup,
} from '@/components/ui/resizable'
import { fetchBody, BODY_RENDER_CAP, type BodyResult } from '@/lib/api'
import { formatBytes } from '@/lib/format'
import type { RequestLog } from '@/types'

function statusColor(code?: number) {
  if (!code) return 'text-[#9ca3af]'
  if (code >= 500) return 'text-[#ff7b72]'
  if (code >= 400) return 'text-[#e3b341]'
  if (code >= 300) return 'text-[#58a6ff]'
  return 'text-[#56d364]'
}

/** Body content classification used to pick a rendering/highlighting strategy. */
type BodyLanguage = 'json' | 'sse' | 'text'

/** Result of formatting a body string for display given the pretty-print toggle. */
interface FormattedBody {
  text: string
  language: BodyLanguage
}

function formatBody(body: string, pretty: boolean): FormattedBody {
  try {
    const parsed = JSON.parse(body)
    return {
      text: pretty ? JSON.stringify(parsed, null, 2) : body,
      language: 'json',
    }
  } catch {
    // not JSON
  }
  if (/^\s*(event|data|id|retry):/m.test(body)) {
    return { text: body, language: 'sse' }
  }
  return { text: body, language: 'text' }
}

/**
 * Splits `text` on case-insensitive occurrences of `query`, returning React
 * nodes with matches wrapped in <mark>. Each match consumes the next index
 * from `counter` (shared across the whole detail panel) so that "N of M"
 * navigation and prev/next jumping can address matches across both the
 * request and response panes in document order.
 */
function highlightText(
  text: string,
  query: string,
  counter: { current: number },
  activeIndex: number,
): React.ReactNode {
  if (!query) return text
  const lower = text.toLowerCase()
  const needle = query.toLowerCase()
  if (!needle) return text

  const nodes: React.ReactNode[] = []
  let cursor = 0
  let pos = lower.indexOf(needle, cursor)
  if (pos === -1) return text

  let key = 0
  while (pos !== -1) {
    if (pos > cursor) nodes.push(text.slice(cursor, pos))
    const matchIndex = counter.current
    counter.current += 1
    const isActive = matchIndex === activeIndex
    nodes.push(
      <mark
        key={`m-${key++}`}
        data-match-index={matchIndex}
        className={
          isActive
            ? 'rounded-[2px] bg-orange-500/50 text-inherit'
            : 'rounded-[2px] bg-yellow-500/30 text-inherit'
        }
      >
        {text.slice(pos, pos + needle.length)}
      </mark>,
    )
    cursor = pos + needle.length
    pos = lower.indexOf(needle, cursor)
  }
  if (cursor < text.length) nodes.push(text.slice(cursor))
  return nodes
}

function HeadersBlock({
  headers,
  search,
  counter,
  activeIndex,
}: {
  headers?: Record<string, string> | null
  search: string
  counter: { current: number }
  activeIndex: number
}) {
  if (!headers || Object.keys(headers).length === 0) {
    return <div className="text-[#6b7280]">(no headers)</div>
  }
  return (
    <div className="space-y-0.5">
      {Object.entries(headers).map(([k, v]) => (
        <div key={k} className="flex gap-2 break-all">
          <span className="text-[#58a6ff]">
            {highlightText(k, search, counter, activeIndex)}:
          </span>
          <span className="text-[#c9d1d9]">
            {highlightText(v, search, counter, activeIndex)}
          </span>
        </div>
      ))}
    </div>
  )
}

const SSE_PREFIX_COLOR: Record<string, string> = {
  event: 'text-[#58a6ff]',
  data: 'text-[#56d364]',
  id: 'text-[#e3b341]',
  retry: 'text-[#ff7b72]',
}

function SseBody({
  text,
  search,
  counter,
  activeIndex,
}: {
  text: string
  search: string
  counter: { current: number }
  activeIndex: number
}) {
  const lines = text.split('\n')
  return (
    <pre className="whitespace-pre-wrap break-all text-[#c9d1d9]">
      {lines.map((line, i) => {
        const match = /^(\s*)(event|data|id|retry)(:\s?)(.*)$/.exec(line)
        if (!match) {
          return (
            <React.Fragment key={i}>
              {highlightText(line, search, counter, activeIndex)}
              {i < lines.length - 1 ? '\n' : ''}
            </React.Fragment>
          )
        }
        const [, lead, prefix, sep, rest] = match
        return (
          <React.Fragment key={i}>
            {lead}
            <span className={SSE_PREFIX_COLOR[prefix]}>{prefix}</span>
            {sep}
            {highlightText(rest, search, counter, activeIndex)}
            {i < lines.length - 1 ? '\n' : ''}
          </React.Fragment>
        )
      })}
    </pre>
  )
}

function JsonBody({
  text,
  search,
  counter,
  activeIndex,
}: {
  text: string
  search: string
  counter: { current: number }
  activeIndex: number
}) {
  return (
    <Highlight theme={themes.vsDark} code={text} language="json">
      {({ className, style, tokens, getLineProps, getTokenProps }) => (
        <pre
          className={`${className} whitespace-pre-wrap break-all !bg-transparent`}
          style={{ ...style, backgroundColor: 'transparent', background: 'transparent' }}
        >
          {tokens.map((line: Token[], i: number) => {
            const lineProps = getLineProps({ line })
            return (
              <div key={i} {...lineProps}>
                {line.map((token: Token, key: number) => {
                  const tokenProps = getTokenProps({ token })
                  if (!search) return <span key={key} {...tokenProps} />
                  return (
                    <span
                      key={key}
                      className={tokenProps.className}
                      style={tokenProps.style}
                    >
                      {highlightText(
                        token.content,
                        search,
                        counter,
                        activeIndex,
                      )}
                    </span>
                  )
                })}
              </div>
            )
          })}
        </pre>
      )}
    </Highlight>
  )
}

/** What a body fetch is currently doing. Bodies arrive over the network, so
 * the panel has states an inline string never had. */
type BodyState =
  | { kind: 'empty' }
  | { kind: 'loading' }
  | { kind: 'error'; message: string }
  | { kind: 'ready'; result: BodyResult }

/**
 * Fetches one body from /api/network/body. Bodies are unbounded and may be
 * binary, so they are never inlined into JSON. See ADR 0092 (D1).
 */
function useBody(path?: string): BodyState {
  const [state, setState] = React.useState<BodyState>({ kind: 'empty' })
  React.useEffect(() => {
    if (!path) {
      setState({ kind: 'empty' })
      return
    }
    const ac = new AbortController()
    setState({ kind: 'loading' })
    fetchBody(path, ac.signal)
      .then((result) => setState({ kind: 'ready', result }))
      .catch((err: unknown) => {
        if (ac.signal.aborted) return
        setState({
          kind: 'error',
          message: err instanceof Error ? err.message : String(err),
        })
      })
    return () => ac.abort()
  }, [path])
  return state
}

// state is a prop, not this component's own: the shared match counter is only
// consistent when a body arriving re-renders the whole panel.
function BodyBlock({
  state,
  pretty,
  search,
  counter,
  activeIndex,
}: {
  state: BodyState
  pretty: boolean
  search: string
  counter: { current: number }
  activeIndex: number
}) {
  if (state.kind === 'empty') {
    return <div className="text-[#6b7280]">(empty body)</div>
  }
  if (state.kind === 'loading') {
    return <div className="text-[#6b7280]">Loading body…</div>
  }
  // A body we cannot read says so. Never render bytes we could not decrypt.
  // See ADR 0095-chunked-body-envelope.
  if (state.kind === 'error') {
    return (
      <div className="text-[#e3b341]" data-testid="body-error">
        Could not read body: {state.message}
      </div>
    )
  }

  const { text, bytes, binary, truncated } = state.result
  if (bytes === 0) return <div className="text-[#6b7280]">(empty body)</div>
  if (binary) {
    return (
      <div className="text-[#6b7280]" data-testid="body-binary">
        (binary body, {formatBytes(bytes)} — not shown)
      </div>
    )
  }

  const { text: shown, language } = formatBody(text, pretty)
  return (
    <div className="text-xs" data-testid="body-content">
      {language === 'json' ? (
        <JsonBody
          text={shown}
          search={search}
          counter={counter}
          activeIndex={activeIndex}
        />
      ) : language === 'sse' ? (
        <SseBody
          text={shown}
          search={search}
          counter={counter}
          activeIndex={activeIndex}
        />
      ) : (
        <pre className="whitespace-pre-wrap break-all text-[#c9d1d9]">
          {highlightText(shown, search, counter, activeIndex)}
        </pre>
      )}
      {truncated ? (
        <div className="text-[#6b7280]" data-testid="body-truncated">
          … showing the first {formatBytes(BODY_RENDER_CAP)} of this body
        </div>
      ) : null}
    </div>
  )
}

export function RequestDetail({
  req,
  onClose,
}: {
  req: RequestLog
  onClose?: () => void
}) {
  const requestBodyState = useBody(req.request_body_path)
  const responseBodyState = useBody(req.response_body_path)
  const [pretty, setPretty] = React.useState(true)
  const [search, setSearch] = React.useState('')
  const [activeIndex, setActiveIndex] = React.useState(0)
  const [totalMatches, setTotalMatches] = React.useState(0)
  const containerRef = React.useRef<HTMLDivElement>(null)

  // Reset search position whenever the query or selected request changes.
  React.useEffect(() => {
    setActiveIndex(0)
  }, [search, req.id])

  // The counter is shared (by reference) across every highlightText() call
  // made during this render pass, so matches are numbered in document order
  // across both the request and response panes.
  const counter = { current: 0 }

  const requestHeaders = (
    <HeadersBlock
      headers={req.request_headers}
      search={search}
      counter={counter}
      activeIndex={activeIndex}
    />
  )
  const requestBody = (
    <BodyBlock
      state={requestBodyState}
      pretty={pretty}
      search={search}
      counter={counter}
      activeIndex={activeIndex}
    />
  )
  const responseHeaders = (
    <HeadersBlock
      headers={req.response_headers}
      search={search}
      counter={counter}
      activeIndex={activeIndex}
    />
  )
  const responseBody = (
    <BodyBlock
      state={responseBodyState}
      pretty={pretty}
      search={search}
      counter={counter}
      activeIndex={activeIndex}
    />
  )

  // After committing, the counter has been walked to its final value --
  // sync it into state (for the "N of M" display). Intentionally runs on
  // every render: `counter` is a fresh local recomputed each render, so it
  // has no stable dependency to list.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  React.useEffect(() => {
    setTotalMatches(counter.current)
  })

  React.useEffect(() => {
    if (!search || totalMatches === 0) return
    const el = containerRef.current?.querySelector(
      `[data-match-index="${activeIndex}"]`,
    )
    el?.scrollIntoView({ block: 'nearest', behavior: 'smooth' })
  }, [activeIndex, search, totalMatches])

  function goToMatch(delta: number) {
    if (totalMatches === 0) return
    setActiveIndex((prev) => (prev + delta + totalMatches) % totalMatches)
  }

  return (
    <div className="flex h-full flex-col overflow-hidden" ref={containerRef}>
      <div className="flex flex-none items-center gap-2 border-b border-[#2a3040] px-3 py-2 text-xs">
        <Badge variant="outline" className="border-[#2a3040] text-[#9ca3af]">
          {req.method}
        </Badge>
        <span className="truncate text-[#c9d1d9]">{req.url}</span>
        <span className={statusColor(req.status_code)}>
          {req.status_code ?? '-'}
        </span>
        {req.policy_action && (
          <Badge variant="outline" className="border-[#2a3040] text-[#9ca3af]">
            {req.policy_action}
          </Badge>
        )}
        <div className="ml-auto flex flex-none items-center gap-1.5">
          <Button
            type="button"
            variant="ghost"
            size="sm"
            aria-pressed={pretty}
            onClick={() => setPretty((p) => !p)}
            className={pretty ? 'bg-[#58a6ff]/20 text-[#58a6ff] border border-[#58a6ff]/40' : 'text-[#6b7280]'}
            title="Pretty-print JSON bodies"
          >
            <Braces className="size-3.5" />
            Pretty
          </Button>
          <div className="flex items-center gap-1 rounded-lg border border-[#2a3040] px-1.5">
            <Search className="size-3.5 text-[#6b7280]" />
            <Input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search in request/response..."
              className="h-6 w-48 border-0 bg-transparent p-0 text-xs shadow-none focus-visible:ring-0"
            />
            {search && (
              <span className="whitespace-nowrap text-[10px] text-[#6b7280]">
                {totalMatches > 0
                  ? `${activeIndex + 1} of ${totalMatches}`
                  : 'no matches'}
              </span>
            )}
            <Button
              type="button"
              variant="ghost"
              size="icon-xs"
              disabled={totalMatches === 0}
              onClick={() => goToMatch(-1)}
              title="Previous match"
            >
              <ChevronUp className="size-3.5" />
            </Button>
            <Button
              type="button"
              variant="ghost"
              size="icon-xs"
              disabled={totalMatches === 0}
              onClick={() => goToMatch(1)}
              title="Next match"
            >
              <ChevronDown className="size-3.5" />
            </Button>
          </div>
          {onClose && (
            <Button
              type="button"
              variant="ghost"
              size="icon-xs"
              onClick={onClose}
              title="Close"
            >
              <X className="size-3.5" />
            </Button>
          )}
        </div>
      </div>
      <div className="min-h-0 flex-1">
        <ResizablePanelGroup orientation="horizontal">
          <ResizablePanel defaultSize={50} minSize={20}>
            <div className="flex h-full flex-col overflow-hidden">
              <div className="flex-none border-b border-[#2a3040] bg-[#1a1f2e] px-3 py-1.5 text-[11px] font-semibold uppercase tracking-wider text-[#9ca3af]">
                Request
              </div>
              <div className="detail-scroll min-h-0 flex-1 overflow-y-auto">
                <div className="p-3 text-xs">
                  <div className="mb-3">
                    <div className="mb-1 text-[10px] font-semibold uppercase text-[#6b7280]">
                      Headers
                    </div>
                    {requestHeaders}
                  </div>
                  <div>
                    <div className="mb-1 text-[10px] font-semibold uppercase text-[#6b7280]">
                      Body
                    </div>
                    {requestBody}
                  </div>
                </div>
              </div>
            </div>
          </ResizablePanel>
          <ResizableHandle withHandle />
          <ResizablePanel defaultSize={50} minSize={20}>
            <div className="flex h-full flex-col overflow-hidden">
              <div className="flex-none border-b border-[#2a3040] bg-[#1a1f2e] px-3 py-1.5 text-[11px] font-semibold uppercase tracking-wider text-[#9ca3af]">
                Response
              </div>
              <div className="detail-scroll min-h-0 flex-1 overflow-y-auto">
                <div className="p-3 text-xs">
                  <div className="mb-3">
                    <div className="mb-1 text-[10px] font-semibold uppercase text-[#6b7280]">
                      Headers
                    </div>
                    {responseHeaders}
                  </div>
                  <div>
                    <div className="mb-1 text-[10px] font-semibold uppercase text-[#6b7280]">
                      Body
                    </div>
                    {responseBody}
                  </div>
                  {req.error && (
                    <div className="mt-3 text-[#ff7b72]">Error: {req.error}</div>
                  )}
                </div>
              </div>
            </div>
          </ResizablePanel>
        </ResizablePanelGroup>
      </div>
    </div>
  )
}
