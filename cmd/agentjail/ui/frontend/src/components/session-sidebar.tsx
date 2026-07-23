import { ArrowLeft } from 'lucide-react'
import { useSearchParams } from 'react-router-dom'
import * as React from 'react'
import { cn } from '@/lib/utils'
import { Badge } from '@/components/ui/badge'
import { ScrollArea } from '@/components/ui/scroll-area'

export interface SidebarSession {
  id: string
  agent?: string
  /** User-assigned session name; wins over any directory-derived label. */
  name?: string
  cwd?: string
  repoName?: string
  active: boolean
  requestCount: number
  networkCount?: number
  denyCount?: number
  lastSeen: string
}

function ClaudeIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 248 248" fill="none" className="shrink-0">
      <path d="M52.4 162.9l46.4-26 .7-2.3-.7-1.3h-2.3l-7.8-.5-26.5-.7-22.9-.9-22.3-1.2-5.6-1.2L6.2 121.9l.5-3.4 4.7-3.2 6.8.6 14.9 1.1 22.4 1.5 16.2 1 24.1 2.5h3.8l.5-1.5-1.3-1-.9-.9-23.2-15.7-25.1-16.5-13.1-9.6-7-4.8-3.6-4.5-1.5-9.9 6.4-7.1 8.7.6 2.2.6 8.8 6.7 18.7 14.5 24.5 18 3.6 2.9 1.4-1 .2-.7-1.7-2.7-13.2-24-14.1-24.5-6.4-10.2-1.7-6 .5-7.2L67.8 7.5l4.1-1.3 9.8 1.3 4.1 3.5 6.1 13.9 9.8 21.9 15.3 29.8 4.5 8.9 2.4 8.1.9 2.5h1.5v-1.4l1.3-16.8 2.3-20.6 2.3-26.5.8-7.4 3.7-9 7.4-4.8 5.7 2.7 4.7 6.7-.6 4.4-2.8 18.2-5.5 28.5-3.6 19.1h2l2.4-2.5 9.7-12.8 16.2-20.3 7.1-8 8.4-8.9 5.4-4.3h10.2l7.4 11.1-3.3 11.5-10.4 13.2-8.7 11.2-12.4 16.6-7.7 13.4.7 1.1 1.9-.2 28-6-14.8-2.7 18.1-3.1 8.1 3.8.9 3.9-3.3 7.9-19.4 4.7-22.7 4.6-33.8 8L161.7 131.9l.4.7 15.2 1.4 6.5.4h15.9l29.7 2.2 7.8 5.1 4.6 6.3-.8 4.8-12 6-16-3.8-37.6-9-12.9-3.2h-1.8v1.1l10.7 10.5 19.7 17.7 24.6 22.9 1.3 5.7-3.2 4.5-3.3-.5-21.7-16.3-8.4-7.3-18.8-16h-1.3v1.7l4.3 6.4 23.1 34.6 1.1 10.6-1.7 3.4-6 2.1-6.5-1.2-13.6-19-13.9-21.3-11.2-19.1-1.4.9-6.7 71.2-3.1 3.7-7.1 2.7-6-4.5-3.2-7.3 3.2-14.5 3.8-18.9 3.1-15 2.8-18.7 1.7-6.2-.2-.4-1.4.2-14.1 19.3-21.5 24.7-17.3 18.1-4.1 1.7-7 -3.7-.6-6.5 3.9-5.8 23.4-29.8 14.1-18.5 9.1-10.6-.1-1.5-.5 0-62.3 40.6-11.1 1.4-4.8-4.5.6-6.5 2.3-2.4 18.7-12.9z" fill="#D97757"/>
    </svg>
  )
}

function CursorIcon() {
  return (
    <svg width="18" height="18" viewBox="96 73 321 366" fill="none" className="shrink-0">
      <path d="M410.3 159.5l-146.4-84.5c-4.7-2.7-10.5-2.7-15.2 0L102.4 159.5c-4 2.3-6.4 6.5-6.4 11.1v170.4c0 4.6 2.4 8.8 6.4 11.1l146.4 84.5c4.7 2.7 10.5 2.7 15.2 0l146.4-84.5c4-2.3 6.4-6.5 6.4-11.1V170.6c0-4.6-2.4-8.8-6.4-11.1zm-9.2 17.9L259.8 422c-1 1.6-3.5 1-3.5-.9V260.8c0-3.2-1.7-6.2-4.5-7.8L113 172.9c-1.6-1-.9-3.5.9-3.5h282.6c4 0 6.5 4.4 4.5 7.8z" fill="#edecec"/>
    </svg>
  )
}

function CodexIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" className="shrink-0">
      <rect width="24" height="24" rx="4" fill="#10a37f"/>
      <path d="M12 3C7.03 3 3 7.03 3 12s4.03 9 9 9 9-4.03 9-9-4.03-9-9-9zm0 16.2c-3.97 0-7.2-3.23-7.2-7.2S8.03 4.8 12 4.8s7.2 3.23 7.2 7.2-3.23 7.2-7.2 7.2z" fill="white"/>
    </svg>
  )
}

function DefaultAgentIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" className="shrink-0">
      <rect width="24" height="24" rx="4" fill="#3b4252"/>
      <path d="M7 8h10M7 12h10M7 16h6" stroke="#9ca3af" strokeWidth="1.5" strokeLinecap="round"/>
    </svg>
  )
}

export function AgentIcon({ agent }: { agent?: string }) {
  const a = (agent || '').toLowerCase()
  if (a.includes('claude')) return <ClaudeIcon />
  if (a.includes('cursor')) return <CursorIcon />
  if (a.includes('codex')) return <CodexIcon />
  return <DefaultAgentIcon />
}

function relativeTime(iso: string): string {
  const then = new Date(iso).getTime()
  if (Number.isNaN(then)) return ''
  const diffMs = Date.now() - then
  const s = Math.floor(diffMs / 1000)
  if (s < 5) return 'just now'
  if (s < 60) return `${s}s ago`
  const m = Math.floor(s / 60)
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ago`
  const d = Math.floor(h / 24)
  return `${d}d ago`
}

function sessionLabel(s: SidebarSession): string {
  if (s.name) return s.name
  if (s.repoName) return s.repoName
  if (s.cwd) {
    const parts = s.cwd.split('/')
    return parts[parts.length - 1] || s.cwd
  }
  return s.id.slice(0, 16)
}

function isSessionActive(s: SidebarSession): boolean {
  return s.active
}

interface SessionSidebarProps {
  sessions: SidebarSession[]
  selectedId: string | null
  onSelect: (id: string | null) => void
  title?: string
  mode?: 'monitor' | 'network'
}

export function SessionSidebar({
  sessions,
  selectedId,
  onSelect,
  title = 'Sessions',
  mode = 'monitor',
}: SessionSidebarProps) {
  const [searchParams, setSearchParams] = useSearchParams()

  React.useEffect(() => {
    const sessionParam = searchParams.get('session')
    if (sessionParam && sessionParam !== selectedId) {
      onSelect(sessionParam)
    }
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  const handleSelect = (id: string | null) => {
    onSelect(id)
    if (id) {
      setSearchParams({ session: id })
    } else {
      setSearchParams({})
    }
  }

  return (
    <div className="flex h-full w-full flex-col overflow-hidden border-r border-[#2a3040]">
      <div className="flex-none truncate border-b border-[#2a3040] px-3 py-2 text-xs font-semibold uppercase tracking-wider text-[#9ca3af]">
        {title}
      </div>
      {selectedId !== null && (
        <div
          className="flex-none cursor-pointer border-b border-[#2a3040] px-3 py-2 text-xs text-[#58a6ff] hover:bg-[#1c2333] hover:text-[#79b8ff]"
          style={{ background: '#1a2030' }}
          onClick={() => handleSelect(null)}
        >
          <div className="flex items-center gap-2 font-semibold">
            <ArrowLeft className="h-3.5 w-3.5" />
            All Sessions
          </div>
        </div>
      )}
      <ScrollArea className="min-h-0 flex-1">
        <div>
          {sessions.length === 0 && (
            <div className="px-3 py-4 text-xs text-[#6b7280]">
              No sessions yet.
            </div>
          )}
          {(() => {
            const activeSessions = sessions.filter(isSessionActive)
            const inactiveSessions = sessions.filter((s) => !isSessionActive(s))

            const renderSession = (s: SidebarSession) => {
              const selected = s.id === selectedId
              const active = isSessionActive(s)
              const label = sessionLabel(s)
              return (
                <div
                  key={s.id}
                  onClick={() => handleSelect(s.id === selectedId ? null : s.id)}
                  className={cn(
                    'cursor-pointer border-b border-[#1c2333] border-l-2 border-l-transparent px-3 py-2.5 transition-colors hover:bg-[#1c2333]',
                    selected && 'border-l-[#58a6ff] bg-[#202b40] hover:bg-[#202b40]',
                  )}
                  title={s.cwd || s.id}
                >
                  <div className="flex items-center gap-2 min-w-0">
                    <span
                      className={active ? 'live-dot' : undefined}
                      style={
                        !active
                          ? {
                              display: 'inline-block',
                              width: 7,
                              height: 7,
                              borderRadius: '50%',
                              background: '#4b5563',
                              flexShrink: 0,
                            }
                          : { flexShrink: 0 }
                      }
                    />
                    <AgentIcon agent={s.agent} />
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center justify-between gap-2">
                        <span
                          className={cn(
                            'truncate text-xs font-semibold',
                            selected
                              ? 'text-[#e6edf3]'
                              : active
                                ? 'text-[#c9d1d9]'
                                : 'text-[#8b95a1]',
                          )}
                        >
                          {label}
                        </span>
                        <Badge
                          variant="outline"
                          className="h-4 shrink-0 border-[#2a3040] bg-transparent px-1.5 text-[10px] text-[#9ca3af]"
                        >
                          {mode === 'network' ? (s.networkCount ?? 0) : s.requestCount}
                        </Badge>
                      </div>
                      <div className="mt-0.5 text-[10px] text-[#6b7280]">
                        {mode === 'network'
                          ? `${s.networkCount ?? 0} requests`
                          : `${s.requestCount} decisions`}
                        {(s.denyCount ?? 0) > 0 && (
                          <span className="font-bold text-[#ff7b72]"> . {s.denyCount} deny</span>
                        )}
                        {' '}{relativeTime(s.lastSeen)}
                      </div>
                      {s.cwd && (
                        <div className="mt-0.5 flex items-center gap-1 text-[10px] text-[#4b5563]">
                          <span>📁</span>
                          <span className="truncate">{s.cwd.split('/').slice(-2).join('/')}</span>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              )
            }

            return (
              <>
                {activeSessions.length > 0 && (
                  <>
                    <div className="flex items-center gap-1.5 px-3 pt-2 pb-1 text-[10px] font-semibold uppercase tracking-wider text-[#56d364]">
                      <span className="live-dot" />
                      Active
                    </div>
                    {activeSessions.map(renderSession)}
                  </>
                )}
                {activeSessions.length > 0 && inactiveSessions.length > 0 && (
                  <div className="my-1 border-t border-[#2a3040]" />
                )}
                {inactiveSessions.length > 0 && (
                  <>
                    <div className="px-3 pt-2 pb-1 text-[10px] font-semibold uppercase tracking-wider text-[#6b7280]">
                      Inactive
                    </div>
                    {inactiveSessions.map(renderSession)}
                  </>
                )}
              </>
            )
          })()}
        </div>
      </ScrollArea>
    </div>
  )
}
