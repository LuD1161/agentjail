import * as React from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import type { ColumnDef } from '@tanstack/react-table'
import { cn } from '@/lib/utils'
import { Layout } from '@/components/layout'
import { SessionSidebar } from '@/components/session-sidebar'
import { SplitPane } from '@/components/split-pane'
import { DataTable } from '@/components/data-table'
import { DataTableColumnHeader } from '@/components/data-table-column-header'
import { ScrollArea } from '@/components/ui/scroll-area'
import { useEventSource } from '@/hooks/use-event-source'
import { fetchState } from '@/lib/api'
import { formatTime, actionClass } from '@/lib/format'
import type { TimelineEvent } from '@/types'

function truncate(s: string | undefined, n = 80) {
  if (!s) return ''
  return s.length > n ? `${s.slice(0, n)}…` : s
}

const columns: ColumnDef<TimelineEvent>[] = [
  {
    accessorKey: 'time',
    header: ({ column }) => <DataTableColumnHeader column={column} title="Time" filterable={false} />,
    cell: ({ row }) => (
      <span className="text-[#9ca3af]">{formatTime(row.original.time)}</span>
    ),
    size: 80,
    minSize: 60,
    maxSize: 120,
  },
  {
    accessorKey: 'tool',
    header: ({ column }) => <DataTableColumnHeader column={column} title="Tool" />,
    cell: ({ row }) => (
      <span className="text-[#c9d1d9]">{row.original.tool ?? '-'}</span>
    ),
    size: 80,
    minSize: 50,
    maxSize: 200,
  },
  {
    accessorKey: 'action',
    header: ({ column, table }) => {
      const fc = (table.options.meta as { actionFacets?: Record<string, number> })?.actionFacets
      return <DataTableColumnHeader column={column} title="Action" facetCounts={fc} />
    },
    cell: ({ row }) => (
      <span className={actionClass(row.original.action)}>
        {row.original.action ?? '-'}
      </span>
    ),
    size: 70,
    minSize: 50,
    maxSize: 120,
  },
  {
    id: 'input',
    header: ({ column }) => <DataTableColumnHeader column={column} title="Input" filterable={false} />,
    accessorFn: (row) => row.tool_input_redacted ?? row.summary ?? '',
    cell: ({ row }) => (
      <span className="truncate text-[#9ca3af]" title={row.original.tool_input_redacted}>
        {truncate(row.original.tool_input_redacted ?? row.original.summary)}
      </span>
    ),
    size: 99999,
    minSize: 200,
  },
  {
    accessorKey: 'rule_id',
    header: ({ column }) => <DataTableColumnHeader column={column} title="Rule" />,
    cell: ({ row }) => (
      <span className="text-[#9ca3af]">{row.original.rule_id ?? '-'}</span>
    ),
    size: 120,
    minSize: 60,
    maxSize: 250,
  },
  {
    accessorKey: 'session_id',
    header: ({ column }) => <DataTableColumnHeader column={column} title="Session" />,
    cell: ({ row }) => (
      <span className="text-[#6b7280]" title={row.original.session_id}>
        {row.original.session_id?.slice(0, 10) ?? '-'}
      </span>
    ),
    size: 90,
    minSize: 60,
    maxSize: 200,
  },
]

export function MonitorPage() {
  const [selectedSession, setSelectedSession] = React.useState<string | null>(
    null,
  )
  const [selectedEvent, setSelectedEvent] = React.useState<TimelineEvent | null>(
    null,
  )
  const queryClient = useQueryClient()

  const stateQuery = useQuery({
    queryKey: ['state'],
    queryFn: fetchState,
    refetchInterval: 10000,
  })

  const [connected, setConnected] = React.useState(false)

  useEventSource<TimelineEvent>(
    '/events',
    (incoming) => {
      queryClient.setQueryData(['state'], (old: typeof stateQuery.data) => {
        if (!old) return old
        return {
          ...old,
          recent_events: [incoming, ...old.recent_events].slice(0, 500),
          total_allow: old.total_allow + (incoming.action === 'allow' ? 1 : 0),
          total_deny: old.total_deny + (incoming.action === 'deny' ? 1 : 0),
          total_ask: old.total_ask + (incoming.action === 'ask' ? 1 : 0),
        }
      })
    },
    {
      onOpen: () => setConnected(true),
      onError: () => setConnected(false),
    },
  )

  const snapshot = stateQuery.data
  const sessions = (snapshot?.sessions ?? [])
    .map((s) => ({
      id: s.id,
      agent: s.agent,
      cwd: s.cwd,
      repoName: s.repo_name,
      active: s.active,
      requestCount: s.total,
      denyCount: s.deny,
      lastSeen: s.last_seen,
    }))
    .sort((a, b) => new Date(b.lastSeen).getTime() - new Date(a.lastSeen).getTime())

  const events = (snapshot?.recent_events ?? []).filter(
    (e) => !selectedSession || e.session_id === selectedSession,
  )

  const status = (
    <>
      <span className="text-xs">
        <span className="font-bold text-[#56d364]">
          {snapshot?.total_allow ?? 0}
        </span>{' '}
        <span className="text-[#6b7280]">allow</span>
      </span>
      <span className="text-xs">
        <span className="font-bold text-[#ff7b72]">
          {snapshot?.total_deny ?? 0}
        </span>{' '}
        <span className="text-[#6b7280]">deny</span>
      </span>
      <span className="text-xs">
        <span className="font-bold text-[#e3b341]">
          {snapshot?.total_ask ?? 0}
        </span>{' '}
        <span className="text-[#6b7280]">ask</span>
      </span>
    </>
  )

  return (
    <Layout connected={connected} status={status}>
      <SplitPane direction="horizontal" defaultSize={300} minSize={150} maxSize={600}>
        <SessionSidebar
          sessions={sessions}
          selectedId={selectedSession}
          onSelect={setSelectedSession}
          title="Sessions"
        />
        <SplitPane direction="vertical" defaultSize={selectedEvent ? 350 : 9999} minSize={150} maxSize={800}>
          <DataTable
            columns={columns}
            data={events}
            pageSize={100}
            meta={{
              actionFacets: {
                allow: snapshot?.total_allow ?? 0,
                deny: snapshot?.total_deny ?? 0,
                ask: snapshot?.total_ask ?? 0,
              },
            }}
            getRowId={(row, index) => `${row.time}-${index}`}
            selectedRowId={
              selectedEvent
                ? `${selectedEvent.time}-${events.indexOf(selectedEvent)}`
                : null
            }
            onRowClick={setSelectedEvent}
            emptyMessage="No policy decisions recorded yet."
          />
          {selectedEvent ? (
            <div className="flex h-full flex-col overflow-hidden border-t-2 border-[#58a6ff]">
              <div className="flex items-center gap-3 border-b border-[#2a3040] px-4 py-2 shrink-0">
                <span className="text-xs font-semibold text-[#f0f3f6]">
                  {selectedEvent.tool ?? 'Unknown'}
                </span>
                <span className={cn(
                  'text-xs font-semibold',
                  selectedEvent.action === 'allow' ? 'text-[#56d364]' :
                  selectedEvent.action === 'deny' ? 'text-[#ff7b72]' :
                  selectedEvent.action === 'ask' ? 'text-[#e3b341]' : 'text-[#9ca3af]'
                )}>
                  {selectedEvent.action ?? '-'}
                </span>
                <span className="text-xs text-[#6b7280]">{selectedEvent.rule_id ?? ''}</span>
                <span className="flex-1" />
                <button
                  onClick={() => setSelectedEvent(null)}
                  className="text-sm text-[#6b7280] hover:text-[#ff7b72]"
                >x</button>
              </div>
              <div className="flex min-h-0 flex-1">
                <ScrollArea className="flex-1 border-r border-[#2a3040]">
                  <div className="p-3">
                    <div className="mb-2 text-[10px] font-semibold uppercase text-[#6b7280]">Details</div>
                    <div className="space-y-1.5 text-xs">
                      <div><span className="text-[#58a6ff]">Tool:</span> <span className="text-[#c9d1d9]">{selectedEvent.tool ?? '-'}</span></div>
                      <div><span className="text-[#58a6ff]">Action:</span> <span className={actionClass(selectedEvent.action)}>{selectedEvent.action ?? '-'}</span></div>
                      <div><span className="text-[#58a6ff]">Rule:</span> <span className="text-[#c9d1d9]">{selectedEvent.rule_id ?? '-'}</span></div>
                      <div><span className="text-[#58a6ff]">Reason:</span> <span className="text-[#c9d1d9]">{selectedEvent.reason ?? '-'}</span></div>
                      <div><span className="text-[#58a6ff]">Time:</span> <span className="text-[#c9d1d9]">{selectedEvent.time ?? '-'}</span></div>
                      <div><span className="text-[#58a6ff]">Session:</span> <span className="text-[#c9d1d9]">{selectedEvent.session_id ?? '-'}</span></div>
                      <div><span className="text-[#58a6ff]">Agent:</span> <span className="text-[#c9d1d9]">{selectedEvent.agent ?? '-'}</span></div>
                      {selectedEvent.elapsed_us != null && (
                        <div><span className="text-[#58a6ff]">Elapsed:</span> <span className="text-[#c9d1d9]">{(selectedEvent.elapsed_us / 1000).toFixed(1)}ms</span></div>
                      )}
                      {selectedEvent.err && (
                        <div><span className="text-[#ff7b72]">Error:</span> <span className="text-[#ff7b72]">{selectedEvent.err}</span></div>
                      )}
                    </div>
                  </div>
                </ScrollArea>
                <ScrollArea className="flex-1">
                  <div className="p-3">
                    <div className="mb-2 text-[10px] font-semibold uppercase text-[#6b7280]">Input</div>
                    <pre className="whitespace-pre-wrap break-all text-xs text-[#c9d1d9]">
                      {selectedEvent.tool_input_redacted ?? selectedEvent.summary ?? '-'}
                    </pre>
                  </div>
                </ScrollArea>
              </div>
            </div>
          ) : <div />}
        </SplitPane>
      </SplitPane>
    </Layout>
  )
}
