import * as React from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import type { ColumnDef } from '@tanstack/react-table'
import { Layout } from '@/components/layout'
import { SessionSidebar } from '@/components/session-sidebar'
import { SplitPane } from '@/components/split-pane'
import { DataTable } from '@/components/data-table'
import { DataTableColumnHeader } from '@/components/data-table-column-header'
import { RequestDetail } from '@/components/request-detail'
import { useEventSource } from '@/hooks/use-event-source'
import { fetchNetworkSessions, fetchRequests } from '@/lib/api'
import { formatTime, formatBytes } from '@/lib/format'
import type { RequestLog } from '@/types'

function methodBadgeClass(method: string) {
  switch (method.toUpperCase()) {
    case 'GET':
      return 'text-[#58a6ff]'
    case 'POST':
      return 'text-[#56d364]'
    case 'PUT':
    case 'PATCH':
      return 'text-[#e3b341]'
    case 'DELETE':
      return 'text-[#ff7b72]'
    default:
      return 'text-[#9ca3af]'
  }
}

function statusClass(code?: number) {
  if (!code) return 'text-[#9ca3af]'
  if (code >= 500) return 'text-[#ff7b72]'
  if (code >= 400) return 'text-[#e3b341]'
  if (code >= 300) return 'text-[#58a6ff]'
  return 'text-[#56d364]'
}

const columns: ColumnDef<RequestLog>[] = [
  {
    accessorKey: 'id',
    header: ({ column }) => <DataTableColumnHeader column={column} title="#" filterable={false} />,
    cell: ({ row }) => <span className="text-[#6b7280]">{row.original.id}</span>,
    size: 45,
    minSize: 35,
    maxSize: 80,
  },
  {
    accessorKey: 'ts',
    header: ({ column }) => <DataTableColumnHeader column={column} title="Time" filterable={false} />,
    cell: ({ row }) => (
      <span className="text-[#9ca3af]">{formatTime(row.original.ts)}</span>
    ),
    size: 80,
    minSize: 60,
    maxSize: 120,
  },
  {
    accessorKey: 'method',
    header: ({ column }) => <DataTableColumnHeader column={column} title="Method" />,
    cell: ({ row }) => (
      <span className={`font-semibold ${methodBadgeClass(row.original.method)}`}>
        {row.original.method}
      </span>
    ),
    size: 65,
    minSize: 50,
    maxSize: 100,
  },
  {
    accessorKey: 'host',
    header: ({ column }) => <DataTableColumnHeader column={column} title="Host" />,
    cell: ({ row }) => (
      <span className="truncate text-[#c9d1d9]">{row.original.host}</span>
    ),
    size: 180,
    minSize: 80,
  },
  {
    accessorKey: 'path',
    header: ({ column }) => <DataTableColumnHeader column={column} title="Path" filterable={false} />,
    cell: ({ row }) => (
      <span className="truncate text-[#c9d1d9]" title={row.original.path}>
        {row.original.path}
      </span>
    ),
    size: 99999,
    minSize: 100,
  },
  {
    accessorKey: 'status_code',
    header: ({ column }) => <DataTableColumnHeader column={column} title="Status" />,
    cell: ({ row }) => (
      <span className={`font-semibold ${statusClass(row.original.status_code)}`}>
        {row.original.status_code ?? '-'}
      </span>
    ),
    size: 60,
    minSize: 45,
    maxSize: 100,
  },
  {
    id: 'size',
    header: ({ column }) => <DataTableColumnHeader column={column} title="Size" filterable={false} />,
    accessorFn: (row) => (row.response_size ?? 0) + (row.request_size ?? 0),
    cell: ({ row }) => (
      <span className="text-[#9ca3af]">
        {formatBytes(row.original.response_size)}
      </span>
    ),
    size: 70,
    minSize: 50,
    maxSize: 120,
  },
  {
    accessorKey: 'elapsed_ms',
    header: ({ column }) => <DataTableColumnHeader column={column} title="Elapsed" filterable={false} />,
    cell: ({ row }) => (
      <span className="text-[#9ca3af]">{row.original.elapsed_ms ?? 0}ms</span>
    ),
    size: 70,
    minSize: 50,
    maxSize: 120,
  },
  {
    accessorKey: 'policy_action',
    header: ({ column }) => <DataTableColumnHeader column={column} title="Policy" />,
    cell: ({ row }) => {
      const action = row.original.policy_action
      if (!action) return <span className="text-[#4b5563]">-</span>
      const color =
        action === 'allow'
          ? 'text-[#56d364]'
          : action === 'deny'
            ? 'text-[#ff7b72]'
            : 'text-[#e3b341]'
      return <span className={color}>{action}</span>
    },
    size: 65,
    minSize: 45,
    maxSize: 120,
  },
]

export function NetworkPage() {
  const [selectedSession, setSelectedSession] = React.useState<string | null>(
    null,
  )
  const [selectedRequestId, setSelectedRequestId] = React.useState<
    number | null
  >(null)
  const queryClient = useQueryClient()

  // Sidebar sessions must come from the network store: its rows carry a
  // body/network session id, a different identity from the daemon's tool-call
  // sessions. See AGE-252.
  const sessionsQuery = useQuery({
    queryKey: ['network-sessions'],
    queryFn: fetchNetworkSessions,
    refetchInterval: 10000,
  })

  const requestsQuery = useQuery({
    queryKey: ['requests'],
    queryFn: () => fetchRequests({ limit: 200 }),
    refetchInterval: false,
  })

  const streamUrl = '/api/requests/stream'

  const [connected, setConnected] = React.useState(false)

  useEventSource<RequestLog>(
    streamUrl,
    (incoming) => {
      queryClient.setQueryData(
        ['requests'],
        (old: { requests: RequestLog[] } | undefined) => {
          if (!old) return old
          if (old.requests.some((r) => r.id === incoming.id)) return old
          return { ...old, requests: [incoming, ...old.requests] }
        },
      )
    },
    {
      onOpen: () => setConnected(true),
      onError: () => setConnected(false),
    },
  )

  const allRequests = requestsQuery.data?.requests ?? []

  // Requests key off the network session id -- the same identity the sidebar
  // now lists. See AGE-252.
  const requests = React.useMemo(() => {
    if (!selectedSession) return allRequests
    return allRequests.filter((r) => r.session_id === selectedSession)
  }, [allRequests, selectedSession])

  const selectedRequest =
    requests.find((r) => r.id === selectedRequestId) ?? null

  // Deny counts are not in the sessions payload; derive them from the loaded
  // rows, grouped by the same network session id.
  const denyBySession = React.useMemo(() => {
    const m = new Map<string, number>()
    for (const r of allRequests) {
      if (!r.session_id || r.policy_action?.toLowerCase() !== 'deny') continue
      m.set(r.session_id, (m.get(r.session_id) ?? 0) + 1)
    }
    return m
  }, [allRequests])

  // A network session is "active" if its last row is recent -- the payload
  // carries no live flag.
  const activeWindowMs = 120_000
  const sessions = React.useMemo(() => {
    const netSessions = sessionsQuery.data?.sessions ?? []
    const now = Date.now()
    return netSessions
      .map((s) => ({
        id: s.session_id,
        active: now - new Date(s.last_seen).getTime() < activeWindowMs,
        requestCount: s.request_count,
        networkCount: s.request_count,
        denyCount: denyBySession.get(s.session_id) ?? 0,
        lastSeen: s.last_seen,
      }))
      .sort((a, b) => new Date(b.lastSeen).getTime() - new Date(a.lastSeen).getTime())
  }, [sessionsQuery.data?.sessions, denyBySession])

  return (
    <Layout connected={connected}>
      <SplitPane direction="horizontal" defaultSize={300} minSize={150} maxSize={600}>
        <SessionSidebar
          sessions={sessions}
          selectedId={selectedSession}
          onSelect={setSelectedSession}
          title="Sessions"
          mode="network"
        />
        <SplitPane direction="vertical" defaultSize={selectedRequest ? 350 : 9999} minSize={150} maxSize={800}>
          <DataTable
            columns={columns}
            data={requests}
            pageSize={50}
            getRowId={(row) => row.id}
            selectedRowId={selectedRequestId}
            onRowClick={(row) => setSelectedRequestId(row.id)}
            emptyMessage={
              requestsQuery.data?.unavailable
                ? 'Network store unavailable -- is agentjail-shield running?'
                : 'No requests captured yet.'
            }
          />
          {selectedRequest ? (
            <RequestDetail
              req={selectedRequest}
              onClose={() => setSelectedRequestId(null)}
            />
          ) : <div />}
        </SplitPane>
      </SplitPane>
    </Layout>
  )
}
