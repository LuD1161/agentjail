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
import { fetchRequests, fetchState } from '@/lib/api'
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

  const stateQuery = useQuery({
    queryKey: ['state'],
    queryFn: fetchState,
    refetchInterval: 10000,
  })

  // Network requests use shield tunnel session IDs (shield-*), not daemon
  // session IDs (uuid). Until the mapping is wired, fetch all requests and
  // filter client-side by the daemon session's time window.
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

  // Filter requests by the selected session's time window since daemon
  // session IDs and tunnel session IDs are different namespaces.
  const selectedSessionData = (stateQuery.data?.sessions ?? []).find(
    (s) => s.id === selectedSession,
  )
  const requests = React.useMemo(() => {
    if (!selectedSession || !selectedSessionData) return allRequests
    const start = new Date(selectedSessionData.first_seen).getTime() - 5000
    const end = new Date(selectedSessionData.last_seen).getTime() + 5000
    return allRequests.filter((r) => {
      const t = new Date(r.ts).getTime()
      return t >= start && t <= end
    })
  }, [allRequests, selectedSession, selectedSessionData])

  const selectedRequest =
    requests.find((r) => r.id === selectedRequestId) ?? null

  // Count network requests per session by time window
  const sessions = React.useMemo(() => {
    const daemonSessions = stateQuery.data?.sessions ?? []
    return daemonSessions
      .map((s) => {
        const start = new Date(s.first_seen).getTime() - 5000
        const end = new Date(s.last_seen).getTime() + 5000
        const sessionRequests = allRequests.filter((r) => {
          const t = new Date(r.ts).getTime()
          return t >= start && t <= end
        })
        const netDenyCount = sessionRequests.filter(
          (r) => r.policy_action?.toLowerCase() === 'deny'
        ).length
        return {
          id: s.id,
          agent: s.agent,
          cwd: s.cwd,
          repoName: s.repo_name,
          active: s.active,
          requestCount: s.total,
          networkCount: sessionRequests.length,
          denyCount: netDenyCount,
          lastSeen: s.last_seen,
        }
      })
      .sort((a, b) => new Date(b.lastSeen).getTime() - new Date(a.lastSeen).getTime())
  }, [stateQuery.data?.sessions, allRequests])

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
