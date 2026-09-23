import * as React from 'react'
import { useSearchParams } from 'react-router-dom'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import type { ColumnDef } from '@tanstack/react-table'
import { Layout } from '@/components/layout'
import { SessionSidebar } from '@/components/session-sidebar'
import { SplitPane } from '@/components/split-pane'
import { DataTable } from '@/components/data-table'
import { DataTableColumnHeader } from '@/components/data-table-column-header'
import { RequestDetail } from '@/components/request-detail'
import { useEventSource } from '@/hooks/use-event-source'
import { fetchNetworkSessions, fetchRequests, fetchRequestDetail, type RequestsListResponse } from '@/lib/api'
import { mergeLiveRequest, networkPageSize, requestId } from '@/lib/network-history'
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
    // Wide enough to show the filter funnel (label + sort chevron + funnel)
    // after the header's horizontal padding.
    size: 115,
    minSize: 100,
    maxSize: 150,
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
  // The selected request lives in the URL (?req=), not component state, so
  // every open detail pane is a shareable perma-link.
  const [searchParams, setSearchParams] = useSearchParams()
  const reqParam = searchParams.get('req')
  const selectedRequestId = requestId(reqParam)
  const [history, setHistory] = React.useState<number[]>([])
  const beforeId = history.at(-1) ?? 0
  const setSelectedRequestId = React.useCallback(
    (id: number | null) => {
      setSearchParams((prev) => {
        const p = new URLSearchParams(prev)
        if (id == null) p.delete('req')
        else p.set('req', String(id))
        return p
      })
    },
    [setSearchParams],
  )
  const queryClient = useQueryClient()

  // Sidebar sessions must come from the network store: its rows carry a
  // body/network session id, a different identity from the daemon's tool-call
  // sessions. See AGE-252.
  const sessionsQuery = useQuery({
    queryKey: ['network-sessions'],
    queryFn: fetchNetworkSessions,
    refetchInterval: 10000,
  })

  const requestsKey = ['requests', selectedSession, beforeId] as const
  const requestsQuery = useQuery({
    queryKey: requestsKey,
    queryFn: () => fetchRequests({ limit: networkPageSize, session: selectedSession, beforeId }),
    refetchInterval: beforeId === 0 ? 10000 : false,
    gcTime: 0,
  })
  const detailQuery = useQuery({
    queryKey: ['request-detail', selectedRequestId],
    queryFn: () => fetchRequestDetail(selectedRequestId!),
    enabled: selectedRequestId !== null,
    gcTime: 0,
    retry: false,
  })
  const [connected, setConnected] = React.useState(false)

  useEventSource<RequestLog>(
    '/api/requests/stream',
    (incoming) => {
      if (beforeId !== 0) return
      queryClient.setQueryData<RequestsListResponse>(requestsKey,
        (old) => mergeLiveRequest(old, incoming, selectedSession))
    },
    {
      onOpen: () => {
        setConnected(true)
        void queryClient.invalidateQueries({ queryKey: ['requests'] })
        void queryClient.invalidateQueries({ queryKey: ['network-sessions'] })
      },
      onError: () => setConnected(false),
    },
  )

  const requests = requestsQuery.data?.requests ?? []
  const selectedRequest = detailQuery.data ?? null
  function selectSession(id: string | null) {
    setHistory([])
    setSelectedSession(id)
  }

  // "active" is authoritative from the server: it reflects the owning shield
  // PID's liveness, so a running-but-network-idle agent stays active. The old
  // 120s recency window is gone. See ADR 0100-network-active-pid.
  const sessions = React.useMemo(() => {
    const netSessions = sessionsQuery.data?.sessions ?? []
    return netSessions
      .map((s) => ({
        id: s.session_id,
        agent: s.agent,
        name: s.name,
        cwd: s.cwd,
        active: s.active,
        requestCount: s.request_count,
        networkCount: s.request_count,
        denyCount: s.deny_count,
        lastSeen: s.last_seen,
      }))
      .sort((a, b) => new Date(b.lastSeen).getTime() - new Date(a.lastSeen).getTime())
  }, [sessionsQuery.data?.sessions])

  return (
    <Layout connected={connected && !requestsQuery.isError && !sessionsQuery.isError}>
      <SplitPane direction="horizontal" defaultSize={300} minSize={150} maxSize={600}>
        <SessionSidebar
          sessions={sessions}
          selectedId={selectedSession}
          onSelect={selectSession}
          title="Sessions"
          mode="network"
        />
        <SplitPane direction="vertical" defaultSize={reqParam ? 350 : 9999} minSize={150} maxSize={800}>
          <div className="flex h-full min-h-0 flex-col">
            <div className="flex flex-wrap items-center gap-3 border-b border-[#2a3040] px-3 py-2 text-xs text-[#9ca3af]">
              <span>{beforeId ? 'History' : 'Live'} · {requestsQuery.data?.total ?? '--'} stored requests (last refresh)</span>
              <button type="button" disabled={!history.length} onClick={() => setHistory((h) => h.slice(0, -1))}>Newer</button>
              <button type="button" disabled={requestsQuery.isFetching || !requestsQuery.data?.has_more || !requests.length} onClick={() => setHistory((h) => [...h, requests[requests.length - 1].id])}>Older</button>
              {beforeId !== 0 && <button type="button" onClick={() => setHistory([])}>Return to live</button>}
              <span>Column filters apply to these {requests.length} rows.</span>
            </div>
            {(requestsQuery.isError || sessionsQuery.isError || !connected) && (
              <div role="status" className="px-3 py-2 text-xs text-[#e3b341]">
                {requestsQuery.isError ? 'Request history could not be loaded. ' : ''}
                {sessionsQuery.isError ? 'Session counts are unavailable. ' : ''}
                {!connected ? 'Live stream disconnected; retrying. ' : ''}
                <button type="button" onClick={() => { void requestsQuery.refetch(); void sessionsQuery.refetch() }}>Retry history</button>
              </div>
            )}
            <div className="min-h-0 flex-1">
          <DataTable
            key={`${selectedSession}-${beforeId}`}
            columns={columns}
            data={requests}
            defaultSorting={[{ id: 'ts', desc: true }]}
            pageSize={50}
            getRowId={(row) => row.id}
            selectedRowId={selectedRequestId}
            onRowClick={(row) =>
              setSelectedRequestId(selectedRequestId === row.id ? null : row.id)
            }
            emptyMessage={
              requestsQuery.data?.unavailable
                ? 'Network store unavailable -- is agentjail-shield running?'
                : requestsQuery.isPending ? 'Loading request history...' : requestsQuery.isError ? 'Request history is unavailable.' : 'No requests captured for this session.'
            }
          />
            </div>
          </div>
          {selectedRequest ? (
            <RequestDetail
              req={selectedRequest}
              onClose={() => setSelectedRequestId(null)}
            />
          ) : reqParam ? (
            <div role="status" className="p-4 text-sm text-[#9ca3af]">
              {selectedRequestId === null ? 'Invalid request link.' : detailQuery.isError ? 'Request unavailable. It may have been removed by retention, or the network store is unavailable.' : 'Loading request...'}
              <button type="button" className="ml-3" onClick={() => setSelectedRequestId(null)}>Close</button>
              {detailQuery.isError && <button type="button" className="ml-3" onClick={() => void detailQuery.refetch()}>Retry</button>}
            </div>
          ) : <div />}
        </SplitPane>
      </SplitPane>
    </Layout>
  )
}
