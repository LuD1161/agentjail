import * as React from 'react'
import { useQuery } from '@tanstack/react-query'
import type { ColumnDef } from '@tanstack/react-table'

import { Shield, Terminal, FileText, Globe, Plug } from 'lucide-react'
import { Highlight, themes } from 'prism-react-renderer'
import { cn } from '@/lib/utils'
import { Layout } from '@/components/layout'
import { SplitPane } from '@/components/split-pane'
import { DataTable } from '@/components/data-table'
import { DataTableColumnHeader } from '@/components/data-table-column-header'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Badge } from '@/components/ui/badge'
import { BrandIcon, hasBrandIcon } from '@/components/brand-icons'
import type { RuleInfo } from '@/types'

async function fetchRules(): Promise<RuleInfo[]> {
  const res = await fetch('/api/rules')
  if (!res.ok) return []
  return res.json()
}

async function fetchPolicyConfig(): Promise<Record<string, unknown>> {
  const res = await fetch('/api/policy/config')
  if (!res.ok) return {}
  return res.json()
}

function RuleIcon({ name }: { name: string }) {
  if (hasBrandIcon(name)) return <BrandIcon name={name} />
  const n = name.toLowerCase()
  if (n.includes('command') || n.includes('shell') || n.includes('launchctl')) return <Terminal size={16} className="shrink-0 text-[#56d364]" />
  if (n.includes('file') || n.includes('history') || n.includes('binary')) return <FileText size={16} className="shrink-0 text-[#e3b341]" />
  if (n.includes('mcp') || n.includes('internal_tools')) return <Plug size={16} className="shrink-0 text-[#bc8cff]" />
  if (n.includes('web') || n.includes('resolver')) return <Globe size={16} className="shrink-0 text-[#9ca3af]" />
  return <Shield size={16} className="shrink-0 text-[#58a6ff]" />
}

const columns: ColumnDef<RuleInfo>[] = [
  {
    accessorKey: 'name',
    header: ({ column }) => <DataTableColumnHeader column={column} title="Rule" filterable={false} />,
    cell: ({ row }) => (
      <div className="flex items-center gap-2">
        <RuleIcon name={row.original.name} />
        <span className="text-xs font-semibold text-[#c9d1d9]">{row.original.name}</span>
      </div>
    ),
  },
  {
    accessorKey: 'source',
    header: ({ column }) => <DataTableColumnHeader column={column} title="Source" />,
    cell: ({ row }) => {
      const src = row.original.source
      const cls = src === 'core'
        ? 'border-[#1e3f6e] bg-[#0f1f3d] text-[#58a6ff]'
        : 'border-[#352555] bg-[#1f1530] text-[#bc8cff]'
      return <Badge variant="outline" className={cn('text-[10px]', cls)}>{src}</Badge>
    },
    size: 100,
  },
  {
    accessorKey: 'enabled',
    header: ({ column }) => <DataTableColumnHeader column={column} title="Status" />,
    cell: ({ row }) => (
      <span className={cn(
        'text-xs font-semibold',
        row.original.enabled ? 'text-[#56d364]' : 'text-[#6b7280]',
      )}>
        {row.original.enabled ? 'enabled' : 'disabled'}
      </span>
    ),
    size: 100,
  },
  {
    accessorKey: 'editable',
    header: ({ column }) => <DataTableColumnHeader column={column} title="Editable" filterable={false} />,
    cell: ({ row }) => (
      <span className="text-xs text-[#6b7280]">
        {row.original.editable ? 'yes' : 'no'}
      </span>
    ),
    size: 80,
  },
]

export function PoliciesPage() {
  const [selectedRule, setSelectedRule] = React.useState<RuleInfo | null>(null)

  const rulesQuery = useQuery({
    queryKey: ['rules'],
    queryFn: fetchRules,
    refetchInterval: 30000,
  })

  const configQuery = useQuery({
    queryKey: ['policy-config'],
    queryFn: fetchPolicyConfig,
    refetchInterval: 30000,
  })

  const rules = rulesQuery.data ?? []
  const enabledCount = rules.filter((r) => r.enabled).length
  const coreCount = rules.filter((r) => r.source === 'core').length
  const libCount = rules.filter((r) => r.source === 'library').length

  // Extract the config section relevant to the selected rule
  const ruleConfig = React.useMemo(() => {
    if (!selectedRule || !configQuery.data) return null
    const cfg = configQuery.data as Record<string, unknown>
    const name = selectedRule.name.toLowerCase()
    // Try to find a matching config section
    for (const [key, val] of Object.entries(cfg)) {
      if (key.toLowerCase().includes(name.replace(/_/g, '').replace('policy', ''))
        || name.includes(key.toLowerCase())) {
        return { [key]: val }
      }
    }
    // Special mappings
    if (name.includes('command')) return { Commands: cfg.Commands ?? cfg.commands }
    if (name.includes('file')) return { Files: cfg.Files ?? cfg.files }
    if (name.includes('mcp')) return { MCP: cfg.MCP ?? cfg.mcp }
    if (name.includes('aws')) return { AWS: cfg.AWS ?? cfg.aws }
    if (name.includes('web')) return { Web: cfg.Web ?? cfg.web }
    return cfg
  }, [selectedRule, configQuery.data])

  const status = (
    <>
      <span className="text-xs">
        <span className="font-bold text-[#56d364]">{enabledCount}</span>{' '}
        <span className="text-[#6b7280]">enabled</span>
      </span>
      <span className="text-xs">
        <span className="font-bold text-[#58a6ff]">{coreCount}</span>{' '}
        <span className="text-[#6b7280]">core</span>
      </span>
      <span className="text-xs">
        <span className="font-bold text-[#bc8cff]">{libCount}</span>{' '}
        <span className="text-[#6b7280]">library</span>
      </span>
    </>
  )

  return (
    <Layout connected={true} status={status}>
      <SplitPane direction="vertical" defaultSize={selectedRule ? 350 : 9999} minSize={200} maxSize={600}>
        <DataTable
          columns={columns}
          data={rules}
          pageSize={100}
          getRowId={(row) => row.name}
          selectedRowId={selectedRule?.name ?? null}
          onRowClick={setSelectedRule}
          emptyMessage="No rules loaded."
        />
        {selectedRule ? (
          <div className="flex h-full flex-col overflow-hidden border-t-2 border-[#58a6ff]">
            <div className="flex items-center gap-3 border-b border-[#2a3040] px-4 py-2 shrink-0">
              <RuleIcon name={selectedRule.name} />
              <span className="text-xs font-semibold text-[#f0f3f6]">{selectedRule.name}</span>
              <Badge variant="outline" className={cn(
                'text-[10px]',
                selectedRule.source === 'core'
                  ? 'border-[#1e3f6e] bg-[#0f1f3d] text-[#58a6ff]'
                  : 'border-[#352555] bg-[#1f1530] text-[#bc8cff]',
              )}>{selectedRule.source}</Badge>
              <span className={cn(
                'text-xs font-semibold',
                selectedRule.enabled ? 'text-[#56d364]' : 'text-[#6b7280]',
              )}>
                {selectedRule.enabled ? 'enabled' : 'disabled'}
              </span>
              {selectedRule.editable && (
                <span className="text-[10px] text-[#6b7280]">editable</span>
              )}
              <span className="flex-1" />
              <button
                onClick={() => setSelectedRule(null)}
                className="text-sm text-[#6b7280] hover:text-[#ff7b72]"
              >x</button>
            </div>
            <div className="flex min-h-0 flex-1">
              <ScrollArea className="flex-1 border-r border-[#2a3040]">
                <div className="p-4">
                  <div className="mb-2 text-[10px] font-semibold uppercase text-[#6b7280]">Rule Details</div>
                  <div className="space-y-1.5 text-xs">
                    <div><span className="text-[#58a6ff]">Name:</span> <span className="text-[#c9d1d9]">{selectedRule.name}</span></div>
                    <div><span className="text-[#58a6ff]">Source:</span> <span className="text-[#c9d1d9]">{selectedRule.source}</span></div>
                    <div><span className="text-[#58a6ff]">Status:</span> <span className={selectedRule.enabled ? 'text-[#56d364]' : 'text-[#6b7280]'}>{selectedRule.enabled ? 'enabled' : 'disabled'}</span></div>
                    <div><span className="text-[#58a6ff]">Editable:</span> <span className="text-[#c9d1d9]">{selectedRule.editable ? 'yes' : 'no'}</span></div>
                  </div>
                </div>
              </ScrollArea>
              <ScrollArea className="flex-1">
                <div className="p-4">
                  <div className="mb-2 text-[10px] font-semibold uppercase text-[#6b7280]">Configuration</div>
                  <Highlight
                    theme={themes.vsDark}
                    code={JSON.stringify(ruleConfig ?? {}, null, 2)}
                    language="json"
                  >
                    {({ tokens, getLineProps, getTokenProps }) => (
                      <pre className="whitespace-pre-wrap break-all text-xs" style={{ background: 'transparent' }}>
                        {tokens.map((line, i) => (
                          <div key={i} {...getLineProps({ line })}>
                            {line.map((token, j) => (
                              <span key={j} {...getTokenProps({ token })} />
                            ))}
                          </div>
                        ))}
                      </pre>
                    )}
                  </Highlight>
                </div>
              </ScrollArea>
            </div>
          </div>
        ) : (
          <div />
        )}
      </SplitPane>
    </Layout>
  )
}
