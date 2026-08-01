import { useQuery } from '@tanstack/react-query'
import { AlertTriangle, CircleDollarSign } from 'lucide-react'
import { useSearchParams } from 'react-router-dom'

import { Layout } from '@/components/layout'
import { fetchCostSummary, type CostPeriod } from '@/lib/api'
import { cn } from '@/lib/utils'
import type { CostBudgetAlert } from '@/types'

const periods: CostPeriod[] = ['1d', '7d', '30d']

function usd(value: number | undefined): string {
  if (value == null) return '--'
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: 'USD',
    minimumFractionDigits: 2,
    maximumFractionDigits: value < 0.01 && value > 0 ? 4 : 2,
  }).format(value)
}

function tokens(value: number | undefined): string {
  if (value == null) return '--'
  return new Intl.NumberFormat('en-US', { notation: 'compact' }).format(value)
}

function projectName(project: string): string {
  const normalized = project.replaceAll('\\', '/')
  return normalized.split('/').filter(Boolean).at(-1) ?? project
}

function StatCard({ label, value, accent = false }: {
  label: string
  value: string
  accent?: boolean
}) {
  return (
    <div className="rounded-md border border-[#2a3040] bg-[#1a1f2e] px-5 py-4">
      <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-[#6b7280]">
        {label}
      </div>
      <div className={cn('text-2xl font-bold', accent ? 'text-[#56d364]' : 'text-[#f0f3f6]')}>
        {value}
      </div>
    </div>
  )
}

function ShareBar({ percent }: { percent: number }) {
  const width = Math.min(100, Math.max(0, percent || 0))
  return (
    <div className="flex min-w-28 items-center gap-2">
      <div className="h-2 flex-1 overflow-hidden rounded-full bg-[#131720]">
        <div className="h-full rounded-full bg-[#58a6ff]" style={{ width: `${width}%` }} />
      </div>
      <span className="w-11 text-right text-[10px] text-[#6b7280]">{percent.toFixed(1)}%</span>
    </div>
  )
}

function BudgetAlert({ alert }: { alert: CostBudgetAlert }) {
  const exceeded = alert.level === 'exceeded'
  return (
    <div className={cn(
      'flex items-start gap-3 rounded-md border px-4 py-3',
      exceeded
        ? 'border-[#6e2a2a] bg-[#2b171a] text-[#ff7b72]'
        : 'border-[#66531c] bg-[#292313] text-[#e3b341]',
    )}>
      <AlertTriangle size={16} className="mt-0.5 shrink-0" />
      <div className="min-w-0">
        <div className="text-xs font-semibold">{alert.message}</div>
        <div className="mt-1 text-[10px] opacity-75">
          {usd(alert.spent)} of {usd(alert.budget)} · {alert.scope}
        </div>
      </div>
    </div>
  )
}

export function CostPage() {
  const [searchParams, setSearchParams] = useSearchParams()
  const period = (searchParams.get('period') ?? '7d') as CostPeriod
  const selectedPeriod = periods.includes(period) ? period : '7d'
  const summaryQuery = useQuery({
    queryKey: ['cost-summary', selectedPeriod],
    queryFn: () => fetchCostSummary(selectedPeriod),
    staleTime: 30_000,
  })
  const summary = summaryQuery.data

  function selectPeriod(next: CostPeriod) {
    setSearchParams({ period: next })
  }

  const status = summary ? (
    <span className="text-xs">
      <span className="font-bold text-[#56d364]">{usd(summary.total_cost)}</span>{' '}
      <span className="text-[#6b7280]">over {summary.period}</span>
    </span>
  ) : undefined

  return (
    <Layout connected={!summaryQuery.isError} status={status}>
      <div className="h-full overflow-y-auto px-6 py-5">
        <div className="mx-auto max-w-7xl">
          <div className="mb-5 flex items-center justify-between">
            <div>
              <div className="flex items-center gap-2">
                <CircleDollarSign size={20} className="text-[#56d364]" />
                <h1 className="text-base font-semibold text-[#f0f3f6]">Cost analytics</h1>
              </div>
              <p className="mt-1 text-xs text-[#6b7280]">
                Local agent usage grouped by project and model.
              </p>
            </div>
            <div className="flex rounded-md border border-[#2a3040] bg-[#1a1f2e] p-1">
              {periods.map((item) => (
                <button
                  key={item}
                  type="button"
                  onClick={() => selectPeriod(item)}
                  className={cn(
                    'rounded px-3 py-1.5 text-[11px] font-semibold transition-colors',
                    item === selectedPeriod
                      ? 'bg-[#0f1f3d] text-[#58a6ff]'
                      : 'text-[#8b949e] hover:text-[#c9d1d9]',
                  )}
                >
                  {item}
                </button>
              ))}
            </div>
          </div>

          {summaryQuery.isPending && (
            <div className="rounded-md border border-[#2a3040] bg-[#1a1f2e] py-16 text-center text-xs text-[#6b7280]">
              Reading local transcripts...
            </div>
          )}

          {summaryQuery.isError && (
            <div className="rounded-md border border-[#6e2a2a] bg-[#2b171a] py-12 text-center">
              <div className="text-sm font-semibold text-[#ff7b72]">Cost data is unavailable</div>
              <div className="mt-2 text-xs text-[#9ca3af]">{summaryQuery.error.message}</div>
              <button
                type="button"
                onClick={() => summaryQuery.refetch()}
                className="mt-4 rounded border border-[#3b4252] px-3 py-1.5 text-xs text-[#c9d1d9] hover:border-[#58a6ff]"
              >
                Retry
              </button>
            </div>
          )}

          {summary && (
            <>
              {summary.budget_alerts.map((alert, index) => (
                <div className="mb-3" key={`${alert.scope}-${alert.level}-${index}`}>
                  <BudgetAlert alert={alert} />
                </div>
              ))}

              <div className="mb-5 grid grid-cols-1 gap-3 sm:grid-cols-3">
                <StatCard label="Total spend" value={usd(summary.total_cost)} accent />
                <StatCard label="Sessions" value={summary.session_count.toLocaleString()} />
                <StatCard label="Average / session" value={usd(summary.avg_cost_per_session)} accent />
              </div>

              {summary.session_count === 0 ? (
                <div className="rounded-md border border-[#2a3040] bg-[#1a1f2e] py-16 text-center">
                  <div className="text-sm font-semibold text-[#c9d1d9]">No cost data for this period</div>
                  <div className="mt-2 text-xs text-[#6b7280]">
                    Claude Code, Codex, and OpenCode sessions appear here after their usage is discovered.
                  </div>
                </div>
              ) : (
                <>
                  <div className="mb-5 grid grid-cols-1 gap-5 xl:grid-cols-2">
                    <section className="overflow-hidden rounded-md border border-[#2a3040] bg-[#1a1f2e]">
                      <h2 className="border-b border-[#2a3040] px-4 py-3 text-[10px] font-semibold uppercase tracking-wider text-[#9ca3af]">
                        Cost by project
                      </h2>
                      <div className="overflow-x-auto">
                        <table className="w-full text-left text-xs">
                          <thead className="text-[10px] uppercase text-[#6b7280]">
                            <tr><th className="px-4 py-2">Project</th><th className="px-4 py-2 text-right">Cost</th><th className="px-4 py-2">Share</th><th className="px-4 py-2 text-right">Sessions</th></tr>
                          </thead>
                          <tbody>
                            {summary.by_project.map((project) => (
                              <tr className="border-t border-[#242a38]" key={project.project}>
                                <td className="max-w-64 truncate px-4 py-3 text-[#c9d1d9]" title={project.project}>{projectName(project.project)}</td>
                                <td className="px-4 py-3 text-right font-semibold text-[#56d364]">{usd(project.cost_usd)}</td>
                                <td className="px-4 py-3"><ShareBar percent={project.percent} /></td>
                                <td className="px-4 py-3 text-right text-[#9ca3af]">{project.session_count}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </section>

                    <section className="overflow-hidden rounded-md border border-[#2a3040] bg-[#1a1f2e]">
                      <h2 className="border-b border-[#2a3040] px-4 py-3 text-[10px] font-semibold uppercase tracking-wider text-[#9ca3af]">
                        Cost by model
                      </h2>
                      <div className="overflow-x-auto">
                        <table className="w-full text-left text-xs">
                          <thead className="text-[10px] uppercase text-[#6b7280]">
                            <tr><th className="px-4 py-2">Model</th><th className="px-4 py-2 text-right">Cost</th><th className="px-4 py-2">Share</th><th className="px-4 py-2 text-right">Sessions</th><th className="px-4 py-2 text-right">Input</th><th className="px-4 py-2 text-right">Output</th></tr>
                          </thead>
                          <tbody>
                            {summary.by_model.map((model) => (
                              <tr className="border-t border-[#242a38]" key={model.model}>
                                <td className="max-w-64 truncate px-4 py-3 text-[#c9d1d9]" title={model.model}>{model.model}</td>
                                <td className="px-4 py-3 text-right font-semibold text-[#56d364]">{usd(model.cost_usd)}</td>
                                <td className="px-4 py-3"><ShareBar percent={model.percent} /></td>
                                <td className="px-4 py-3 text-right text-[#9ca3af]">{model.session_count}</td>
                                <td className="px-4 py-3 text-right text-[#9ca3af]">{tokens(model.input_tokens)}</td>
                                <td className="px-4 py-3 text-right text-[#9ca3af]">{tokens(model.output_tokens)}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </section>
                  </div>

                  <section className="rounded-md border border-[#2a3040] bg-[#1a1f2e]">
                    <h2 className="border-b border-[#2a3040] px-4 py-3 text-[10px] font-semibold uppercase tracking-wider text-[#9ca3af]">
                      Token efficiency
                    </h2>
                    <div className="grid grid-cols-1 gap-6 px-5 py-4 sm:grid-cols-3">
                      <div>
                        <div className="text-[10px] text-[#6b7280]">Cache hit rate</div>
                        <div className="mt-2 flex items-center gap-3">
                          <span className="font-semibold text-[#56d364]">{summary.cache_hit_rate.toFixed(1)}%</span>
                          <ShareBar percent={summary.cache_hit_rate} />
                        </div>
                      </div>
                      <div><div className="text-[10px] text-[#6b7280]">Average input / session</div><div className="mt-2 font-semibold text-[#c9d1d9]">{tokens(summary.avg_input_tokens)}</div></div>
                      <div><div className="text-[10px] text-[#6b7280]">Average output / session</div><div className="mt-2 font-semibold text-[#c9d1d9]">{tokens(summary.avg_output_tokens)}</div></div>
                    </div>
                  </section>
                </>
              )}
            </>
          )}
        </div>
      </div>
    </Layout>
  )
}
