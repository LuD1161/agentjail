import * as React from 'react'
import type { Column } from '@tanstack/react-table'
import { ArrowDown, ArrowUp, ChevronsUpDown, Filter } from 'lucide-react'

import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from '@/components/ui/popover'
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from '@/components/ui/command'

interface DataTableColumnHeaderProps<TData, TValue>
  extends React.HTMLAttributes<HTMLDivElement> {
  column: Column<TData, TValue>
  title: string
  filterable?: boolean
  facetCounts?: Record<string, number>
}

export function DataTableColumnHeader<TData, TValue>({
  column,
  title,
  filterable = true,
  facetCounts,
  className,
}: DataTableColumnHeaderProps<TData, TValue>) {
  const sorted = column.getIsSorted()
  const canSort = column.getCanSort()
  const canFilter = filterable && column.getCanFilter()

  const facets = canFilter ? column.getFacetedUniqueValues() : undefined
  const filterValue = (column.getFilterValue() as string[] | undefined) ?? []
  const isFiltered = filterValue.length > 0
  const selectedValues = new Set(filterValue)

  const options = React.useMemo(() => {
    if (!facets) return []
    return Array.from(facets.keys())
      .filter((v) => v !== undefined && v !== null && v !== '')
      .sort((a, b) => String(a).localeCompare(String(b)))
  }, [facets])

  function toggleValue(value: string) {
    if (!isFiltered) {
      // No filter active (all shown). First click = show all EXCEPT this one.
      const allExcept = options
        .map(String)
        .filter((v) => v !== value)
      column.setFilterValue(allExcept.length > 0 ? allExcept : undefined)
    } else {
      const next = new Set(selectedValues)
      if (next.has(value)) {
        next.delete(value)
      } else {
        next.add(value)
      }
      // If all are re-selected, clear the filter entirely
      if (next.size >= options.length) {
        column.setFilterValue(undefined)
      } else {
        column.setFilterValue(next.size ? Array.from(next) : undefined)
      }
    }
  }

  function clearFilter() {
    column.setFilterValue(undefined)
  }

  function isChecked(value: string): boolean {
    if (!isFiltered) return true
    return selectedValues.has(value)
  }

  return (
    <div className={cn('flex items-center gap-1 select-none', className)}>
      <button
        type="button"
        disabled={!canSort}
        onClick={() => {
          if (!canSort) return
          if (sorted === 'asc') column.toggleSorting(true)
          else if (sorted === 'desc') column.clearSorting()
          else column.toggleSorting(false)
        }}
        className={cn(
          'flex items-center gap-1 text-xs font-semibold uppercase tracking-wider text-[#9ca3af] hover:text-[#f0f3f6]',
          canSort && 'cursor-pointer',
        )}
      >
        <span>{title}</span>
        {canSort &&
          (sorted === 'asc' ? (
            <ArrowUp className="h-3 w-3" />
          ) : sorted === 'desc' ? (
            <ArrowDown className="h-3 w-3" />
          ) : (
            <ChevronsUpDown className="h-3 w-3 opacity-40" />
          ))}
      </button>

      {canFilter && (
        <Popover>
          <PopoverTrigger asChild>
            <Button
              variant="ghost"
              size="icon"
              className={cn(
                'h-4 w-4 p-0 opacity-60 hover:opacity-100',
                isFiltered && 'text-[#58a6ff] opacity-100',
              )}
            >
              <Filter className="h-3 w-3" />
            </Button>
          </PopoverTrigger>
          <PopoverContent
            align="start"
            className="w-56 border-[#2a3040] bg-[#1a1f2e] p-0 text-[#f0f3f6]"
          >
            <Command className="bg-transparent">
              <CommandInput placeholder={`Filter ${title.toLowerCase()}...`} />
              <CommandList>
                <CommandEmpty>No values.</CommandEmpty>
                <CommandGroup>
                  {options.map((value) => {
                    const strValue = String(value)
                    const checked = isChecked(strValue)
                    return (
                      <CommandItem
                        key={strValue}
                        onSelect={() => toggleValue(strValue)}
                        className="flex items-center gap-2"
                      >
                        <Checkbox checked={checked} className="pointer-events-none" />
                        <span className="flex-1 truncate">{strValue}</span>
                        <span className="text-[10px] text-[#6b7280]">
                          {facetCounts?.[strValue] ?? facets?.get(value) ?? 0}
                        </span>
                      </CommandItem>
                    )
                  })}
                </CommandGroup>
              </CommandList>
              {isFiltered && (
                <div className="border-t border-[#2a3040] p-1">
                  <Button
                    variant="ghost"
                    size="sm"
                    className="w-full justify-center text-xs text-[#9ca3af] hover:text-white"
                    onClick={clearFilter}
                  >
                    Show all
                  </Button>
                </div>
              )}
            </Command>
          </PopoverContent>
        </Popover>
      )}
    </div>
  )
}
