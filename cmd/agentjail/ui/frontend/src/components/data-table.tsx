import * as React from 'react'
import {
  type ColumnDef,
  type ColumnFiltersState,
  type SortingState,
  type VisibilityState,
  flexRender,
  getCoreRowModel,
  getFacetedUniqueValues,
  getFilteredRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  useReactTable,
} from '@tanstack/react-table'
import { ChevronDown, SlidersHorizontal } from 'lucide-react'

import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'

/** Multi-select facet filter: column value must be in the selected set. */
function arrIncludesSome<TData>(row: { getValue(columnId: string): unknown }, columnId: string, filterValue: string[]) {
  if (!filterValue?.length) return true
  const value = row.getValue(columnId)
  return filterValue.includes(String(value))
}
arrIncludesSome.autoRemove = (val: string[]) => !val?.length

interface DataTableProps<TData, TValue> {
  columns: ColumnDef<TData, TValue>[]
  data: TData[]
  pageSize?: number
  onRowClick?: (row: TData) => void
  selectedRowId?: number | string | null
  getRowId?: (row: TData, index: number) => string | number
  emptyMessage?: string
  meta?: Record<string, unknown>
}

export function DataTable<TData, TValue>({
  columns,
  data,
  pageSize = 50,
  onRowClick,
  selectedRowId,
  getRowId,
  emptyMessage = 'No results.',
  meta,
}: DataTableProps<TData, TValue>) {
  const [sorting, setSorting] = React.useState<SortingState>([])
  const [columnFilters, setColumnFilters] = React.useState<ColumnFiltersState>(
    [],
  )
  const [columnVisibility, setColumnVisibility] =
    React.useState<VisibilityState>({})
  const [pagination, setPagination] = React.useState({
    pageIndex: 0,
    pageSize,
  })

  const columnsWithFilterFn = React.useMemo<ColumnDef<TData, TValue>[]>(
    () =>
      columns.map((c) => ({
        ...c,
        filterFn: c.filterFn ?? (arrIncludesSome as never),
      })),
    [columns],
  )

  const table = useReactTable({
    data,
    columns: columnsWithFilterFn,
    meta,
    state: {
      sorting,
      columnFilters,
      columnVisibility,
      pagination,
    },
    onSortingChange: setSorting,
    onColumnFiltersChange: setColumnFilters,
    onColumnVisibilityChange: setColumnVisibility,
    onPaginationChange: setPagination,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    getFacetedUniqueValues: getFacetedUniqueValues(),
    getRowId: getRowId
      ? (row, index) => String(getRowId(row, index))
      : undefined,
    enableColumnResizing: true,
    columnResizeMode: 'onChange',
    columnResizeDirection: 'ltr',
  })

  const rows = table.getRowModel().rows
  const pageCount = table.getPageCount()
  const pageIndex = table.getState().pagination.pageIndex

  return (
    <div className="flex h-full flex-col">
      <div className="flex flex-none items-center justify-between gap-2 border-b border-[#2a3040] px-3 py-1.5">
        <div className="text-[11px] text-[#6b7280]">
          {table.getFilteredRowModel().rows.length} row
          {table.getFilteredRowModel().rows.length === 1 ? '' : 's'}
        </div>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              variant="outline"
              size="sm"
              className="h-7 gap-1 border-[#2a3040] bg-transparent text-xs text-[#9ca3af] hover:bg-[#1c2333] hover:text-[#f0f3f6]"
            >
              <SlidersHorizontal className="h-3 w-3" />
              Columns
              <ChevronDown className="h-3 w-3" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent
            align="end"
            className="border-[#2a3040] bg-[#1a1f2e] text-[#f0f3f6]"
          >
            {table
              .getAllColumns()
              .filter((column) => column.getCanHide())
              .map((column) => (
                <DropdownMenuCheckboxItem
                  key={column.id}
                  className="capitalize"
                  checked={column.getIsVisible()}
                  onCheckedChange={(value) => column.toggleVisibility(!!value)}
                  onSelect={(e) => e.preventDefault()}
                >
                  {(column.columnDef.meta as { label?: string } | undefined)
                    ?.label ?? column.id}
                </DropdownMenuCheckboxItem>
              ))}
          </DropdownMenuContent>
        </DropdownMenu>
      </div>

      <div className="min-h-0 flex-1 overflow-auto">
        <Table style={{ width: '100%', tableLayout: 'fixed' }}>
          <TableHeader className="sticky top-0 z-10 bg-[#131720]">
            {table.getHeaderGroups().map((headerGroup) => (
              <TableRow
                key={headerGroup.id}
                className="border-[#2a3040] hover:bg-transparent"
              >
                {headerGroup.headers.map((header) => (
                  <TableHead
                    key={header.id}
                    className="relative h-9 pr-3 text-[#9ca3af]"
                    style={header.getSize() < 10000 ? { width: header.getSize() } : undefined}
                  >
                    {header.isPlaceholder
                      ? null
                      : flexRender(
                          header.column.columnDef.header,
                          header.getContext(),
                        )}
                    {header.column.getCanResize() && (
                      <div
                        onDoubleClick={() => header.column.resetSize()}
                        onMouseDown={header.getResizeHandler()}
                        onTouchStart={header.getResizeHandler()}
                        className={cn(
                          'col-resize-handle',
                          header.column.getIsResizing() && 'active',
                        )}
                      />
                    )}
                  </TableHead>
                ))}
              </TableRow>
            ))}
          </TableHeader>
          <TableBody>
            {rows.length ? (
              rows.map((row) => (
                <TableRow
                  key={row.id}
                  data-state={
                    selectedRowId != null && row.id === String(selectedRowId)
                      ? 'selected'
                      : undefined
                  }
                  onClick={() => onRowClick?.(row.original)}
                  style={onRowClick ? { cursor: 'pointer' } : undefined}
                  className={cn(
                    'border-[#1c2333] hover:bg-[#1c2333]',
                    onRowClick && 'cursor-pointer',
                    selectedRowId != null &&
                      row.id === String(selectedRowId) &&
                      'bg-[#1c2333]',
                  )}
                >
                  {row.getVisibleCells().map((cell) => (
                    <TableCell
                      key={cell.id}
                      className="py-1.5 overflow-hidden text-ellipsis"
                      style={cell.column.getSize() < 10000 ? { width: cell.column.getSize() } : undefined}
                    >
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </TableCell>
                  ))}
                </TableRow>
              ))
            ) : (
              <TableRow className="hover:bg-transparent">
                <TableCell
                  colSpan={columns.length}
                  className="h-24 text-center text-[#6b7280]"
                >
                  {emptyMessage}
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </div>

      <div className="flex flex-none items-center justify-between gap-4 border-t border-[#2a3040] px-3 py-1.5 text-xs text-[#9ca3af]">
        <div className="flex items-center gap-2">
          <span>Rows per page</span>
          <Select
            value={String(table.getState().pagination.pageSize)}
            onValueChange={(value) => table.setPageSize(Number(value))}
          >
            <SelectTrigger className="h-7 w-[70px] border-[#2a3040] bg-transparent text-xs">
              <SelectValue />
            </SelectTrigger>
            <SelectContent className="border-[#2a3040] bg-[#1a1f2e] text-[#f0f3f6]">
              {[50, 100, 200].map((size) => (
                <SelectItem key={size} value={String(size)}>
                  {size}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="flex items-center gap-3">
          <span>
            Page {pageCount === 0 ? 0 : pageIndex + 1} of {pageCount}
          </span>
          <div className="flex items-center gap-1">
            <Button
              variant="outline"
              size="sm"
              className="h-7 border-[#2a3040] bg-transparent px-2 text-xs hover:bg-[#1c2333]"
              onClick={() => table.previousPage()}
              disabled={!table.getCanPreviousPage()}
            >
              Prev
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="h-7 border-[#2a3040] bg-transparent px-2 text-xs hover:bg-[#1c2333]"
              onClick={() => table.nextPage()}
              disabled={!table.getCanNextPage()}
            >
              Next
            </Button>
          </div>
        </div>
      </div>
    </div>
  )
}
