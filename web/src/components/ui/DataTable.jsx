import { isValidElement } from 'react'
import { ChevronDownIcon, ChevronUpDownIcon, ChevronUpIcon } from '@heroicons/react/16/solid'
import { cx } from '../../lib/cx.js'
import { Skeleton } from './Skeleton.jsx'
import { EmptyState } from './EmptyState.jsx'

/**
 * A list as a table on md and up, and as cards below it.
 *
 * columns: [{
 *   key,                       // the field, and the React key
 *   header,                    // node: the header slot (text, a checkbox, anything)
 *   cell?: (row) => node,      // defaults to row[key] as text
 *   sortable?: boolean,        // header becomes a button; onSort(key) is called
 *   align?: 'left' | 'right',
 *   primary?: boolean,         // on a card, this column is the title line
 *   hideOnCard?: boolean,      // left off the card (actions usually stay)
 *   className?: string,
 * }]
 * rows, rowKey (a field name or (row) => key), loading, empty (node or
 * {title, body, icon, action}), sort ({ key, dir: 'asc' | 'desc' }), onSort,
 * caption (read to screen readers), rowClassName ((row) => classes).
 */
export function DataTable({
  columns, rows = [], rowKey = 'id', loading = false, empty, sort = null, onSort, caption,
  skeletonRows = 5, rowClassName, className,
}) {
  const keyOf = (row, i) => (typeof rowKey === 'function' ? rowKey(row, i) : row?.[rowKey] ?? i)
  const cellOf = (col, row) => (col.cell ? col.cell(row) : row?.[col.key] == null ? '' : String(row[col.key]))
  const showSkeleton = loading && rows.length === 0
  const showEmpty = !loading && rows.length === 0
  const primary = columns.find((c) => c.primary) || columns[0]

  return (
    <div className={cx('relative', className)} aria-busy={loading || undefined}>
      {loading && rows.length > 0 && (
        <div aria-hidden="true" className="absolute inset-x-0 top-0 z-10 h-0.5 animate-shimmer bg-accent" />
      )}

      {/* md and up: a table */}
      <table className="hidden w-full border-collapse text-sm md:table">
        {caption && <caption className="sr-only">{caption}</caption>}
        <thead>
          <tr className="border-b border-line">
            {columns.map((col) => {
              const active = sort?.key === col.key
              const dir = active ? sort.dir : null
              return (
                <th
                  key={col.key}
                  scope="col"
                  aria-sort={active ? (dir === 'asc' ? 'ascending' : 'descending') : col.sortable ? 'none' : undefined}
                  className={cx(
                    'px-4 py-2.5 font-mono text-eyebrow font-medium uppercase tracking-[0.12em] text-muted whitespace-nowrap',
                    col.align === 'right' ? 'text-right' : 'text-left', col.className,
                  )}
                >
                  {col.sortable && onSort ? (
                    <button
                      type="button"
                      onClick={() => onSort(col.key)}
                      className="inline-flex items-center gap-1 uppercase tracking-[0.12em] hover:text-ink focus:outline-none focus-visible:outline-2 focus-visible:outline-focus"
                    >
                      {col.header}
                      {dir === 'asc' ? <ChevronUpIcon aria-hidden="true" className="size-3.5" />
                        : dir === 'desc' ? <ChevronDownIcon aria-hidden="true" className="size-3.5" />
                          : <ChevronUpDownIcon aria-hidden="true" className="size-3.5 opacity-50" />}
                    </button>
                  ) : col.header}
                </th>
              )
            })}
          </tr>
        </thead>
        <tbody>
          {showSkeleton && Array.from({ length: skeletonRows }, (_, i) => (
            <tr key={`s${i}`} className="border-b border-line last:border-b-0">
              {columns.map((col) => (
                <td key={col.key} className="px-4 py-3.5"><Skeleton className={i % 2 ? 'w-2/3' : 'w-1/2'} /></td>
              ))}
            </tr>
          ))}
          {rows.map((row, i) => (
            <tr key={keyOf(row, i)} className={cx('border-b border-line last:border-b-0 transition-colors hover:bg-sunken/50', rowClassName?.(row))}>
              {columns.map((col) => (
                <td key={col.key} className={cx('px-4 py-3 align-middle text-ink', col.align === 'right' && 'text-right', col.className)}>
                  {cellOf(col, row)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>

      {/* below md: cards */}
      <ul className="divide-y divide-line md:hidden" aria-label={caption}>
        {showSkeleton && Array.from({ length: Math.min(skeletonRows, 3) }, (_, i) => (
          <li key={`s${i}`} className="space-y-2 px-4 py-4"><Skeleton className="w-1/2" /><Skeleton className="w-3/4" /></li>
        ))}
        {rows.map((row, i) => (
          <li key={keyOf(row, i)} className={cx('px-4 py-4', rowClassName?.(row))}>
            <div className="font-medium text-ink">{cellOf(primary, row)}</div>
            <dl className="mt-2 grid grid-cols-[max-content_1fr] gap-x-3 gap-y-1.5 text-sm">
              {columns.filter((c) => c !== primary && !c.hideOnCard).map((col) => (
                <div key={col.key} className="contents">
                  <dt className="font-mono text-eyebrow uppercase leading-5 tracking-[0.12em] text-muted">{col.header}</dt>
                  <dd className="min-w-0 break-words text-ink">{cellOf(col, row)}</dd>
                </div>
              ))}
            </dl>
          </li>
        ))}
      </ul>

      {showSkeleton && <span className="sr-only" role="status">Loading</span>}
      {showEmpty && (empty && typeof empty === 'object' && !isValidElement(empty)
        ? <EmptyState icon={empty.icon} title={empty.title} action={empty.action}>{empty.body}</EmptyState>
        : empty ?? <EmptyState title="Nothing here yet" />)}
    </div>
  )
}
