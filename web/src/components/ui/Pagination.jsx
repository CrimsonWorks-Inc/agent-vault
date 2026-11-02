import { ChevronLeftIcon, ChevronRightIcon } from '@heroicons/react/16/solid'
import { PAGE_SIZES } from '../../lib/paging.js'
import { cx } from '../../lib/cx.js'
import { Button } from './Button.jsx'
import { Select } from './Select.jsx'

/**
 * Prev and Next, "Showing 26–50 of 312" when the total is known, and the page
 * size (25/50/100, remembered by usePaged). Spread `usePaged(...).pagination`
 * into it.
 */
export function Pagination({ page, limit, hasNext, hasPrev, onNext, onPrev, onLimitChange, range, loading = false, className, label = 'Pagination' }) {
  return (
    <nav aria-label={label} className={cx('flex flex-col-reverse gap-3 px-1 py-3 sm:flex-row sm:items-center sm:justify-between', className)}>
      <div className="flex items-center gap-3 text-sm text-muted">
        <span aria-live="polite" className="tabular-nums">{range?.text}</span>
        {onLimitChange && (
          <span className="flex items-center gap-2">
            <span aria-hidden="true" className="hidden sm:inline">Per page</span>
            <Select
              aria-label="Rows per page"
              value={limit}
              onChange={onLimitChange}
              options={PAGE_SIZES.map((n) => ({ value: n, label: String(n) }))}
              className="w-20"
              up
            />
          </span>
        )}
      </div>
      <div className="flex items-center gap-2">
        <span className="mr-1 text-sm tabular-nums text-muted" aria-hidden="true">Page {page}</span>
        <Button size="sm" icon={ChevronLeftIcon} onClick={onPrev} disabled={!hasPrev || loading} aria-label="Previous page">Prev</Button>
        <Button size="sm" onClick={onNext} disabled={!hasNext || loading} aria-label="Next page">
          Next<ChevronRightIcon aria-hidden="true" />
        </Button>
      </div>
    </nav>
  )
}
