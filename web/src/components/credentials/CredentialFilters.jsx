import { XMarkIcon } from '@heroicons/react/16/solid'
import { cx } from '../../lib/cx.js'
import { cleanLine } from '../../lib/text.js'
import { Select } from '../ui/Select.jsx'

/** The statuses the daemon can narrow to (list_paging.rs CREDENTIAL_STATUSES). */
export const STATUSES = [
  { value: 'attention', label: 'Needs attention', hint: 'the last check was refused (401 or 403)' },
  { value: 'expiring', label: 'Expiring', hint: 'expired, or expires soon' },
  { value: 'quarantined', label: 'Quarantined', hint: 'nothing can use it until it is released' },
  { value: 'untested', label: 'Never checked', hint: 'no probe or response has been seen' },
]
export const SORTS = [
  { value: 'name', label: 'Name' },
  { value: 'folder', label: 'Folder' },
  { value: 'created', label: 'Newest first' },
  { value: 'checked', label: 'Last checked' },
]

export const NO_FILTERS = { status: [], kind: '', sort: 'name' }
export const isFiltered = (f) => f.status.length > 0 || Boolean(f.kind)

/**
 * Status chips (any of them), the connector kind, and the order. Chips are
 * toggle buttons, so a screen reader hears pressed or not.
 */
export function CredentialFilters({ filters, onChange, kinds = [] }) {
  const toggle = (v) => onChange({
    ...filters,
    status: filters.status.includes(v) ? filters.status.filter((s) => s !== v) : [...filters.status, v],
  })
  return (
    <div className="flex flex-wrap items-center gap-2">
      <div role="group" aria-label="Status" className="flex flex-wrap gap-1.5">
        {STATUSES.map((s) => {
          const on = filters.status.includes(s.value)
          return (
            <button
              key={s.value}
              type="button"
              aria-pressed={on}
              title={s.hint}
              onClick={() => toggle(s.value)}
              className={cx(
                'inline-flex h-7 items-center gap-1 rounded-pill border px-2.5 text-xs font-medium transition-colors',
                'focus:outline-none focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-focus',
                on ? 'border-accent/40 bg-accent-soft text-accent' : 'border-line bg-surface text-muted hover:text-ink hover:border-line-strong',
              )}
            >
              {s.label}
            </button>
          )
        })}
      </div>
      <div className="ml-auto flex flex-wrap items-center gap-2">
        <Select
          aria-label="Kind"
          className="w-40"
          value={filters.kind}
          onChange={(kind) => onChange({ ...filters, kind })}
          options={[{ value: '', label: 'Any kind' }, ...kinds.map((k) => ({ value: k.kind, label: `${cleanLine(k.kind)} (${k.count})` }))]}
        />
        <Select
          aria-label="Sort by"
          className="w-40"
          value={filters.sort}
          onChange={(sort) => onChange({ ...filters, sort })}
          options={SORTS.map((s) => ({ ...s, label: `Sort: ${s.label}` }))}
        />
        {isFiltered(filters) && (
          <button
            type="button"
            onClick={() => onChange({ ...NO_FILTERS, sort: filters.sort })}
            className="inline-flex h-7 items-center gap-1 rounded-control px-2 text-xs text-muted hover:text-ink focus:outline-none focus-visible:outline-2 focus-visible:outline-focus"
          >
            <XMarkIcon aria-hidden="true" className="size-3.5" />
            Clear filters
          </button>
        )}
      </div>
    </div>
  )
}
