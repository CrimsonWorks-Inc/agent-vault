import { cx } from '../../lib/cx.js'
import { Skeleton } from './Skeleton.jsx'

/** One number and what it counts. */
export function Stat({ value, label, hint, action, loading = false, className }) {
  return (
    <div className={cx('flex flex-col gap-1 p-5', className)}>
      <dt className="font-mono text-eyebrow uppercase tracking-[0.14em] text-muted">{label}</dt>
      <dd className="text-stat font-semibold tabular-nums tracking-tight text-ink">
        {loading ? <Skeleton className="mt-2 h-6 w-16" /> : value}
      </dd>
      {(hint || action) && (
        <dd className="flex flex-wrap items-center justify-between gap-x-2 gap-y-1 text-xs text-muted">
          {hint && <span>{hint}</span>}
          {action}
        </dd>
      )}
    </div>
  )
}
