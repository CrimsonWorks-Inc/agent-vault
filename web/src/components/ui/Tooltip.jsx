import { useId } from 'react'
import { cx } from '../../lib/cx.js'

/**
 * A short hint on hover and on keyboard focus. Plain CSS, so it needs no
 * inline style and no positioning script. The trigger is described by the
 * tooltip, so screen readers hear it too. Never put anything essential only
 * in a tooltip: touch screens have no hover.
 */
export function Tooltip({ content, side = 'top', children, className }) {
  const id = useId()
  return (
    <span className={cx('group/tip relative inline-flex', className)} aria-describedby={id}>
      {children}
      <span
        role="tooltip"
        id={id}
        className={cx(
          'pointer-events-none absolute left-1/2 z-40 w-max max-w-64 -translate-x-1/2 rounded-control bg-ink px-2 py-1 text-xs text-bg opacity-0 shadow-raised transition-opacity',
          'group-hover/tip:opacity-100 group-focus-within/tip:opacity-100',
          side === 'top' ? 'bottom-full mb-1.5' : 'top-full mt-1.5',
        )}
      >
        {content}
      </span>
    </span>
  )
}
