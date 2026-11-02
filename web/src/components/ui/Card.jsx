import { cx } from '../../lib/cx.js'
import { Eyebrow } from './Eyebrow.jsx'

/**
 * A panel. Give it a `title` (and optionally an `eyebrow`, `actions` and a
 * `description`) for a header row, or none for a bare surface.
 * `padded={false}` lets a DataTable or a list of Rows run to the edges.
 */
export function Card({ title, eyebrow, description, actions, footer, padded = true, as: As = 'section', className, children, ...rest }) {
  const headed = title || eyebrow || actions
  return (
    <As className={cx('rounded-card border border-line bg-surface shadow-card', className)} {...rest}>
      {headed && (
        <header className="flex flex-wrap items-start justify-between gap-3 border-b border-line px-5 py-4">
          <div className="min-w-0">
            {eyebrow && <Eyebrow>{eyebrow}</Eyebrow>}
            {title && <h2 className="text-lg font-semibold tracking-tight text-ink">{title}</h2>}
            {description && <p className="mt-0.5 text-sm text-muted">{description}</p>}
          </div>
          {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={cx(padded && 'px-5 py-4')}>{children}</div>
      {footer && <footer className="border-t border-line px-5 py-3">{footer}</footer>}
    </As>
  )
}

/**
 * One line inside a card: a title and its meta on the left, actions on the
 * right; stacks on small screens. The old page's `.row`.
 */
export function Row({ title, meta, actions, children, className }) {
  return (
    <div className={cx('flex flex-col gap-3 border-t border-line px-5 py-4 first:border-t-0 sm:flex-row', children ? 'sm:items-start' : 'sm:items-center', className)}>
      <div className="min-w-0 flex-1">
        {title && <div className="flex flex-wrap items-center gap-2 font-medium text-ink">{title}</div>}
        {meta && <div className="mt-0.5 text-sm text-muted">{meta}</div>}
        {children}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2 sm:justify-end">{actions}</div>}
    </div>
  )
}
