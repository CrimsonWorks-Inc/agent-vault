import { cx } from '../../lib/cx.js'

/** Nothing here, said plainly, with what to do about it. */
export function EmptyState({ icon: Icon = null, title, children, action, className }) {
  return (
    <div className={cx('flex flex-col items-center gap-2 px-6 py-10 text-center', className)}>
      {Icon && (
        <span className="mb-1 inline-flex size-10 items-center justify-center rounded-pill bg-sunken text-muted">
          <Icon aria-hidden="true" className="size-5" />
        </span>
      )}
      {title && <p className="font-medium text-ink">{title}</p>}
      {children && <div className="max-w-md text-sm text-muted">{children}</div>}
      {action && <div className="mt-2">{action}</div>}
    </div>
  )
}
