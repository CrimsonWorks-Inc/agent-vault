import { cx } from '../../lib/cx.js'

/** The small uppercase mono label above a heading (ioLite's section labels). */
export function Eyebrow({ className, children, as: As = 'p' }) {
  return <As className={cx('font-mono text-eyebrow font-medium uppercase tracking-[0.14em] text-muted', className)}>{children}</As>
}
