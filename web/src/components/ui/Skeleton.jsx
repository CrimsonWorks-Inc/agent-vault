import { cx } from '../../lib/cx.js'

/** A placeholder bar while data loads. Decorative: the region says "Loading". */
export function Skeleton({ className }) {
  return <span aria-hidden="true" className={cx('block h-3 animate-shimmer rounded-pill bg-sunken', className)} />
}
