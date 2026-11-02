import { cx } from '../../lib/cx.js'

const SIZES = { sm: 'size-3.5 border-[1.5px]', md: 'size-5 border-2', lg: 'size-8 border-2' }

/** Busy. `label` is read to screen readers; pass '' inside a labelled button. */
export function Spinner({ size = 'md', label = 'Loading', className }) {
  return (
    <span role={label ? 'status' : undefined} className={cx('inline-flex items-center', className)}>
      <span aria-hidden="true" className={cx('animate-spin rounded-pill border-current border-r-transparent', SIZES[size] || SIZES.md)} />
      {label && <span className="sr-only">{label}</span>}
    </span>
  )
}
