import { cx } from '../../lib/cx.js'

/** A labelled native checkbox: methods, credentials, GraphQL. Keyboard and screen-reader native. */
export function Check({ checked, onChange, children, mono = false, className, disabled, ...rest }) {
  return (
    <label className={cx('inline-flex cursor-pointer select-none items-center gap-2 text-sm text-ink', disabled && 'cursor-not-allowed opacity-60', className)}>
      <input
        type="checkbox"
        className="size-4 shrink-0 cursor-pointer rounded border-line-strong accent-accent focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus"
        checked={checked}
        disabled={disabled}
        onChange={(e) => onChange(e.target.checked)}
        {...rest}
      />
      <span className={cx(mono && 'font-mono text-[0.8125rem]')}>{children}</span>
    </label>
  )
}
