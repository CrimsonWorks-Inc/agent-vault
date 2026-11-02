import { cx } from '../../lib/cx.js'

/** A two-column list of facts. `rows` is `[[label, value], ...]`. */
export function KeyValue({ rows, mono = true, className }) {
  return (
    <dl className={cx('grid grid-cols-[max-content_1fr] gap-x-4 text-sm', className)}>
      {rows.map(([k, v]) => (
        <div key={k} className="contents">
          <dt className="border-t border-line py-1.5 text-muted first:border-t-0">{k}</dt>
          <dd className={cx('min-w-0 break-words border-t border-line py-1.5 text-ink', mono && 'font-mono text-[0.8125rem]')}>{v}</dd>
        </div>
      ))}
    </dl>
  )
}
