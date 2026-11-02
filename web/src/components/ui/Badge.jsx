import { cx } from '../../lib/cx.js'

const TONES = {
  neutral: 'bg-sunken text-muted border-line',
  accent: 'bg-accent-soft text-accent border-accent/25',
  ok: 'bg-ok-soft text-ok border-ok/30',
  warn: 'bg-warn-soft text-warn border-warn/35',
  crit: 'bg-crit-soft text-crit border-crit/35',
}
const DOTS = { neutral: 'bg-muted', accent: 'bg-accent', ok: 'bg-ok', warn: 'bg-warn', crit: 'bg-crit' }

/**
 * A short status. Status is never colour alone (U6): the words carry it, and
 * the dot is decoration.
 * @param {{tone?: 'neutral'|'accent'|'ok'|'warn'|'crit', dot?: boolean, mono?: boolean, title?: string}} props
 */
export function Badge({ tone = 'neutral', dot = false, mono = false, className, children, ...rest }) {
  return (
    <span
      className={cx(
        'inline-flex items-center gap-1.5 rounded-pill border px-2 py-px text-xs font-medium whitespace-nowrap align-middle',
        mono && 'font-mono text-[0.6875rem] tracking-tight',
        TONES[tone] || TONES.neutral, className,
      )}
      {...rest}
    >
      {dot && <span aria-hidden="true" className={cx('size-1.5 rounded-pill', DOTS[tone] || DOTS.neutral)} />}
      {children}
    </span>
  )
}

/** The same thing by the old page's name for it. */
export const Pill = Badge
