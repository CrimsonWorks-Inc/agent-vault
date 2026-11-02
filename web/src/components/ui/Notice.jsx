import { CheckCircleIcon, ExclamationTriangleIcon, InformationCircleIcon, XCircleIcon } from '@heroicons/react/20/solid'
import { cx } from '../../lib/cx.js'

const TONES = {
  info: { box: 'border-accent/30 bg-accent-soft', icon: InformationCircleIcon, ink: 'text-accent' },
  ok: { box: 'border-ok/30 bg-ok-soft', icon: CheckCircleIcon, ink: 'text-ok' },
  warn: { box: 'border-warn/40 bg-warn-soft', icon: ExclamationTriangleIcon, ink: 'text-warn' },
  crit: { box: 'border-crit/40 bg-crit-soft', icon: XCircleIcon, ink: 'text-crit' },
}

/** A callout across the page: something the human should know or act on. */
export function Notice({ tone = 'info', title, children, actions, className, role }) {
  const t = TONES[tone] || TONES.info
  const Icon = t.icon
  return (
    <div role={role} className={cx('flex gap-3 rounded-card border px-4 py-3.5', t.box, className)}>
      <Icon aria-hidden="true" className={cx('mt-0.5 size-5 shrink-0', t.ink)} />
      <div className="min-w-0 flex-1 text-sm text-ink">
        {title && <p className="font-semibold">{title}</p>}
        {children && <div className={cx(title && 'mt-0.5', 'text-ink/85')}>{children}</div>}
        {actions && <div className="mt-3 flex flex-wrap gap-2">{actions}</div>}
      </div>
    </div>
  )
}
