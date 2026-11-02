import { Field, Label, Switch as HSwitch } from '@headlessui/react'
import { cx } from '../../lib/cx.js'

/**
 * An on/off switch with its label. The state is said in words beside it
 * ("on"/"off"), never by the knob's colour alone.
 */
export function Switch({ checked, onChange, label, disabled, showState = true, className }) {
  return (
    <Field disabled={disabled} className={cx('inline-flex items-center gap-3', className)}>
      <HSwitch
        checked={checked}
        onChange={onChange}
        className={cx(
          'group relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-pill border border-line-strong bg-sunken p-0.5 transition-colors',
          'data-[checked]:border-accent data-[checked]:bg-accent focus:outline-none data-[focus]:outline-2 data-[focus]:outline-offset-2 data-[focus]:outline-focus',
          'data-[disabled]:opacity-50 data-[disabled]:cursor-not-allowed',
        )}
      >
        <span aria-hidden="true" className="size-4.5 translate-x-0 rounded-pill bg-surface shadow-card ring-1 ring-line-strong/40 transition-transform group-data-[checked]:translate-x-5" />
      </HSwitch>
      {label && <Label className="text-sm text-ink">{label}</Label>}
      {showState && <span className="text-sm text-muted" aria-hidden="true">{checked ? 'on' : 'off'}</span>}
    </Field>
  )
}
