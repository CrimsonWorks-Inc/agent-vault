import { Field as HField, Label, Description } from '@headlessui/react'
import { cx } from '../../lib/cx.js'

/**
 * A labelled form control. Headless UI's Field wires the label, the hint and
 * the error to whatever Input, Textarea, Select or Switch is inside it.
 * @param {{label: import('react').ReactNode, hint?: import('react').ReactNode, error?: string, optional?: boolean}} props
 */
export function Field({ label, hint, error, optional = false, className, children, disabled }) {
  return (
    <HField disabled={disabled} className={cx('flex flex-col gap-1.5', className)}>
      <Label className="text-sm font-medium text-ink">
        {label}
        {optional && <span className="ml-1 font-normal text-muted">(optional)</span>}
      </Label>
      {children}
      {hint && !error && <Description className="text-xs text-muted">{hint}</Description>}
      {error && <Description className="text-xs font-medium text-crit" role="alert">{error}</Description>}
    </HField>
  )
}

/** The classes every text control shares, in one place. */
export const controlClass = (mono, invalid) => cx(
  'block w-full rounded-control border bg-surface px-3 text-sm text-ink placeholder:text-muted/70',
  'transition-colors focus:outline-none data-[focus]:border-accent data-[focus]:outline-2 data-[focus]:outline-offset-0 data-[focus]:outline-focus/40',
  'data-[disabled]:opacity-60 data-[disabled]:cursor-not-allowed',
  invalid ? 'border-crit' : 'border-line-strong data-[hover]:border-accent/70',
  mono && 'font-mono text-[0.8125rem]',
)
