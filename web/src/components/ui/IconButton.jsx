import { forwardRef } from 'react'
import { Button as HButton } from '@headlessui/react'
import { cx } from '../../lib/cx.js'

const VARIANTS = {
  ghost: 'text-muted hover:text-ink hover:bg-sunken border-transparent',
  secondary: 'text-ink bg-surface border-line hover:border-accent hover:text-accent',
  danger: 'text-crit hover:bg-crit-soft border-transparent',
}
const SIZES = { sm: 'size-7 [&_svg]:size-4', md: 'size-9 [&_svg]:size-5' }

/** An icon-only button. `label` is required: it is the accessible name. */
export const IconButton = forwardRef(function IconButton(
  { icon: Icon, label, variant = 'ghost', size = 'md', className, type = 'button', ...rest },
  ref,
) {
  return (
    <HButton
      ref={ref}
      type={type}
      aria-label={label}
      title={label}
      className={cx(
        'inline-flex items-center justify-center rounded-control border transition-colors cursor-pointer',
        'focus:outline-none data-[focus]:outline-2 data-[focus]:outline-offset-2 data-[focus]:outline-focus data-[disabled]:opacity-50',
        VARIANTS[variant] || VARIANTS.ghost, SIZES[size] || SIZES.md, className,
      )}
      {...rest}
    >
      <Icon aria-hidden="true" />
    </HButton>
  )
})
