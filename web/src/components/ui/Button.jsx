import { forwardRef } from 'react'
import { Button as HButton } from '@headlessui/react'
import { cx } from '../../lib/cx.js'
import { Spinner } from './Spinner.jsx'

// Variants are props, mapped here once (frontend standards).
const VARIANTS = {
  primary: 'bg-accent text-on-accent border-accent hover:bg-accent-hover hover:border-accent-hover shadow-card',
  secondary: 'bg-surface text-ink border-line-strong/60 hover:border-accent hover:text-accent shadow-card',
  ghost: 'bg-transparent text-muted border-transparent hover:bg-sunken hover:text-ink',
  danger: 'bg-surface text-crit border-crit/60 hover:bg-crit-soft hover:border-crit',
  panic: 'bg-crit text-on-crit border-crit hover:bg-crit-hover hover:border-crit-hover shadow-card',
}
const SIZES = {
  sm: 'h-8 px-3 text-sm gap-1.5 [&_svg]:size-4',
  md: 'h-9 px-3.5 text-sm gap-2 [&_svg]:size-4',
  lg: 'h-11 px-5 text-base gap-2 [&_svg]:size-5',
}

/**
 * @param {{variant?: 'primary'|'secondary'|'ghost'|'danger'|'panic', size?: 'sm'|'md'|'lg',
 *   loading?: boolean, icon?: import('react').ComponentType, block?: boolean}} props
 */
export const Button = forwardRef(function Button(
  { variant = 'secondary', size = 'md', loading = false, icon: Icon = null, block = false, type = 'button', className, children, disabled, ...rest },
  ref,
) {
  return (
    <HButton
      ref={ref}
      type={type}
      disabled={disabled || loading}
      aria-busy={loading || undefined}
      className={cx(
        'inline-flex items-center justify-center rounded-control border font-medium whitespace-nowrap select-none',
        'transition-colors duration-150 focus:outline-none data-[focus]:outline-2 data-[focus]:outline-offset-2 data-[focus]:outline-focus',
        'data-[disabled]:opacity-50 data-[disabled]:cursor-not-allowed cursor-pointer',
        VARIANTS[variant] || VARIANTS.secondary,
        SIZES[size] || SIZES.md,
        block && 'w-full',
        className,
      )}
      {...rest}
    >
      {loading ? <Spinner size="sm" label="" /> : Icon ? <Icon aria-hidden="true" /> : null}
      {children}
    </HButton>
  )
})
