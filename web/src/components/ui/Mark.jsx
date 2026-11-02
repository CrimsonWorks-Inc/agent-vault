import { useId } from 'react'
import { cx } from '../../lib/cx.js'

// The geometry of src/ui/mark.svg, drawn as JSX (never injected as markup).
// A test holds the two equal (web/test/brand.test.js).
export const MARK_DOOR = 'M26.8,6 Q32,3 37.2,6 L51.92,14.5 Q57.11,17.5 57.11,23.5 L57.11,40.5 Q57.11,46.5 51.92,49.5 L37.2,58 Q32,61 26.8,58 L12.08,49.5 Q6.89,46.5 6.89,40.5 L6.89,23.5 Q6.89,17.5 12.08,14.5 Z'
export const MARK_TICKS = 'M32 13.2V10.6M41.4 15.72L42.7 13.47M48.28 22.6L50.53 21.3M50.8 32H53.4M48.28 41.4L50.53 42.7M41.4 48.28L42.7 50.53M32 50.8V53.4M22.6 48.28L21.3 50.53M15.72 41.4L13.47 42.7M13.2 32H10.6M15.72 22.6L13.47 21.3M22.6 15.72L21.3 13.47'
export const MARK_SLOT = 'M28.8,31 L24.5,45.5 A2.5,2.5 0 0 0 27,48 L37,48 A2.5,2.5 0 0 0 39.5,45.5 L35.2,31 Z'

/**
 * The agent-vault mark in currentColor. Under 24 px the ticks are left out
 * (`compact`), because they turn to grey noise first.
 */
export function Mark({ size = 28, compact, title, className }) {
  const id = useId().replace(/:/g, '')
  const small = compact ?? size < 24
  return (
    <svg
      viewBox="0 0 64 64"
      width={size}
      height={size}
      className={cx('shrink-0', className)}
      role={title ? 'img' : undefined}
      aria-hidden={title ? undefined : true}
      aria-label={title}
    >
      <defs>
        {/* A mask paints in luminance, not colour: white keeps the door, black
            cuts the dial and keyhole out of it. These two literals are
            stencil values, so they cannot come from a theme token, and a token
            that changed them would break the mark. The colour you see is
            currentColor on the path below. brand.test.js allows exactly these. */}
        <mask id={`av-punch-${id}`}>
          <rect width="64" height="64" fill="#fff" />
          <circle cx="32" cy="32" r="15" fill="none" stroke="#000" strokeWidth={small ? 3.4 : 2.6} />
          {!small && <path d={MARK_TICKS} stroke="#000" strokeWidth="2" strokeLinecap="round" />}
          <g fill="#000" transform={small ? 'translate(32 32.6) scale(0.6) translate(-32 -32.25)' : 'translate(32 32.6) scale(0.56) translate(-32 -32.25)'}>
            <circle cx="32" cy="25" r="8.5" />
            <path d={MARK_SLOT} />
          </g>
        </mask>
      </defs>
      <path d={MARK_DOOR} fill="currentColor" mask={`url(#av-punch-${id})`} />
    </svg>
  )
}

/**
 * The lockup: mark, "agent-vault", and "by ioLite Labs" beneath it. The
 * parent brand sits in its own colour (ioLite's indigo, or lilac in dark),
 * smaller and quieter: this is a product of the lab, not the lab's name.
 */
export function Logo({ size = 'md', stacked = true, className }) {
  const big = size === 'lg'
  return (
    <span className={cx('inline-flex items-center gap-2.5', className)} aria-label="agent-vault, by ioLite Labs" role="img">
      <Mark size={big ? 40 : 30} className="text-accent" />
      <span aria-hidden="true" className={cx('flex', stacked ? 'flex-col leading-none' : 'items-baseline gap-2')}>
        <span className={cx('font-semibold tracking-[-0.02em] text-ink', big ? 'text-2xl' : 'text-[1.0625rem]')}>
          agent<span className="text-accent">-</span>vault
        </span>
        <span className={cx('font-mono uppercase tracking-[0.16em] text-brand', big ? 'mt-1.5 text-[0.6875rem]' : 'mt-1 text-[0.5625rem]')}>
          by ioLite Labs
        </span>
      </span>
    </span>
  )
}
