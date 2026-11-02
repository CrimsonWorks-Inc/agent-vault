import { forwardRef } from 'react'
import { Input as HInput } from '@headlessui/react'
import { cx } from '../../lib/cx.js'
import { controlClass } from './Field.jsx'

/** A text input. `mono` for ids and tokens; `invalid` paints the error state. */
export const Input = forwardRef(function Input({ mono = false, invalid = false, className, type = 'text', ...rest }, ref) {
  return (
    <HInput
      ref={ref}
      type={type}
      invalid={invalid}
      spellCheck={mono || type === 'password' ? false : undefined}
      className={cx(controlClass(mono, invalid), 'h-9', className)}
      {...rest}
    />
  )
})
