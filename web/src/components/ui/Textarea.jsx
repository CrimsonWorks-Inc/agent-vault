import { forwardRef } from 'react'
import { Textarea as HTextarea } from '@headlessui/react'
import { cx } from '../../lib/cx.js'
import { controlClass } from './Field.jsx'

export const Textarea = forwardRef(function Textarea({ mono = false, invalid = false, rows = 4, className, ...rest }, ref) {
  return (
    <HTextarea
      ref={ref}
      rows={rows}
      invalid={invalid}
      spellCheck={mono ? false : undefined}
      className={cx(controlClass(mono, invalid), 'py-2 leading-relaxed resize-y', className)}
      {...rest}
    />
  )
})
