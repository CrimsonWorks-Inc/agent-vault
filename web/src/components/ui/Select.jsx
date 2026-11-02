import { Listbox, ListboxButton, ListboxOption, ListboxOptions } from '@headlessui/react'
import { CheckIcon, ChevronUpDownIcon } from '@heroicons/react/16/solid'
import { cx } from '../../lib/cx.js'
import { controlClass } from './Field.jsx'

/**
 * A listbox. `options` is `[{ value, label, description? }]`; `value` is the
 * selected option's value. Put it in a <Field> for a label, or pass
 * `aria-label`. The list opens below the button with plain CSS positioning,
 * so nothing needs an inline style (CSP, U2).
 */
export function Select({ value, onChange, options, placeholder = 'Choose…', disabled, mono = false, className, up = false, ...rest }) {
  const current = options.find((o) => o.value === value)
  return (
    <Listbox value={value} onChange={onChange} disabled={disabled}>
      <div className={cx('relative', className)}>
        <ListboxButton className={cx(controlClass(mono, false), 'flex h-9 items-center justify-between gap-2 text-left cursor-pointer')} {...rest}>
          <span className={cx('truncate', !current && 'text-muted')}>{current ? current.label : placeholder}</span>
          <ChevronUpDownIcon aria-hidden="true" className="size-4 shrink-0 text-muted" />
        </ListboxButton>
        <ListboxOptions
          className={cx(
            'absolute z-30 max-h-64 min-w-full overflow-auto rounded-control border border-line bg-surface p-1 shadow-raised focus:outline-none',
            up ? 'bottom-full mb-1' : 'top-full mt-1',
          )}
        >
          {options.map((o) => (
            <ListboxOption
              key={String(o.value)}
              value={o.value}
              disabled={o.disabled}
              className="group flex cursor-pointer items-start gap-2 rounded-[0.375rem] px-2.5 py-1.5 text-sm text-ink data-[focus]:bg-accent-soft data-[focus]:text-accent data-[disabled]:opacity-50"
            >
              <CheckIcon aria-hidden="true" className="mt-0.5 size-4 shrink-0 invisible group-data-[selected]:visible" />
              <span className="min-w-0">
                <span className={cx('block whitespace-nowrap', mono && 'font-mono')}>{o.label}</span>
                {o.description && <span className="block text-xs text-muted">{o.description}</span>}
              </span>
            </ListboxOption>
          ))}
        </ListboxOptions>
      </div>
    </Listbox>
  )
}
