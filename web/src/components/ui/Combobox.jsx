import { useState } from 'react'
import { Combobox as HCombobox, ComboboxButton, ComboboxInput, ComboboxOption, ComboboxOptions } from '@headlessui/react'
import { CheckIcon, ChevronUpDownIcon } from '@heroicons/react/16/solid'
import { cx } from '../../lib/cx.js'
import { controlClass } from './Field.jsx'

/**
 * A searchable picker. `options` is `[{ value, label }]`. Filtering is a
 * case-insensitive substring match on the label.
 */
export function Combobox({ value, onChange, options, placeholder = 'Search…', mono = false, className, emptyText = 'No match', ...rest }) {
  const [query, setQuery] = useState('')
  const shown = query ? options.filter((o) => String(o.label).toLowerCase().includes(query.toLowerCase())) : options
  const labelOf = (v) => options.find((o) => o.value === v)?.label ?? ''
  return (
    <HCombobox value={value} onChange={onChange} onClose={() => setQuery('')}>
      <div className={cx('relative', className)}>
        <ComboboxInput
          className={cx(controlClass(mono, false), 'h-9 pr-8')}
          displayValue={labelOf}
          placeholder={placeholder}
          onChange={(e) => setQuery(e.target.value)}
          {...rest}
        />
        <ComboboxButton className="absolute inset-y-0 right-0 flex items-center px-2 text-muted" aria-label="Show options">
          <ChevronUpDownIcon aria-hidden="true" className="size-4" />
        </ComboboxButton>
        <ComboboxOptions className="absolute top-full z-30 mt-1 max-h-64 w-full overflow-auto rounded-control border border-line bg-surface p-1 shadow-raised empty:invisible focus:outline-none">
          {shown.length === 0 && <div className="px-2.5 py-1.5 text-sm text-muted">{emptyText}</div>}
          {shown.map((o) => (
            <ComboboxOption
              key={String(o.value)}
              value={o.value}
              className="group flex cursor-pointer items-center gap-2 rounded-[0.375rem] px-2.5 py-1.5 text-sm text-ink data-[focus]:bg-accent-soft data-[focus]:text-accent"
            >
              <CheckIcon aria-hidden="true" className="size-4 invisible group-data-[selected]:visible" />
              <span className={cx(mono && 'font-mono')}>{o.label}</span>
            </ComboboxOption>
          ))}
        </ComboboxOptions>
      </div>
    </HCombobox>
  )
}
