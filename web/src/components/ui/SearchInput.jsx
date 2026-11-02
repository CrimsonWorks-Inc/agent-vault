import { MagnifyingGlassIcon, XMarkIcon } from '@heroicons/react/16/solid'
import { cx } from '../../lib/cx.js'
import { controlClass } from './Field.jsx'

/**
 * The search box on every list page (U4). `onChange` gets the text; the
 * debounce lives in usePaged, so this stays a plain controlled input.
 */
export function SearchInput({ value, onChange, label = 'Search', placeholder = 'Search…', className }) {
  return (
    <div className={cx('relative w-full sm:max-w-xs', className)} role="search">
      <MagnifyingGlassIcon aria-hidden="true" className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted" />
      <input
        type="search"
        aria-label={label}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        onKeyDown={(e) => { if (e.key === 'Escape' && value) { e.preventDefault(); onChange('') } }}
        placeholder={placeholder}
        autoComplete="off"
        spellCheck={false}
        className={cx(controlClass(false, false), 'h-9 pl-9 pr-8 focus:border-accent focus:outline-2 focus:outline-offset-0 focus:outline-focus/40 [&::-webkit-search-cancel-button]:hidden')}
      />
      {value && (
        <button
          type="button"
          onClick={() => onChange('')}
          aria-label="Clear search"
          className="absolute right-2 top-1/2 -translate-y-1/2 rounded p-0.5 text-muted hover:text-ink focus:outline-none focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-focus"
        >
          <XMarkIcon aria-hidden="true" className="size-4" />
        </button>
      )}
    </div>
  )
}
