import { Menu as HMenu, MenuButton, MenuItem, MenuItems } from '@headlessui/react'
import { EllipsisHorizontalIcon } from '@heroicons/react/20/solid'
import { cx } from '../../lib/cx.js'

/**
 * A dropdown of actions. `items` is `[{ label, onClick, danger?, disabled?, icon? }]`.
 * `label` names the trigger for screen readers.
 */
export function Menu({ label = 'More actions', items, align = 'right', trigger = null }) {
  return (
    <HMenu as="div" className="relative inline-block text-left">
      <MenuButton
        aria-label={trigger ? undefined : label}
        className="inline-flex size-9 items-center justify-center rounded-control text-muted transition-colors hover:bg-sunken hover:text-ink focus:outline-none data-[focus]:outline-2 data-[focus]:outline-focus"
      >
        {trigger || <EllipsisHorizontalIcon aria-hidden="true" className="size-5" />}
      </MenuButton>
      <MenuItems
        className={cx(
          'absolute top-full z-30 mt-1 min-w-48 rounded-control border border-line bg-surface p-1 shadow-raised focus:outline-none',
          align === 'right' ? 'right-0' : 'left-0',
        )}
      >
        {items.map((it) => (
          <MenuItem key={it.label} disabled={it.disabled}>
            <button
              type="button"
              onClick={it.onClick}
              className={cx(
                'flex w-full items-center gap-2 rounded-[0.375rem] px-2.5 py-1.5 text-left text-sm data-[disabled]:opacity-50',
                it.danger ? 'text-crit data-[focus]:bg-crit-soft' : 'text-ink data-[focus]:bg-accent-soft data-[focus]:text-accent',
              )}
            >
              {it.icon && <it.icon aria-hidden="true" className="size-4" />}
              {it.label}
            </button>
          </MenuItem>
        ))}
      </MenuItems>
    </HMenu>
  )
}
