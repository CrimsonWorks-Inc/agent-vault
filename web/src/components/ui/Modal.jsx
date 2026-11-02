import { Dialog, DialogBackdrop, DialogPanel, DialogTitle, Description } from '@headlessui/react'
import { XMarkIcon } from '@heroicons/react/20/solid'
import { cx } from '../../lib/cx.js'
import { IconButton } from './IconButton.jsx'

const WIDTHS = { sm: 'max-w-md', md: 'max-w-lg', lg: 'max-w-2xl' }

/**
 * A dialog. Headless UI traps focus, closes on Escape and outside click, and
 * restores focus to whatever opened it. `footer` holds the buttons.
 */
export function Modal({ open, onClose, title, description, footer, size = 'md', children, initialFocus }) {
  return (
    <Dialog open={open} onClose={onClose} className="relative z-50" initialFocus={initialFocus}>
      <DialogBackdrop transition className="fixed inset-0 bg-scrim backdrop-blur-[2px] transition-opacity duration-150 data-[closed]:opacity-0" />
      <div className="fixed inset-0 flex items-end justify-center overflow-y-auto p-4 sm:items-center">
        <DialogPanel
          transition
          className={cx(
            'w-full rounded-card border border-line bg-surface shadow-raised transition duration-150',
            'data-[closed]:translate-y-2 data-[closed]:opacity-0', WIDTHS[size] || WIDTHS.md,
          )}
        >
          <div className="flex items-start justify-between gap-4 px-5 pt-5">
            <div className="min-w-0">
              <DialogTitle className="text-lg font-semibold tracking-tight text-ink">{title}</DialogTitle>
              {description && <Description className="mt-1 text-sm text-muted">{description}</Description>}
            </div>
            <IconButton icon={XMarkIcon} label="Close" size="sm" onClick={onClose} />
          </div>
          <div className="px-5 py-4">{children}</div>
          {footer && <div className="flex flex-wrap justify-end gap-2 border-t border-line bg-sunken/50 px-5 py-3 rounded-b-card">{footer}</div>}
        </DialogPanel>
      </div>
    </Dialog>
  )
}
