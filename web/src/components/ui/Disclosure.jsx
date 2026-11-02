import { Disclosure as HDisclosure, DisclosureButton, DisclosurePanel } from '@headlessui/react'
import { ChevronRightIcon } from '@heroicons/react/16/solid'
import { cx } from '../../lib/cx.js'

/** Something to open when wanted: "Edit rules", "Advanced". */
export function Disclosure({ title, defaultOpen = false, children, className }) {
  return (
    <HDisclosure defaultOpen={defaultOpen} as="div" className={className}>
      <DisclosureButton className="group inline-flex items-center gap-1.5 rounded-control text-sm font-medium text-accent hover:text-accent-hover focus:outline-none data-[focus]:outline-2 data-[focus]:outline-focus">
        <ChevronRightIcon aria-hidden="true" className={cx('size-4 transition-transform group-data-[open]:rotate-90')} />
        {title}
      </DisclosureButton>
      <DisclosurePanel className="pt-3">{children}</DisclosurePanel>
    </HDisclosure>
  )
}
