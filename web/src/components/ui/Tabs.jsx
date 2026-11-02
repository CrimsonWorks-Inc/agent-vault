import { Tab, TabGroup, TabList, TabPanel, TabPanels } from '@headlessui/react'
import { cx } from '../../lib/cx.js'

/**
 * Tabs over `tabs = [{ id, label, content }]`. Controlled when `selected`
 * (an id) and `onChange(id)` are given.
 */
export function Tabs({ tabs, selected, onChange, className }) {
  const index = selected === undefined ? undefined : Math.max(0, tabs.findIndex((t) => t.id === selected))
  return (
    <TabGroup
      selectedIndex={index}
      onChange={onChange ? (i) => onChange(tabs[i].id) : undefined}
      className={className}
    >
      <TabList className="flex gap-1 overflow-x-auto border-b border-line">
        {tabs.map((t) => (
          <Tab
            key={t.id}
            className={cx(
              '-mb-px cursor-pointer whitespace-nowrap border-b-2 border-transparent px-3 py-2 text-sm font-medium text-muted transition-colors',
              'data-[hover]:text-ink data-[selected]:border-accent data-[selected]:text-accent focus:outline-none data-[focus]:outline-2 data-[focus]:outline-focus',
            )}
          >
            {t.label}
          </Tab>
        ))}
      </TabList>
      <TabPanels className="pt-4">
        {tabs.map((t) => <TabPanel key={t.id} className="focus:outline-none">{t.content}</TabPanel>)}
      </TabPanels>
    </TabGroup>
  )
}
