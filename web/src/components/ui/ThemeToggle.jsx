import { useEffect, useState } from 'react'
import { Radio, RadioGroup } from '@headlessui/react'
import { ComputerDesktopIcon, MoonIcon, SunIcon } from '@heroicons/react/16/solid'
import { applyTheme, readTheme, saveTheme } from '../../lib/theme.js'
import { cx } from '../../lib/cx.js'

const storage = () => { try { return globalThis.localStorage } catch { return null } }
const OPTIONS = [
  { value: 'system', label: 'System', icon: ComputerDesktopIcon },
  { value: 'light', label: 'Light', icon: SunIcon },
  { value: 'dark', label: 'Dark', icon: MoonIcon },
]

/** System, light or dark, remembered in localStorage (U6). */
export function ThemeToggle({ className }) {
  const [theme, setTheme] = useState(() => readTheme(storage()))
  useEffect(() => {
    applyTheme(globalThis.document?.documentElement, theme)
    saveTheme(storage(), theme)
  }, [theme])
  return (
    <RadioGroup value={theme} onChange={setTheme} aria-label="Theme" className={cx('inline-flex rounded-control border border-line bg-sunken p-0.5', className)}>
      {OPTIONS.map(({ value, label, icon: Icon }) => (
        <Radio
          key={value}
          value={value}
          aria-label={label}
          title={label}
          className="inline-flex h-7 flex-1 cursor-pointer items-center justify-center gap-1.5 rounded-[0.375rem] px-2 text-xs text-muted transition-colors data-[hover]:text-ink data-[checked]:bg-surface data-[checked]:text-ink data-[checked]:shadow-card focus:outline-none data-[focus]:outline-2 data-[focus]:outline-focus"
        >
          <Icon aria-hidden="true" className="size-3.5" />
          <span>{label}</span>
        </Radio>
      ))}
    </RadioGroup>
  )
}
