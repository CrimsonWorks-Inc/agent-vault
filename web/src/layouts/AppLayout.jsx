import { useState } from 'react'
import { Dialog, DialogBackdrop, DialogPanel } from '@headlessui/react'
import { Bars3Icon, LockClosedIcon, LockOpenIcon, XMarkIcon } from '@heroicons/react/20/solid'
import { PAGES, formatHash } from '../lib/router.js'
import { cx } from '../lib/cx.js'
import { useVault } from '../hooks/useVault.js'
import { usePresence } from '../hooks/usePresence.js'
import { usePrompt } from '../hooks/usePrompt.js'
import { useToast } from '../hooks/useToast.js'
import { useApi, useSlowCache } from '../hooks/useApi.js'
import { Badge } from '../components/ui/Badge.jsx'
import { Button } from '../components/ui/Button.jsx'
import { IconButton } from '../components/ui/IconButton.jsx'
import { Logo } from '../components/ui/Mark.jsx'
import { ThemeToggle } from '../components/ui/ThemeToggle.jsx'
import { NAV_GROUPS, NAV_ICONS } from './nav.js'

const LABEL = Object.fromEntries(PAGES.map((p) => [p.id, p.label]))

/**
 * The shell for every page: the sidebar (a drawer below lg), the header with
 * the vault's lock state and the count waiting in Approvals, and the content.
 */
export function AppLayout({ page, children }) {
  const [drawer, setDrawer] = useState(false)
  return (
    <div className="min-h-dvh bg-bg lg:grid lg:grid-cols-[16rem_1fr]">
      <aside className="sticky top-0 hidden h-dvh border-r border-line bg-nav lg:block">
        <Sidebar page={page} />
      </aside>

      <Dialog open={drawer} onClose={setDrawer} className="relative z-50 lg:hidden">
        <DialogBackdrop transition className="fixed inset-0 bg-scrim transition-opacity duration-200 data-[closed]:opacity-0" />
        <DialogPanel transition className="fixed inset-y-0 left-0 w-72 max-w-[85vw] border-r border-line bg-nav shadow-raised transition duration-200 data-[closed]:-translate-x-full">
          <div className="absolute right-2 top-3">
            <IconButton icon={XMarkIcon} label="Close navigation" onClick={() => setDrawer(false)} />
          </div>
          <Sidebar page={page} onNavigate={() => setDrawer(false)} />
        </DialogPanel>
      </Dialog>

      <div className="min-w-0">
        <Header page={page} onMenu={() => setDrawer(true)} />
        <main id="main" className="mx-auto w-full max-w-6xl px-4 pb-16 pt-6 sm:px-6 lg:px-10 lg:pt-8">
          {children}
        </main>
      </div>
    </div>
  )
}

function Sidebar({ page, onNavigate }) {
  const { pendingCount } = useVault()
  return (
    <div className="flex h-full flex-col">
      <a href={formatHash('overview')} onClick={onNavigate} className="block px-5 pb-5 pt-5 focus:outline-none focus-visible:outline-2 focus-visible:outline-focus">
        <Logo />
      </a>
      <nav aria-label="Pages" className="flex-1 overflow-y-auto px-3">
        {NAV_GROUPS.map((group) => (
          <div key={group.title} className="mb-4">
            <p className="px-2 pb-1.5 font-mono text-eyebrow uppercase tracking-[0.14em] text-muted/80">{group.title}</p>
            <ul className="space-y-0.5">
              {group.ids.map((id) => {
                const Icon = NAV_ICONS[id]
                const current = id === page
                return (
                  <li key={id}>
                    <a
                      href={formatHash(id)}
                      onClick={onNavigate}
                      aria-current={current ? 'page' : undefined}
                      className={cx(
                        'group flex items-center gap-2.5 rounded-control px-2.5 py-1.5 text-sm transition-colors',
                        'focus:outline-none focus-visible:outline-2 focus-visible:outline-focus',
                        current ? 'bg-accent-soft font-semibold text-accent' : 'text-ink/80 hover:bg-sunken hover:text-ink',
                      )}
                    >
                      <Icon aria-hidden="true" className={cx('size-4 shrink-0', current ? 'text-accent' : 'text-muted group-hover:text-ink')} />
                      <span className="flex-1">{LABEL[id]}</span>
                      {id === 'approvals' && pendingCount > 0 && (
                        <Badge tone="warn" className="tabular-nums">
                          {pendingCount}<span className="sr-only"> waiting</span>
                        </Badge>
                      )}
                    </a>
                  </li>
                )
              })}
            </ul>
          </div>
        ))}
      </nav>
      <div className="space-y-3 border-t border-line px-5 py-4">
        <p className="text-xs leading-relaxed text-muted">
          No credential value is ever sent to this page, and every change needs your fingerprint.
        </p>
        <ThemeToggle className="w-full" />
      </div>
    </div>
  )
}

function Header({ page, onMenu }) {
  const { locked, pendingCount, refresh } = useVault()
  return (
    <header className="sticky top-0 z-30 border-b border-line bg-bg/85 backdrop-blur supports-[backdrop-filter]:bg-bg/70">
      <div className="mx-auto flex h-14 w-full max-w-6xl items-center gap-3 px-4 sm:px-6 lg:px-10">
        <IconButton icon={Bars3Icon} label="Open navigation" onClick={onMenu} className="-ml-2 lg:hidden" />
        <span className="hidden font-mono text-eyebrow uppercase tracking-[0.14em] text-muted min-[400px]:inline lg:hidden">{LABEL[page]}</span>
        <div className="ml-auto flex min-w-0 items-center gap-2 sm:gap-3">
          {pendingCount > 0 && (
            <a
              href={formatHash('approvals')}
              className="inline-flex items-center gap-1.5 rounded-pill border border-warn/40 bg-warn-soft px-2.5 py-1 text-xs font-medium text-warn hover:border-warn"
            >
              <span className="tabular-nums">{pendingCount}</span>
              <span>waiting<span className="hidden sm:inline"> for you</span></span>
            </a>
          )}
          <LockState locked={locked} />
          <LockButton locked={locked} onChanged={refresh} />
        </div>
      </div>
    </header>
  )
}

function LockState({ locked }) {
  if (locked === null) return null
  return locked
    ? <Badge tone="crit"><LockClosedIcon aria-hidden="true" className="size-3" /><span className="hidden sm:inline">Vault </span>locked</Badge>
    : <Badge tone="ok"><LockOpenIcon aria-hidden="true" className="size-3" /><span className="hidden sm:inline">Vault </span>unlocked</Badge>
}

/**
 * Lock is a gated change (POST lock), confirmed in a page-drawn dialog first.
 * Unlock is not gated: the passphrase is the proof (the old page's lockBtn).
 */
function LockButton({ locked, onChanged }) {
  const api = useApi()
  const slow = useSlowCache()
  const presence = usePresence()
  const prompt = usePrompt()
  const toast = useToast()
  const [busy, setBusy] = useState(false)

  const run = async (fn) => {
    setBusy(true)
    try { await fn() } catch (e) { toast(e?.message || String(e), { tone: 'crit' }) } finally { setBusy(false); slow.clear(); onChanged?.() }
  }

  if (locked === null) return null
  if (locked) {
    return (
      <Button size="sm" variant="primary" icon={LockOpenIcon} loading={busy} aria-label="Unlock the vault" onClick={() => run(async () => {
        const ok = await unlockWithPassphrase({ api, prompt })
        toast(ok === true ? 'Unlocked' : ok === null ? 'Cancelled' : 'That passphrase did not unlock the vault', { tone: ok === true ? 'ok' : 'warn' })
      })}>
        <span className="hidden sm:inline">Unlock</span>
      </Button>
    )
  }
  return (
    <Button size="sm" variant="danger" icon={LockClosedIcon} loading={busy} aria-label="Lock the vault" title="Refuse every proxied request until you unlock" onClick={() => run(async () => {
      const ok = await prompt.confirm({
        title: 'Lock the vault?',
        body: 'Every proxied request is refused until it is unlocked, and it stays locked across restarts.',
        submit: 'Lock with Touch ID',
        danger: true,
      })
      if (!ok) return
      await presence.lock()
      toast('Vault locked', { tone: 'ok' })
    })}>
      <span className="hidden sm:inline">Lock</span>
    </Button>
  )
}

/**
 * Unlocking with the passphrase, as the old page's `unlock` action: asked for only
 * when the vault needs one. Resolves true when unlocked, false when refused,
 * null when cancelled.
 */
export async function unlockWithPassphrase({ api, prompt }) {
  const state = await api.get('lockstate')
  const passphrase = state.needs_secret ? await prompt.secret({ title: 'Vault passphrase', submit: 'Unlock' }) : null
  if (state.needs_secret && passphrase == null) return null
  const res = await api.post('unlock/passphrase', { passphrase })
  return res.locked ? false : true
}
