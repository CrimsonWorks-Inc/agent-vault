import { useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react'
import { createApi } from './lib/api.js'
import { createCache } from './lib/cache.js'
import { fetchAll } from './lib/paging.js'
import { parseHash } from './lib/router.js'
import { batchText, createWatcher, notificationsOn } from './lib/notify.js'
import { ApiContext } from './hooks/useApi.js'
import { PresenceContext, usePresenceController } from './hooks/usePresence.js'
import { usePrompt } from './hooks/usePrompt.js'
import { usePolling } from './hooks/usePolling.js'
import { VaultContext } from './hooks/useVault.js'
import { PresenceStatus } from './components/ui/PresenceStatus.jsx'
import { PromptProvider } from './components/ui/PromptProvider.jsx'
import { ToastProvider } from './components/ui/Toast.jsx'
import { AppLayout } from './layouts/AppLayout.jsx'
import { NoSession, Unreachable } from './layouts/CenteredLayout.jsx'
import { PAGE_COMPONENTS } from './pages/index.js'

const CHROME_POLL_MS = 5000
const storage = () => { try { return globalThis.localStorage } catch { return null } }

/** The hash route, kept in state and in step with the address bar. */
function useRoute() {
  const [route, setRoute] = useState(() => parseHash(globalThis.location?.hash))
  useEffect(() => {
    const on = () => setRoute(parseHash(globalThis.location?.hash))
    globalThis.addEventListener?.('hashchange', on)
    return () => globalThis.removeEventListener?.('hashchange', on)
  }, [])
  return route
}

export function App({ fetch: doFetch } = {}) {
  const [fatal, setFatal] = useState(null)
  const api = useMemo(() => createApi(doFetch ? { fetch: doFetch } : {}), [doFetch])
  const slow = useMemo(() => createCache(), [])
  useEffect(() => api.onFatal((e) => setFatal((cur) => (cur?.kind === 'session' ? cur : e))), [api])
  const apiCtx = useMemo(() => ({ api, slow }), [api, slow])

  return (
    <ApiContext.Provider value={apiCtx}>
      <ToastProvider>
        <PromptProvider>
          <Shell fatal={fatal} setFatal={setFatal} />
        </PromptProvider>
      </ToastProvider>
    </ApiContext.Provider>
  )
}

function Shell({ fatal, setFatal }) {
  const { api } = useApiCtx()
  const prompt = usePrompt()
  const askSecret = useCallback((label) => prompt.secret({ title: label }), [prompt])
  const presence = usePresenceController({ api, askSecret })
  const vault = useVaultController(api, !fatal)
  const route = useRoute()

  // Unreachable heals itself: keep asking, and go back to the app when the
  // daemon answers. A lost session does not: the launch link is spent.
  const retry = useCallback(async () => {
    try { await api.get('status'); setFatal(null); vault.refresh() } catch { /* still down */ }
  }, [api, setFatal, vault])
  usePolling(retry, CHROME_POLL_MS, { enabled: fatal !== null && fatal.kind !== 'session', immediate: false })

  if (fatal?.kind === 'session') return <NoSession cli={vault.context.cli} />
  if (fatal) return <Unreachable error={fatal} onRetry={retry} cli={vault.context.cli} />

  const Page = PAGE_COMPONENTS[route.page] || PAGE_COMPONENTS.overview
  return (
    <PresenceContext.Provider value={presence}>
      <VaultContext.Provider value={vault}>
        <AppLayout page={route.page}>
          <Page rest={route.rest} />
        </AppLayout>
        <PresenceStatus />
      </VaultContext.Provider>
    </PresenceContext.Provider>
  )
}

function useApiCtx() { return useContext(ApiContext) }

/**
 * The header's truth, whichever page is open (app.html's refreshChrome): the
 * lock state and what is waiting, every five seconds. A fresh item raises a
 * desktop notification when the human turned them on (F14).
 */
function useVaultController(api, enabled) {
  const [lockState, setLockState] = useState(null)
  const [pending, setPending] = useState(null)
  const [context, setContext] = useState({ cli: 'agent-vault' })
  const watcher = useRef(createWatcher())

  const refresh = useCallback(async () => {
    const [ls, items] = await Promise.all([
      api.get('lockstate').catch(() => null),
      fetchAll(api.get, 'pending').catch(() => null),
    ])
    if (ls) setLockState(ls)
    if (Array.isArray(items)) {
      setPending(items)
      const fresh = watcher.current(items)
      if (fresh.length && notificationsOn(storage())) notify(fresh)
    }
  }, [api])

  useEffect(() => {
    if (!enabled) return
    api.get('docs/context').then((c) => setContext({ ...c, cli: c?.cli || 'agent-vault' })).catch(() => {})
  }, [api, enabled])
  usePolling(refresh, CHROME_POLL_MS, { enabled })

  return useMemo(() => ({
    locked: lockState ? lockState.locked === true : null,
    lockState,
    pending: pending || [],
    pendingKnown: pending !== null,
    pendingCount: pending ? pending.length : 0,
    context,
    refresh,
  }), [lockState, pending, context, refresh])
}

/** A signal, never an approval channel: clicking only opens Approvals. */
function notify(fresh) {
  const N = globalThis.Notification
  if (typeof N === 'undefined' || N.permission !== 'granted') return
  try {
    const n = new N('agent-vault', { body: batchText(fresh), tag: 'agent-vault-pending' })
    n.onclick = () => { globalThis.focus?.(); globalThis.location.hash = `#approvals/${encodeURIComponent(fresh[0].id)}` }
  } catch { /* a browser that will not show one has nothing to fall back to */ }
}
