// The API client for components, and a load-and-refresh hook over it.
// Components never call fetch: they take the client from here (U4).

import { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react'
import { usePolling } from './usePolling.js'

/** Holds `{ api, slow }`: the lib/api.js client and the slow-read cache. */
export const ApiContext = createContext(null)

export function useApi() {
  const ctx = useContext(ApiContext)
  if (!ctx) throw new Error('useApi needs an ApiContext provider (App.jsx)')
  return ctx.api
}

/** The 30-second cache for slow reads; clear it after any change. */
export function useSlowCache() {
  const ctx = useContext(ApiContext)
  if (!ctx) throw new Error('useSlowCache needs an ApiContext provider (App.jsx)')
  return ctx.slow
}

/**
 * Run `load(api)` now, again whenever `deps` change, and every `poll` ms when
 * given. The last good data stays on screen while a refresh is in flight, so
 * a five-second refresh never blanks the page.
 *
 * @returns {{ data: any, error: Error|null, loading: boolean, reload: () => Promise<void> }}
 */
export function useApiQuery(load, deps = [], { poll = 0, enabled = true } = {}) {
  const api = useApi()
  const [state, setState] = useState({ data: undefined, error: null, loading: true })
  const seq = useRef(0)
  const loadRef = useRef(load)
  loadRef.current = load

  const reload = useCallback(async () => {
    const mine = ++seq.current
    setState((s) => ({ ...s, loading: true }))
    try {
      const data = await loadRef.current(api)
      if (mine === seq.current) setState({ data, error: null, loading: false })
    } catch (error) {
      if (mine === seq.current) setState((s) => ({ data: s.data, error, loading: false }))
    }
  }, [api])

  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => { if (enabled) reload() }, [reload, enabled, ...deps])
  usePolling(reload, poll, { enabled: enabled && poll > 0, immediate: false })

  return { ...state, reload }
}
