// Call `fn` every `ms` while the tab is visible. A hidden tab does not poll,
// and coming back to it polls at once, so the page is never minutes stale.

import { useEffect, useRef } from 'react'

export function usePolling(fn, ms, { enabled = true, immediate = true } = {}) {
  const fnRef = useRef(fn)
  fnRef.current = fn

  useEffect(() => {
    if (!enabled || !(ms > 0)) return undefined
    const doc = globalThis.document
    const visible = () => !doc || doc.visibilityState !== 'hidden'
    let stopped = false
    const tick = () => { if (!stopped && visible()) fnRef.current() }
    if (immediate) tick()
    const id = setInterval(tick, ms)
    const onVisible = () => { if (visible()) tick() }
    doc?.addEventListener('visibilitychange', onVisible)
    return () => {
      stopped = true
      clearInterval(id)
      doc?.removeEventListener('visibilitychange', onVisible)
    }
  }, [ms, enabled, immediate])
}
