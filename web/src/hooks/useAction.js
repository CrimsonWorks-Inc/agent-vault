// Run a click's work with a busy flag and a toast for the outcome, so every
// button does not repeat the same try/catch.
//
//   const [run, busy] = useAction()
//   <Button loading={busy} onClick={() => run(() => api.get('audit/verify'), {
//     done: (v) => (v.ok ? `Chain intact across ${v.count} records` : `Chain broken at record ${v.brokenAt}`),
//   })}>Verify chain</Button>

import { useCallback, useState } from 'react'
import { useToast } from './useToast.js'

export function useAction() {
  const toast = useToast()
  const [busy, setBusy] = useState(false)
  const run = useCallback(async (fn, { done, tone = 'ok', after } = {}) => {
    setBusy(true)
    try {
      const result = await fn()
      const msg = typeof done === 'function' ? done(result) : done
      if (msg) toast(msg, { tone: typeof tone === 'function' ? tone(result) : tone })
      await after?.(result)
      return result
    } catch (e) {
      toast(e?.message || String(e), { tone: 'crit' })
      return undefined
    } finally {
      setBusy(false)
    }
  }, [toast])
  return [run, busy]
}
