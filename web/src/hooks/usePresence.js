// Touch ID confirmation for the whole app (contract U4, U7).
//
// The provider (App.jsx) owns one lib/presence.js instance. Every gated call
// goes through `gated(operation, send)`, which puts the operation's name on
// screen ("Touch ID to revoke session s_123", components/ui/PresenceStatus)
// BEFORE the platform dialog opens, because that dialog says who is asking
// and never what for.

import { createContext, useCallback, useContext, useMemo, useState } from 'react'
import { flushSync } from 'react-dom'
import { createPresence, describeOperation, operationFor } from '../lib/presence.js'

export const PresenceContext = createContext(null)
const NO_OVERRIDES = Object.freeze({})

export function usePresence() {
  const ctx = useContext(PresenceContext)
  if (!ctx) throw new Error('usePresence needs a PresenceContext provider (App.jsx)')
  return ctx
}

/**
 * Build the context value. `api` is the lib/api.js client; `askSecret(label)`
 * resolves with a passphrase or null (hooks/usePrompt.js).
 */
export function usePresenceController({ api, askSecret, platform = NO_OVERRIDES }) {
  const presence = useMemo(() => createPresence({ call: api.request, ...platform }), [api, platform])
  const [state, setState] = useState({ enrolled: false, known: false })
  const [signing, setSigning] = useState(null)

  const refresh = useCallback(async () => {
    const s = await presence.refresh()
    setState({ ...s, known: true })
    return s
  }, [presence])

  /**
   * Show what is being signed for as long as `fn` runs. Committed
   * synchronously, so the line is in the DOM before the challenge is even
   * requested, and so before the platform dialog can open.
   */
  const showing = useCallback(async (label, fn) => {
    flushSync(() => setSigning({ label }))
    try { return await fn() } finally { setSigning(null) }
  }, [])

  const gated = useCallback((operation, send, { label } = {}) =>
    showing(label || describeOperation(operation), () => presence.gated(operation, send)), [presence, showing])

  const value = useMemo(() => ({
    enrolled: state.enrolled === true,
    known: state.known,
    state,
    signing,
    refresh,
    gated,
    operationFor,
    describe: describeOperation,
    enroll: () => showing('enrol this device to confirm changes', () => presence.enroll({ askPassphrase: askSecret })).then((s) => { setState({ ...s, known: true }); return s }),
    replaceKey: () => showing('replace the confirmation authenticator', () => presence.replaceKey()).then((s) => { setState({ ...s, known: true }); return s }),
    enableTouchId: () => showing('turn on Touch ID unlock', () => presence.enableTouchId()),
    disableTouchId: () => showing('turn off Touch ID unlock', () => presence.disableTouchId()),
    touchIdUnlock: () => showing('unlock the vault', () => presence.touchIdUnlock()),
    lock: () => showing('lock the vault', () => presence.lock()),
  }), [state, signing, refresh, gated, showing, presence, askSecret])

  return value
}
