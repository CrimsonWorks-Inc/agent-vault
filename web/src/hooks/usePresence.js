// Touch ID confirmation for the whole app (contract U4, U7).
//
// The provider (App.jsx) owns one lib/presence.js instance. Every gated call
// goes through `gated(operation, send)`, which puts the operation's name on
// screen ("Touch ID to revoke session s_123", components/ui/PresenceStatus)
// BEFORE the platform dialog opens, because that dialog says who is asking
// and never what for.

import { createContext, useCallback, useContext, useMemo, useRef, useState } from 'react'
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

  // Whether the server has been asked yet. The App shell asks on mount, so
  // every page, a deep link included, sees the real enrolment; a gated call
  // that races ahead of that first answer asks for itself rather than
  // reporting "No authenticator enrolled" for a key that is there.
  const known = useRef(false)

  const refresh = useCallback(async () => {
    const s = await presence.refresh()
    known.current = true
    setState({ ...s, known: true })
    return s
  }, [presence])

  /** Run a change to the authenticators, then re-read the enrolment, whatever happened. */
  const changing = useCallback(async (fn) => {
    try { return await fn() } finally { await refresh() }
  }, [refresh])

  /**
   * Show what is being signed for as long as `fn` runs. Committed
   * synchronously, so the line is in the DOM before the challenge is even
   * requested, and so before the platform dialog can open.
   */
  const showing = useCallback(async (label, fn) => {
    flushSync(() => setSigning({ label }))
    try { return await fn() } finally { setSigning(null) }
  }, [])

  const gated = useCallback(async (operation, send, { label } = {}) => {
    if (!known.current) await refresh()
    return showing(label || describeOperation(operation), () => presence.gated(operation, send))
  }, [presence, showing, refresh])

  const value = useMemo(() => ({
    enrolled: state.enrolled === true,
    known: state.known,
    state,
    signing,
    refresh,
    gated,
    operationFor,
    describe: describeOperation,
    enroll: () => changing(() => showing('enrol this device to confirm changes', () => presence.enroll({ askPassphrase: askSecret }))),
    replaceKey: () => changing(() => showing('replace the confirmation authenticator', () => presence.replaceKey())),
    enableTouchId: () => changing(() => showing('turn on Touch ID unlock', () => presence.enableTouchId())),
    disableTouchId: () => changing(() => showing('turn off Touch ID unlock', () => presence.disableTouchId())),
    touchIdUnlock: () => showing('unlock the vault', () => presence.touchIdUnlock()),
    lock: () => showing('lock the vault', () => presence.lock()),
  }), [state, signing, refresh, gated, showing, changing, presence, askSecret])

  return value
}
