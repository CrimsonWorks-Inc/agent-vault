// Desktop notifications (F14): a signal, never an approval channel. The
// notice only opens Approvals, where a decision still needs a fingerprint.
// Only while this tab is open; on or off is remembered in localStorage.

import { clip } from './text.js'

export const NOTIFY_KEY = 'agent-vault.notify'

export function notificationsOn(storage) {
  try { return storage?.getItem(NOTIFY_KEY) === 'on' } catch { return false }
}

export function setNotifications(storage, on) {
  try { storage?.setItem(NOTIFY_KEY, on ? 'on' : 'off') } catch { /* nothing to remember it in */ }
}

/** The agent's headline, controls out, cut to 120 characters (the CLI's watch). */
export function notificationText(item) {
  const lead = item?.kind === 'request' ? 'Held request: ' : 'Session requested: '
  return clip(`${lead}${String(item?.headline ?? '')}`, 120)
}

/**
 * What is new since the last look. What was waiting when the page opened is
 * on screen already, so the first look primes and announces nothing.
 */
export function createWatcher() {
  const seen = new Set()
  let primed = false
  return (pending) => {
    const fresh = pending.filter((p) => !seen.has(p.id))
    for (const p of pending) seen.add(p.id)
    if (!primed) { primed = true; return [] }
    return fresh
  }
}

/** The notice's body for a batch of fresh items. */
export function batchText(fresh) {
  if (!fresh.length) return ''
  return fresh.length > 1 ? `${notificationText(fresh[0])} (and ${fresh.length - 1} more)` : notificationText(fresh[0])
}

/**
 * Raise the desktop notice for fresh items. A signal, never an approval
 * channel: it carries the daemon's headline (never the agent's claim), has
 * no actions, and clicking it only opens Approvals at the first item.
 */
export function showNotice(fresh, { Notification: N = globalThis.Notification, focus = () => globalThis.focus?.(), location = globalThis.location } = {}) {
  if (!fresh?.length || typeof N === 'undefined' || N.permission !== 'granted') return null
  try {
    const n = new N('agent-vault', { body: batchText(fresh), tag: 'agent-vault-pending' })
    n.onclick = () => { focus(); location.hash = `#approvals/${encodeURIComponent(fresh[0].id)}` }
    return n
  } catch { return null /* a browser that will not show one has nothing to fall back to */ }
}
