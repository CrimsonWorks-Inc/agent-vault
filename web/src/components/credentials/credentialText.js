// What the Credentials page says about a credential, ported from app.html's
// credentialBadges, pinsText, testLine and the row's meta as pure functions.

import { ago, expiresIn, soonestExpiry } from '../../lib/format.js'

/** The kinds a credential can be stored as, in app.html's order. */
export const KINDS = [
  { value: 'github', label: 'github' },
  { value: 'slack', label: 'slack' },
  { value: 'anthropic', label: 'anthropic' },
  { value: 'openai', label: 'openai' },
  { value: 'google-genai', label: 'google-genai' },
  { value: 'http', label: 'http (generic)' },
]

/** Badges for what a human should notice (F10, F16): `[{ tone, text }]`. */
export function credentialBadges(c) {
  const out = []
  if (c?.quarantine) out.push({ tone: 'crit', text: 'quarantined' })
  if (c?.expiry_warning === 'expired') out.push({ tone: 'crit', text: 'expired' })
  else if (c?.expiry_warning === 'soon') out.push({ tone: 'warn', text: expiresIn(soonestExpiry(c)) })
  const status = c?.health?.status
  if (status === 'ok') out.push({ tone: 'ok', text: 'healthy' })
  else if (typeof status === 'string' && status !== 'unknown') out.push({ tone: 'warn', text: status })
  return out
}

/** `pinned: api.github.com (2)`, read-only: pinning stays in the CLI (F11). */
export function pinsText(pins) {
  const hosts = Object.entries(pins && typeof pins === 'object' ? pins : {})
    .filter(([, n]) => Number.isInteger(n) && n > 0)
  return hosts.length ? `pinned: ${hosts.map(([h, n]) => `${h} (${n})`).join(', ')}` : ''
}

/** The facts under a credential's name, as `[[label, value]]`. */
export function credentialFacts(c) {
  const f = c?.fields?.[0] || {}
  const version = `${f.version ?? 1}${f.rotated_at ? `, rotated ${ago(f.rotated_at)}` : ''}`
  return [
    ['host', c?.connector?.host || 'no host set'],
    ['fingerprint', f.fp8 || ''],
    ['injected at', (f.sites || []).join(', ')],
    ['version', version],
  ]
}

/** "expires in 3d (2026-11-04, as the upstream reports it)", or ''. */
export function expiryLine(c) {
  const at = soonestExpiry(c)
  if (at === null) return ''
  return `${expiresIn(at)} (${new Date(at).toISOString().slice(0, 10)}${c?.health?.observed_expires_at ? ', as the upstream reports it' : ''})`
}

/** "quarantined 3h ago by tripwire (tripwire replay)". The reason is shown apart, as agent text. */
export function quarantineLine(q) {
  if (!q) return ''
  return `quarantined ${q.since ? ago(q.since) : ''} by ${q.by ?? ''}${q.rule_id ? ` (tripwire ${q.rule_id})` : ''}`.replace(/\s+/g, ' ')
}

/**
 * The last probe (F12) in parts: `{ ok, status, rest }`, or `{ error }`.
 * "test: ok · 200 · 41ms · scopes: repo, read:org".
 */
export function testParts(t) {
  if (t?.error) return { error: String(t.error) }
  const scopes = Array.isArray(t?.scopes) && t.scopes.length ? ` · scopes: ${t.scopes.join(', ')}` : ''
  return { ok: t?.status === 'ok', status: String(t?.status ?? ''), rest: ` · ${t?.http_status ?? 'no answer'} · ${t?.latency_ms}ms${scopes}` }
}

/** Midnight UTC of a date input's day, as app.html sent it. */
export const expiryIso = (day) => new Date(`${day}T00:00:00Z`).toISOString()

/** The YYYY-MM-DD a date input shows for a stored expiry. */
export const expiryDay = (c) => (typeof c?.expires_at === 'string' ? c.expires_at.slice(0, 10) : '')

/** "; 2 held requests denied", or ''. */
export const heldDenied = (n) => {
  const k = Number(n) || 0
  return k ? `; ${k} held request${k > 1 ? 's' : ''} denied` : ''
}
