// Dates, durations and counts, worded the way app.html worded them so the
// two pages agree while both exist.

const now = () => Date.now()

/** "12s ago", "4m ago", "3h ago". */
export function ago(iso, at = now()) {
  const s = Math.max(0, (at - Date.parse(iso)) / 1000)
  if (!Number.isFinite(s)) return ''
  if (s < 60) return `${Math.floor(s)}s ago`
  if (s < 3600) return `${Math.floor(s / 60)}m ago`
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`
  return `${Math.floor(s / 86400)}d ago`
}

/**
 * Time left on a session or grant. An infinite one has nothing to count down
 * to, and says so in words: "never expires", never a far-off date.
 */
export function until(iso, { infinite = false } = {}, at = now()) {
  if (infinite === true || iso === null) return 'never expires'
  const s = (Date.parse(iso) - at) / 1000
  if (!Number.isFinite(s) || s <= 0) return 'expired'
  if (s < 3600) return `${Math.max(1, Math.floor(s / 60))}m left`
  if (s < 86400 * 2) return `${Math.floor(s / 3600)}h left`
  return `${Math.floor(s / 86400)}d left`
}

/** The earlier of the expiry you set and the one the upstream reported (F10). */
export function soonestExpiry(c) {
  const at = [c?.expires_at, c?.health?.observed_expires_at]
    .filter((x) => typeof x === 'string').map((x) => Date.parse(x)).filter(Number.isFinite)
  return at.length ? Math.min(...at) : null
}

/** "expires in 3d", "expired", or "expires soon" when no date is known. */
export function expiresIn(ms, at = now()) {
  if (ms === null || ms === undefined) return 'expires soon'
  const days = Math.ceil((ms - at) / 86_400_000)
  return days <= 0 ? 'expired' : `expires in ${days}d`
}

/** 1 credential, 2 credentials. */
export function plural(n, one, many = `${one}s`) {
  return `${n} ${n === 1 ? one : many}`
}

/** 12,480 */
export function count(n) {
  return Number.isFinite(n) ? new Intl.NumberFormat('en-US').format(n) : '—'
}

/** 2026-11-01 14:03 (local), for tables. */
export function stamp(iso) {
  const t = Date.parse(iso)
  if (!Number.isFinite(t)) return ''
  const d = new Date(t)
  const p = (x) => String(x).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`
}

/** A tripwire window in its largest whole unit: 3600 -> 1h. */
export function span(seconds) {
  const w = Number(seconds)
  if (!Number.isFinite(w)) return '?'
  return w % 3600 === 0 ? `${w / 3600}h` : w % 60 === 0 ? `${w / 60}m` : `${w}s`
}

/** `replay  AV_PH_REPLAY  1 in 10m  → revoke_session`, as app.html printed it. */
export function tripwireRuleText(r) {
  const what = (r?.codes || []).length ? r.codes.join(',') : r?.rule_prefix ? `${r.rule_prefix}*` : '?'
  return `${r?.id}  ${what}  ${r?.threshold} in ${span(r?.window_s)}  → ${r?.action}`
}

/** One effective-policy value in words. */
export function policyValue(v) {
  if (v === null || v === undefined) return 'none'
  if (Array.isArray(v)) return v.length ? v.map((x) => (typeof x === 'object' ? JSON.stringify(x) : String(x))).join(', ') : 'none'
  if (typeof v === 'object') return JSON.stringify(v)
  return String(v)
}
