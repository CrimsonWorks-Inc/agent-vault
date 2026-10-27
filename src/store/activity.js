// Session activity and the access review report (F19).
//
// Pure: both read audit rows the caller hands them and records it already
// holds, and write nothing. They copy only the fields named here, never a
// record's `detail`, which can carry text from the upstream or the agent.
//
// History can be incomplete — the log started after the session, or was cut
// back, or lost its anchor — and missing records are never read as zero
// activity: the answer says so (`complete: false` with a `note`).
//
// Rows are the log's records: `request.allowed` keeps the request under
// `req` ({ method, path }), every denial kind has `decision: 'deny'` with
// `reason_code` and `rule`, and approval outcomes name only `approval_id`, so
// they are tied to a session through the `approval.requested` that named the
// grant. Pass the whole log (or at least every row of these kinds); rows of
// other sessions are ignored here.
//
// A request held for approval is ALSO written as `request.allowed` (status
// 202, no path: nothing reached the upstream), under the request id its
// `approval.requested` names. It is a hold, not a use, so it counts under
// `held` only: counting it as allowed would also mark the held method as
// used, which is the one thing an access review must not get wrong.

import { deny } from '../core/errors.js'
import * as ph from '../core/placeholder.js'
import { sessionExpiryMs, expiryWarning } from './vault.js'

const ANOMALIES = new Set(['audit.anchor_missing', 'audit.truncation_detected'])
const MAX_PATHS = 50
const DEFAULT_METHODS = ['GET', 'HEAD']

const list = (x) => (Array.isArray(x) ? x : Object.values(x || {}))
const isDenial = (r) => r.decision === 'deny'

/**
 * Whether a `request.allowed` row is a hold. The record's own `decision:
 * 'held'` says so where the gateway writes it; older logs only say it by
 * sharing a request id with an `approval.requested`, and by a 202 with no path.
 */
function holdsOf(rows) {
  const ids = new Set(rows.filter((r) => r.kind === 'approval.requested' && r.request_id != null).map((r) => r.request_id))
  return (r) => r.decision === 'held' || ids.has(r.request_id) || (r.req?.status === 202 && r.req?.path == null)
}
const methodOf = (r) => (typeof r.req?.method === 'string' ? r.req.method.toUpperCase() : null)

/**
 * The path a record names, as it may be shown. The log keeps paths scrubbed
 * and without a query already; this holds to that whatever wrote the row.
 */
function pathOf(r) {
  const p = r.req?.path
  if (typeof p !== 'string') return null
  let out = p.split('?')[0]
  for (const hit of ph.findAll(out).reverse()) out = `${out.slice(0, hit.offset)}[[av:placeholder]]${out.slice(hit.end)}`
  return out
}

function anomalyNote(rows) {
  const hit = rows.find((r) => ANOMALIES.has(r.kind))
  if (!hit) return null
  return hit.kind === 'audit.truncation_detected'
    ? 'the audit log was cut back at some point, so records may be missing'
    : 'the audit log lost its head anchor at some point, so records may be missing'
}

/** One session's activity, from the rows that concern it. */
export function summarizeSession(rows, { session, grants }) {
  const grantIds = new Set(list(grants).filter((g) => g.session_id === session.id).map((g) => g.id))
  const approvalIds = new Set(rows.filter((r) => r.kind === 'approval.requested' && grantIds.has(r.grant_id)).map((r) => r.approval_id))
  const own = rows.filter((r) => r.session_id === session.id ||
    (r.grant_id != null && grantIds.has(r.grant_id)) || (r.approval_id != null && approvalIds.has(r.approval_id)))

  const anomaly = anomalyNote(rows)
  const created = rows.some((r) => r.kind === 'session.created' && r.session_id === session.id)
  const note = anomaly ?? (created ? null : 'the audit log starts after this session was created, so its early activity is not in it')

  const isHold = holdsOf(rows)
  const requests = { allowed: 0, denied: 0, held: 0 }
  const approvals = { requested: 0, granted: 0, denied: 0, replayed: 0 }
  const paths = new Map()
  const denials = new Map()
  const tripwires = []
  let from = null
  let to = null
  for (const r of own) {
    if (from === null || r.seq < from.seq) from = r
    if (to === null || r.seq > to.seq) to = r
    const allowed = r.kind === 'request.allowed' && !isHold(r)
    const request = allowed || (isDenial(r) && r.session_id === session.id)
    if (r.kind === 'request.allowed') { if (allowed) requests.allowed++ }
    else if (isDenial(r) && r.session_id === session.id) {
      requests.denied++
      const code = typeof r.reason_code === 'string' ? r.reason_code : null
      const rule = typeof r.rule === 'string' ? r.rule : null
      const key = `${code}\u0000${rule}`
      const d = denials.get(key) ?? { code, rule, count: 0 }
      d.count++
      denials.set(key, d)
    } else if (r.kind === 'approval.requested') { requests.held++; approvals.requested++ }
    else if (r.kind === 'approval.granted') approvals.granted++
    else if (r.kind === 'approval.denied') approvals.denied++
    else if (r.kind === 'approval.replayed') approvals.replayed++
    else if (r.kind === 'tripwire.fired' && r.session_id === session.id) tripwires.push({ rule_id: r.rule_id ?? null, at: r.ts })
    if (request) {
      const method = methodOf(r)
      const path = pathOf(r)
      const key = `${method}\u0000${path}`
      const p = paths.get(key) ?? { method, path, count: 0, last_at: null }
      p.count++
      if (!p.last_at || r.ts > p.last_at) p.last_at = r.ts
      paths.set(key, p)
    }
  }
  return {
    complete: note === null, note,
    from_seq: from?.seq ?? null, to_seq: to?.seq ?? null, first_at: from?.ts ?? null, last_at: to?.ts ?? null,
    requests,
    paths: [...paths.values()].sort((a, b) => b.count - a.count || String(b.last_at).localeCompare(String(a.last_at))).slice(0, MAX_PATHS),
    denials: [...denials.values()].sort((a, b) => b.count - a.count),
    approvals,
    tripwires,
  }
}

/** The state a session is in now: an active one past its end has expired, noticed or not. */
function stateNow(s, now) {
  return s.state === 'active' && !(sessionExpiryMs(s) > now) ? 'expired' : s.state
}

/**
 * Every credential and every session in the window, for an access review:
 * what was used, what was refused, what was granted and never used.
 * `since` is an ISO date; rows before it are not counted.
 */
export function accessReport(rows, { sessions, grants, credentials, since }) {
  const sinceMs = typeof since === 'string' ? Date.parse(since) : NaN
  if (Number.isNaN(sinceMs)) throw deny('AV_POLICY_DENIED', 'since must be a date', { rule: 'report_since' })
  const now = Date.now()
  const isHold = holdsOf(rows)
  const used = (r) => r.kind === 'request.allowed' && !isHold(r)
  const inWindow = rows.filter((r) => Date.parse(r.ts) >= sinceMs)
  const allGrants = list(grants)
  const allSessions = list(sessions)
  const slugById = new Map(list(credentials).map((c) => [c.id, c.slug]))
  const createdRow = new Map(rows.filter((r) => r.kind === 'session.created').map((r) => [r.session_id, r]))

  const reported = allSessions.filter((s) => stateNow(s, now) === 'active' ||
    Date.parse(s.created_at) >= sinceMs || Date.parse(s.last_seen_at) >= sinceMs)
  const missing = reported.filter((s) => Date.parse(s.created_at) >= sinceMs && !createdRow.has(s.id))
  const anomaly = anomalyNote(rows)

  const count = (pred) => inWindow.filter(pred).length
  const credReport = list(credentials).map((c) => {
    const sessionIds = new Set(allGrants.filter((g) => g.credential_id === c.id).map((g) => g.session_id))
    const theirs = allSessions.filter((s) => sessionIds.has(s.id))
    const usedAt = rows.filter((r) => used(r) && r.credential_slug === c.slug).map((r) => r.ts).sort()
    return {
      slug: c.slug,
      sessions_active: theirs.filter((s) => stateNow(s, now) === 'active').length,
      sessions_total: theirs.length,
      requests: count((r) => used(r) && r.credential_slug === c.slug),
      denials: count((r) => isDenial(r) && r.credential_slug === c.slug),
      last_used_at: usedAt.at(-1) ?? null,
      expires_at: c.expires_at ?? null,
      expiry_warning: c.expiry_warning !== undefined ? c.expiry_warning : expiryWarning(c, now),
      health_status: c.health?.status ?? null,
      quarantined: !!c.quarantine,
    }
  })

  const sessionReport = reported.map((s) => {
    const theirGrants = allGrants.filter((g) => g.session_id === s.id)
    const usedMethods = new Set(rows.filter((r) => used(r) && r.session_id === s.id).map(methodOf))
    const granted = new Set(theirGrants.flatMap((g) => (Array.isArray(g.policy?.methods) ? g.policy.methods : DEFAULT_METHODS).map((m) => String(m).toUpperCase())))
    const elevated = Array.isArray(s.elevated) ? s.elevated : (Array.isArray(createdRow.get(s.id)?.elevated) ? createdRow.get(s.id).elevated : null)
    return {
      id: s.id, label: s.label ?? null, state: stateNow(s, now),
      creds: [...new Set(theirGrants.map((g) => slugById.get(g.credential_id)).filter(Boolean))],
      requests: count((r) => used(r) && r.session_id === s.id),
      denials: count((r) => isDenial(r) && r.session_id === s.id),
      last_seen_at: s.last_seen_at ?? null,
      elevated: elevated ? [...elevated] : null,
      unused_methods: [...granted].filter((m) => !usedMethods.has(m)).sort(),
    }
  })

  return {
    generated_at: new Date(now).toISOString(), since: new Date(sinceMs).toISOString(),
    complete: !anomaly && !missing.length,
    credentials: credReport,
    sessions: sessionReport,
  }
}
