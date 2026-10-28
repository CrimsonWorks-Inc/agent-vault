// Sessions an agent has asked for, and a human has not yet answered.
//
// An agent cannot create a session: that is capability, and capability needs a
// human. But it could not ask for one either, which left it at a dead end —
// and two error paths told it to call `vault_request_session`, a tool that did
// not exist. This is that tool's other half.
//
// The shape is the one the HTTP approval flow already uses: the agent proposes,
// nothing exists until a human says yes, and the answer is bound to the exact
// proposal that was shown. Today's audit found the HTTP version binding
// everything about a request except its headers, which is how an approved POST
// became a DELETE — so the rule here is that what the human saw IS what gets
// created, with no field left outside the binding.
//
// What approval supplies is presence, not permission. Every ceiling still
// applies afterwards: the credential's own hosts, the profile's deny paths,
// and the policy intersection, which can only narrow. A human approving a
// greedy proposal cannot widen it past what the credential allows.

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto'
import { id } from '../store/ids.js'
import { deny } from '../core/errors.js'
import * as policyMod from '../core/policy.js'

// An agent can ask as often as it likes, so the store is bounded the way the
// approvals map is. A flood must not push out a request a human is reading.
const MAX_PENDING = 64
const PENDING_TTL_MS = 30 * 60_000
const COLLECT_TTL_MS = 5 * 60_000
// How long a settled request is kept so its asker can poll the outcome. Past
// this it is forgotten: a finished request is history, and history belongs in
// the audit log, not in the waiting room.
const SETTLED_TTL_MS = 30 * 60_000
// Everything held, pending or settled. Settled ones are evicted first.
const MAX_ITEMS = MAX_PENDING * 4

const sha256 = (s) => createHash('sha256').update(String(s)).digest('hex')

/**
 * The fields a proposal may name. Anything else is not part of the offer.
 *
 * Every one of the later ones only narrows a grant (a rate, a quota, routes,
 * payload rules, a spend limit, a shorter grant), so an agent may ask for
 * them; a human still answers. `approval` and `infinite` are not here: only
 * the owner sets those (OWNER_FIELDS).
 */
const FIELDS = [
  'cred', 'methods', 'paths', 'budget', 'uses', 'ttl_minutes',
  'rate', 'max_concurrent', 'quota', 'routes', 'payload', 'redirects',
  'spend_tokens', 'spend_usd', 'grant_ttl_minutes',
]

/**
 * A stable description of exactly what was proposed.
 *
 * The human approves this and nothing else. Whatever is not in here is what an
 * agent could change between the approval and the creation — which is the bug
 * the HTTP approvals had, found by an audit today, where the headers were
 * outside the hash and an approved POST arrived as a DELETE.
 */
export function proposalOf(input = {}) {
  const out = {}
  for (const f of FIELDS) if (input[f] !== undefined && input[f] !== null) out[f] = input[f]
  return out
}

/**
 * The fields only the owner may set: an approval mode and an unlimited
 * lifetime. Either one can take the human out of the loop for good, so an
 * agent may not ask for them at all — a proposal carrying one is refused, not
 * trimmed, so the agent never believes it asked for something it did not.
 */
export const OWNER_FIELDS = ['approval', 'infinite']

/**
 * A human's overrides, read once. The daemon's binding, its settle path and
 * the web UI's signed operation all call this, so none of them can disagree
 * about which fields a decision carried.
 */
export function overridesOf(input = {}) {
  const out = proposalOf(input)
  for (const f of OWNER_FIELDS) if (input?.[f] !== undefined && input?.[f] !== null) out[f] = input[f]
  return out
}

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])

/**
 * Why a session spec needs fresh presence. [] means it does not.
 *
 * `spec` is a session-create input: `{cred, …}` or `{grants: […]}`. One
 * function decides this for creating, deciding and bulk-deciding, so no path
 * can call an elevated session ordinary.
 *
 * Fail-closed: anything it cannot read counts as elevated, whatever its
 * approval mode. `methods` absent or null is the creation default, GET and
 * HEAD, which is how #createSession reads it too; `methods` or `routes`
 * present as anything but a list of method names is unreadable. An unknown
 * approval mode is not read here at all: #planSession refuses it.
 */
export function elevationOf(spec) {
  const out = []
  try {
    if (!spec || typeof spec !== 'object' || Array.isArray(spec)) return ['approval_auto_writes']
    if (spec.infinite === true) out.push('infinite')
    if (spec.grants !== undefined && !Array.isArray(spec.grants)) return [...out, 'approval_auto_writes']
    const grants = spec.grants !== undefined ? spec.grants : [spec]
    if (grants.some((g) => !readable(g) || (g.approval === 'auto' && permitsWrite(g)))) {
      out.push('approval_auto_writes')
    }
    return out
  } catch {
    return [...new Set([...out, 'approval_auto_writes'])]
  }
}

const names = (v) => Array.isArray(v) && v.every((m) => typeof m === 'string')

/** Whether elevationOf can tell what a grant spec permits. */
function readable(g) {
  if (!g || typeof g !== 'object' || Array.isArray(g)) return false
  if (g.methods != null && !names(g.methods)) return false
  // Method-bound routes (F3) name methods of their own.
  if (g.routes != null && !(Array.isArray(g.routes) && g.routes.every((r) => r && names(r.methods)))) return false
  return true
}

/** Whether a readable grant spec permits a method outside GET, HEAD and OPTIONS. */
function permitsWrite(g) {
  const named = [...(g.methods == null ? ['GET', 'HEAD'] : g.methods)]
  for (const r of g.routes || []) named.push(...r.methods)
  return named.some((m) => !SAFE_METHODS.has(m.toUpperCase()))
}

export function fingerprint(proposal) {
  const canonical = JSON.stringify(proposal, Object.keys(proposal).sort())
  return createHash('sha256').update(canonical).digest('hex').slice(0, 16)
}

/** One line a human can read without knowing the schema. */
export function summarize(p) {
  const bits = [`session for ${p.cred}`]
  bits.push(listOf(p.methods, ['GET']).join(','))
  bits.push(listOf(p.paths, ['/**']).join(' '))
  if (p.budget) bits.push(`${p.budget} requests`)
  if (p.uses) bits.push(`${p.uses}-use placeholder`)
  if (p.ttl_minutes) bits.push(`${p.ttl_minutes}m`)
  // The narrowing fields an agent may also ask for. Each is shown, because a
  // human approves the summary; a field missing here is one nobody read.
  if (Array.isArray(p.routes)) {
    bits.push(`routes ${p.routes.map((r) => `${listOf(r?.methods, []).join(',')} ${listOf(r?.paths, []).join(' ')}`).join(' | ')}`)
  }
  if (p.rate != null) bits.push(`rate ${windowText(p.rate, 'per')}`)
  if (p.max_concurrent != null) bits.push(`${p.max_concurrent} at once`)
  if (p.quota != null) bits.push(`quota ${windowText(p.quota, 'window')}`)
  if (p.redirects != null) bits.push(`follows ${p.redirects} redirects`)
  if (p.spend_tokens != null) bits.push(`${p.spend_tokens} tokens`)
  if (p.spend_usd != null) bits.push(`$${p.spend_usd}`)
  if (p.grant_ttl_minutes != null) bits.push(`grant ${p.grant_ttl_minutes}m`)
  if (p.payload != null) bits.push('payload rules')
  if (p.approval != null) bits.push(`approval ${p.approval}`)
  if (p.infinite === true) bits.push('never expires')
  const line = bits.join(' · ')
  // A request that came from a template says which one, first.
  return typeof p.template === 'string' ? `template ${p.template} v${p.template_version} · ${line}` : line
}

const listOf = (v, fallback) => (Array.isArray(v) ? v.map(String) : fallback)
const windowText = (w, key) => (w && typeof w === 'object' ? `${w.count}/${w[key]}` : String(w))

// ------------------------------------------------------------- templates

/** What a template override may name (F17). Every one of them only narrows. */
const TEMPLATE_OVERRIDES = ['methods', 'paths', 'budget', 'uses', 'grant_ttl_minutes', 'approval', 'ttl_hours', 'infinite', 'label']
const APPROVAL_MODES = ['each', 'on-write', 'first-use', 'auto']
// What a session without ttl_hours lives for: the store's default lifetime.
// An override is held to it, so "12 hours" on a template that named none
// cannot outlast the session the template would have made.
const DEFAULT_TTL_HOURS = 8

const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v)
const isNames = (v) => Array.isArray(v) && v.every((x) => typeof x === 'string' && x)

/**
 * A template with a human's overrides on top, as a session-create input (F17).
 *
 * A template is configuration, not standing approval, and its overrides can
 * only narrow it: applied to every grant, methods are intersected, paths are
 * intersected the way policy layers are, budget, uses and grant_ttl_minutes
 * take the minimum, approval takes the stricter mode, ttl_hours takes the
 * minimum (an infinite template given one becomes finite), infinite can only
 * be cleared, and label may be replaced. Any other key is refused, never
 * ignored, so nobody believes they narrowed something they did not.
 *
 * `budgetDefault(grantSpec)`, when given, is the budget a grant gets when the
 * template names none (the profile's default). Without it, a budget override
 * on such a grant is refused: there is nothing to take the minimum with, and
 * taking the override as given could raise the default.
 */
export function resolveTemplate(template, overrides = {}, { budgetDefault = null } = {}) {
  const refuse = (detail, rule = 'template_override') => deny('AV_POLICY_DENIED', detail, {
    rule, hint: `A template can only be narrowed. Overrides are: ${TEMPLATE_OVERRIDES.join(', ')}.`,
  })
  if (!isObject(template) || !isObject(template.spec)) throw refuse('that template has no readable spec', 'session_shape')
  if (!isObject(overrides)) throw refuse('overrides must be an object')
  for (const k of Object.keys(overrides)) {
    if (!TEMPLATE_OVERRIDES.includes(k)) throw refuse(`a template cannot be overridden with ${k}`)
  }
  const o = overrides
  const has = (k) => o[k] !== undefined
  const spec = structuredClone(template.spec)
  const grants = spec.grants !== undefined ? spec.grants : [spec]
  if (!Array.isArray(grants) || !grants.every(isObject)) throw refuse('the template\'s grants cannot be read', 'session_shape')

  if (has('methods') && !isNames(o.methods)) throw refuse('methods must be a list of method names', 'policy_invalid')
  if (has('paths') && !isNames(o.paths)) throw refuse('paths must be a list of path globs', 'policy_invalid')
  if (has('approval') && !APPROVAL_MODES.includes(o.approval)) {
    throw deny('AV_POLICY_DENIED', 'approval is not one of the four modes', { rule: 'approval', hint: 'approval is one of: each, on-write, first-use, auto' })
  }
  const budget = has('budget') ? policyMod.budgetInteger(o.budget) : null
  if (has('budget') && budget === null) throw refuse('budget must be a whole number of requests, 0 or more', 'policy_invalid')
  for (const k of ['uses', 'grant_ttl_minutes']) {
    if (has(k) && !(Number.isInteger(o[k]) && o[k] >= 1)) throw refuse(`${k} must be a whole number, 1 or more`, k === 'uses' ? 'policy_invalid' : 'grant_ttl')
  }
  const min = (a, b) => (a == null ? b : Math.min(a, b))

  for (const g of grants) {
    if (has('methods')) {
      const base = g.methods == null ? ['GET', 'HEAD'] : g.methods
      if (!isNames(base)) throw refuse('the template\'s methods cannot be read', 'policy_invalid')
      g.methods = o.methods.filter((m) => base.includes(m))
    }
    if (has('paths')) {
      const base = g.paths == null ? ['/**'] : g.paths
      if (!isNames(base)) throw refuse('the template\'s paths cannot be read', 'policy_invalid')
      // The containment policy layers use, so a path survives only where the
      // template already allowed it.
      g.paths = policyMod.intersect([{ paths: base }, { paths: o.paths }]).paths
    }
    if (has('budget')) {
      let base = g.budget
      if (base == null) {
        base = typeof budgetDefault === 'function' ? budgetDefault(g) : null
        if (!Number.isInteger(base)) throw refuse('this template names no budget to narrow', 'policy_invalid')
      }
      const baseInt = policyMod.budgetInteger(base)
      if (baseInt === null) throw refuse('the template\'s budget cannot be read', 'policy_invalid')
      g.budget = Math.min(baseInt, budget)
    }
    for (const k of ['uses', 'grant_ttl_minutes']) {
      if (!has(k)) continue
      if (g[k] != null && !(Number.isInteger(g[k]) && g[k] >= 1)) throw refuse(`the template's ${k} cannot be read`, 'policy_invalid')
      g[k] = min(g[k], o[k])
    }
    if (has('approval')) {
      const base = g.approval ?? 'on-write'
      const order = policyMod.APPROVAL_ORDER
      // An unknown stored mode is the strictest, never auto.
      g.approval = !order.includes(base) ? 'each' : (order.indexOf(o.approval) > order.indexOf(base) ? o.approval : base)
    }
  }

  if (has('infinite')) {
    if (typeof o.infinite !== 'boolean') throw refuse('infinite is true or false', 'ttl')
    // Only cleared: an override never makes a session last longer.
    if (o.infinite === true && spec.infinite !== true) throw refuse('an override cannot remove a template\'s lifetime')
    if (o.infinite === false) delete spec.infinite
  }
  if (has('ttl_hours')) {
    if (typeof o.ttl_hours !== 'number' || !Number.isFinite(o.ttl_hours) || !(o.ttl_hours > 0)) {
      throw deny('AV_POLICY_DENIED', 'ttl_hours must be a positive number of hours', { rule: 'ttl' })
    }
    if (spec.infinite === true) {
      delete spec.infinite
      spec.ttl_hours = o.ttl_hours
    } else {
      const base = spec.ttl_hours ?? DEFAULT_TTL_HOURS
      if (typeof base !== 'number' || !Number.isFinite(base) || !(base > 0)) throw refuse('the template\'s ttl_hours cannot be read', 'ttl')
      spec.ttl_hours = Math.min(base, o.ttl_hours)
    }
  }
  if (has('label')) {
    if (typeof o.label !== 'string' || o.label.length > 80) throw refuse('label is a string of at most 80 characters', 'policy_invalid')
    spec.label = o.label
  }
  return spec
}

/** The grant specs of a session-create input, whichever form it has. */
export function grantSpecsOf(spec) {
  if (!isObject(spec)) return []
  if (spec.grants !== undefined) return Array.isArray(spec.grants) ? spec.grants.filter(isObject) : []
  return [spec]
}

/** The credentials a template covers, in order. */
export function templateCreds(spec) {
  return grantSpecsOf(spec).map((g) => g.cred).filter((c) => typeof c === 'string')
}

/** One line per template, in the words a session request summary uses. */
export function templateSummary(spec) {
  const grants = grantSpecsOf(spec)
  const lines = grants.map((g) => summarize({
    ...g,
    infinite: spec.infinite === true ? true : undefined,
    ttl_minutes: typeof spec.ttl_hours === 'number' ? Math.round(spec.ttl_hours * 60) : undefined,
  }))
  return lines.join(' + ')
}

export class SessionRequests {
  /**
   * @param {{audit: object|null}} vault
   *
   * The VAULT, not its audit handle. A vault with a passphrase comes up locked
   * and sets `audit` to null until someone unlocks it, so capturing the handle
   * at construction captured null — and every `audit?.write` after that was a
   * silent no-op. An agent asking for capability went unrecorded on every
   * properly configured vault, which is the one kind where it matters.
   *
   * Locking sets it back to null too, so there is no moment at which caching it
   * is safe. Read it through the vault, every time.
   */
  constructor(vault = null) {
    this.items = new Map()
    this.vault = vault
    // Told when a request starts waiting (F14), the way the pipeline tells
    // it about a held request. A hook that throws never stops the request.
    this.onPending = null
    this.#load()
  }

  /**
   * Read back the questions a human has not answered.
   *
   * These used to live only in memory, so every daemon restart threw them away
   * — and a restart is not rare: `agent-vault upgrade` does one, and launchd
   * will too. In practice this was the feature's dominant failure mode rather
   * than an edge case: a human sent a request, the daemon restarted, and the
   * request vanished with nothing to say it ever existed.
   *
   * A pending request holds no secret. It is a credential slug, a policy
   * somebody is proposing, and a sentence an agent wrote — the same kind of
   * thing already sitting in vault.json beside it. So it persists, and it
   * persists even while the vault is LOCKED, because none of it needs the key.
   */
  #load() {
    const rows = this.vault?.db?.kv?.session_requests
    if (!Array.isArray(rows)) return
    for (const row of rows) {
      // `result` is never persisted, so anything approved-but-uncollected comes
      // back without its token. That is the right way round: the token would be
      // a live capability written to disk for no one, and a human approving
      // again is a small price for never doing that.
      if (row?.id) this.items.set(row.id, { ...row, result: null })
    }
  }

  /**
   * Write the questions back. Never the answers.
   *
   * `result` carries a session token, and a token on disk that nobody asked for
   * is a capability lying around. It stays in memory: if the daemon restarts
   * between an approval and its collection, the human approves once more.
   */
  #save() {
    if (!this.vault?.db?.kv) return
    const keep = [...this.items.values()]
      .filter((r) => r.state === 'pending' || r.state === 'denied')
      .map(({ result, ...rest }) => rest)
    const before = JSON.stringify(this.vault.db.kv.session_requests ?? null)
    if (before === JSON.stringify(keep)) return
    this.vault.db.kv.session_requests = keep
    // Not durable: a question lost to a power cut is one an agent asks again,
    // and the fsync cost belongs to key material.
    try { this.vault.save?.({ durable: false }) } catch { /* a locked or absent vault is not fatal here */ }
  }

  get audit() { return this.vault?.audit ?? null }

  #sweep() {
    const now = Date.now()
    const sizeBefore = this.items.size
    const statesBefore = [...this.items.values()].map((r) => r.state).join(',')
    for (const [key, r] of this.items) {
      const age = now - Date.parse(r.created_at)
      if (r.state === 'pending' && age > PENDING_TTL_MS) { this.items.delete(key); continue }
      // Settled and seen out. Nothing deleted these, and denied ones are
      // persisted, so they piled up for the life of the vault.
      const settledFor = now - Date.parse(r.decided_at || r.created_at)
      if (r.state !== 'pending' && !r.result && settledFor > SETTLED_TTL_MS) { this.items.delete(key); continue }
      // An approved request holds a live token until the agent collects it.
      // Uncollected, that is a capability sitting in memory with nobody
      // waiting for it, so it does not sit there indefinitely.
      if (r.state === 'approved' && r.result && now - Date.parse(r.decided_at) > COLLECT_TTL_MS) {
        r.result = null
        r.state = 'expired'
        this.audit?.write('session_request.uncollected', { request_id: r.id })
      }
    }
    if (this.items.size !== sizeBefore
      || [...this.items.values()].map((r) => r.state).join(',') !== statesBefore) this.#save()
  }

  /**
   * Record a proposal. Creates nothing: no session, no token, no grant. The
   * only thing that exists afterwards is a question for a human.
   */
  propose({ proposal, reason, fromTemplate = false }) {
    // The route refuses these before it gets here; this is for any other
    // caller. An agent's proposal never carries an owner field. The one
    // exception is a template's own (F17): the owner wrote it, and the daemon
    // copied it into a proposal that names that template.
    const templated = fromTemplate === true && typeof proposal?.template === 'string'
    if (!templated && OWNER_FIELDS.some((f) => proposal?.[f] !== undefined)) {
      const err = new Error('only the owner can choose the approval mode or an unlimited lifetime')
      err.code = 'AV_OWNER_ONLY'
      throw err
    }
    this.#sweep()
    // Only what is actually waiting counts. This counted every record in
    // every state, and settled ones were never removed, so after 64 decisions
    // in a vault's life — denials survive restarts — no agent could ask for a
    // session again: a bound on the wrong thing.
    const waiting = [...this.items.values()].filter((r) => r.state === 'pending').length
    if (waiting >= MAX_PENDING) {
      // Refuse rather than evict, so a flood cannot push out the request a
      // human is in the middle of reading.
      const err = new Error('too many session requests are already waiting')
      err.code = 'AV_TOO_MANY_REQUESTS'
      throw err
    }
    // Memory stays bounded by forgetting the oldest SETTLED requests, never a
    // pending one.
    for (const [key, r] of this.items) {
      if (this.items.size < MAX_ITEMS) break
      if (r.state !== 'pending') this.items.delete(key)
    }
    // Handed to the asker once and stored only as a hash. The request id is
    // listed to anyone on the socket, so the id alone let one agent collect
    // the session a human had granted to another.
    const collectSecret = randomBytes(24).toString('base64url')
    const record = {
      id: id.sessionRequest(),
      collect_hash: sha256(collectSecret),
      proposal,
      fingerprint: fingerprint(proposal),
      summary: summarize(proposal),
      // The agent wrote this. It is shown to the human as a claim and is
      // never treated as a fact about anything.
      reason_untrusted: reason || null,
      state: 'pending',
      created_at: new Date().toISOString(),
      decided_at: null,
      result: null,
    }
    this.items.set(record.id, record)
    this.#save()
    this.audit?.write('session_request.opened', {
      request_id: record.id, summary: record.summary, fingerprint: record.fingerprint,
      agent_reason_untrusted: record.reason_untrusted,
    })
    try { this.onPending?.({ kind: 'session', id: record.id, headline: record.summary, created_at: record.created_at }) } catch { /* a signal, never the request */ }
    return { record, collectSecret }
  }

  /**
   * Whether `secret` is the one this request was opened with. Compared in
   * constant time over digests; a request with no stored hash — one opened
   * before secrets existed — can be collected by nobody but the human's own
   * decision.
   */
  static mayCollect(record, secret) {
    if (!record?.collect_hash || typeof secret !== 'string' || !secret) return false
    const want = Buffer.from(record.collect_hash, 'hex')
    const got = Buffer.from(sha256(secret), 'hex')
    return want.length === got.length && timingSafeEqual(want, got)
  }

  get(id_) { this.#sweep(); return this.items.get(id_) || null }

  /** Called by whoever settled or collected a request, so the change survives. */
  persist() { this.#save() }

  pending() {
    this.#sweep()
    return [...this.items.values()].filter((r) => r.state === 'pending')
  }

  /** Public view: never includes the token, which is collected once. */
  static redact(r) {
    return {
      id: r.id,
      summary: r.summary,
      proposal: r.proposal,
      fingerprint: r.fingerprint,
      agent_reason_untrusted: r.reason_untrusted,
      state: r.state,
      created_at: r.created_at,
      decided_at: r.decided_at,
    }
  }
}

export { MAX_PENDING, PENDING_TTL_MS, COLLECT_TTL_MS, SETTLED_TTL_MS }
