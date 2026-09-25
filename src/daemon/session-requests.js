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

import { createHash } from 'node:crypto'
import { id } from '../store/ids.js'

// An agent can ask as often as it likes, so the store is bounded the way the
// approvals map is. A flood must not push out a request a human is reading.
const MAX_PENDING = 64
const PENDING_TTL_MS = 30 * 60_000
const COLLECT_TTL_MS = 5 * 60_000

/** The fields a proposal may name. Anything else is not part of the offer. */
const FIELDS = ['cred', 'methods', 'paths', 'budget', 'uses', 'ttl_minutes']

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

export function fingerprint(proposal) {
  const canonical = JSON.stringify(proposal, Object.keys(proposal).sort())
  return createHash('sha256').update(canonical).digest('hex').slice(0, 16)
}

/** One line a human can read without knowing the schema. */
export function summarize(p) {
  const bits = [`session for ${p.cred}`]
  bits.push((p.methods || ['GET']).join(','))
  bits.push((p.paths || ['/**']).join(' '))
  if (p.budget) bits.push(`${p.budget} requests`)
  if (p.uses) bits.push(`${p.uses}-use placeholder`)
  if (p.ttl_minutes) bits.push(`${p.ttl_minutes}m`)
  return bits.join(' · ')
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
  propose({ proposal, reason }) {
    this.#sweep()
    if (this.items.size >= MAX_PENDING) {
      // Refuse rather than evict, so a flood cannot push out the request a
      // human is in the middle of reading.
      const err = new Error('too many session requests are already waiting')
      err.code = 'AV_TOO_MANY_REQUESTS'
      throw err
    }
    const record = {
      id: id.sessionRequest(),
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
    return record
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

export { MAX_PENDING, PENDING_TTL_MS, COLLECT_TTL_MS }
