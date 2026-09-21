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
  constructor(audit = null) {
    this.items = new Map()
    this.audit = audit
  }

  #sweep() {
    const now = Date.now()
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
    this.audit?.write('session_request.opened', {
      request_id: record.id, summary: record.summary, fingerprint: record.fingerprint,
      agent_reason_untrusted: record.reason_untrusted,
    })
    return record
  }

  get(id_) { this.#sweep(); return this.items.get(id_) || null }

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
