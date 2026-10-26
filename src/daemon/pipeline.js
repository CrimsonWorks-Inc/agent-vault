// The request pipeline.
//
//   accept -> session carrier -> route -> normalize destination
//   -> locate placeholders (every encoding) -> resolve each -> site check
//   -> policy -> budget -> approval -> [consume] -> decrypt -> substitute
//   -> DNS + TLS -> upstream -> strip -> scrub -> audit -> agent
//
// Two invariants hold the whole design up and are asserted by the security
// tests: every denial returns before an upstream socket exists, and a use is
// consumed before the first upstream byte.

import { request as httpsRequest } from 'node:https'
import { request as httpRequest } from 'node:http'
import * as zlib from 'node:zlib'
import { pipeline as streamPipeline, PassThrough } from 'node:stream'
import * as sub from '../core/substitute.js'
import * as sitesMod from '../core/sites.js'
import * as policyMod from '../core/policy.js'
import * as canon from '../core/canon.js'
import { evaluatePayload, parseStrictJson } from '../core/payload.js'
import * as models from '../core/model-usage.js'
import { Tripwires } from './tripwire.js'
import { detectAll } from '../core/detect.js'
import * as profiles from '../connectors/profiles.js'
import { Scrubber, compileScrubPattern } from '../core/scrub.js'
import { deny, VaultError } from '../core/errors.js'
import { id } from '../store/ids.js'
import * as vaultMod from '../store/vault.js'
import { getProfile } from '../connectors/profiles.js'
import * as ph from '../core/placeholder.js'

const HOP_BY_HOP = new Set([
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
  'te', 'trailer', 'transfer-encoding', 'upgrade', 'host', 'content-length',
])

const ALLOWED_HOSTS = new Set(['127.0.0.1', 'localhost', '::1', '[::1]', 'host.docker.internal', 'host.containers.internal'])

/** Headers the agent may send that the daemon consumes and never forwards. */
const CONSUMED = new Set(['av-session', 'av-reason', 'av-expect-placeholders'])

/**
 * A session token, in the header the agent used to carry it.
 *
 * `Authorization: Bearer avs1...` is the documented way to authenticate, and
 * that header was being forwarded upstream verbatim: every API the vault
 * proxied for received a live vault capability and wrote it to its logs. It is
 * consumed here, like AV-Session, and never leaves the machine.
 */
const SESSION_TOKEN = /avs1\.[0-9a-z]{12}\.[A-Za-z0-9_-]{20,}/

// Bounds on the approval map. It is the one structure an agent can grow simply
// by making requests, and it holds response bodies.
const PENDING_TTL_MS = 15 * 60_000   // a human who has not answered by now will not
const REPLAY_TTL_MS = 5 * 60_000     // long enough for a retrying SDK, not for a process lifetime
const DECIDED_TTL_MS = 60 * 60_000   // keep decisions visible for an hour, then forget
const MAX_APPROVALS = 1000

// The most a response may expand to once decompressed. A compressed body is an
// amplifier and the daemon is single-threaded, so this is the ceiling on what
// one upstream can make it hold and scan.
const MAX_DECOMPRESSED = 64 * 1024 * 1024

// The most of an upstream response the daemon will hold to scan it. Anything
// larger cannot be scrubbed, and a body that cannot be scrubbed is refused.
const MAX_RESPONSE_BYTES = 32 * 1024 * 1024

// The most of one server-sent event the daemon will hold while waiting for it
// to end. An event is held whole so it can be scanned whole, and a stream that
// never sends a blank line would otherwise be held whole, forever.
const MAX_EVENT_BYTES = 16 * 1024 * 1024

// How many runs an event stream's reassembly tracks at once: one per JSON key
// path, and one per path and combination of the indexes above it. A model
// stream uses a few per content block; this bounds what a hostile one can make
// us keep, at most `keep` characters and a short key each. A stream that uses
// more is cut: forgetting a run forgets the first half of whatever secret its
// next value finishes.
const MAX_SSE_PATHS = 1024

// The most index fields above one JSON string whose combinations are each
// tracked. Every combination is a run, so this is 2^4 runs at most per string.
const MAX_SSE_INDEXES = 4

// Failures that happen before any byte could have reached the server, so the
// placeholder use is refunded. A timeout or a reset is deliberately not here:
// the request may have been delivered and acted on, and refunding a write that
// happened is worse than charging for one that did not.
const PRE_CONNECT_ERRORS = new Set([
  'ENOTFOUND', 'EAI_AGAIN', 'ECONNREFUSED', 'EHOSTUNREACH', 'ENETUNREACH', 'EADDRNOTAVAIL',
  'ERR_TLS_CERT_ALTNAME_INVALID', 'CERT_HAS_EXPIRED', 'DEPTH_ZERO_SELF_SIGNED_CERT',
  'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'SELF_SIGNED_CERT_IN_CHAIN',
])

export class Pipeline {
  #buckets = new Map()
  #inFlight = new Map()
  #preflightBuckets = new Map()
  #patterns = new Map()
  #spendRecovered = false

  /**
   * @param {import('../store/vault.js').Vault} vault
   * @param {{approvals: Map, allowedHosts?: Set<string>, fetchImpl?: Function}} opts
   */
  constructor(vault, opts = {}) {
    this.vault = vault
    this.approvals = opts.approvals || new Map()
    this.allowedHosts = opts.allowedHosts || ALLOWED_HOSTS
    this.upstream = opts.fetchImpl || defaultUpstream
    this.approvalHoldMs = opts.approvalHoldMs ?? 0
    // Optional override for the response scrubber's layered-decode budget, so
    // a test can drive the fail-closed path without a multi-megabyte body.
    this.scrubBudget = opts.scrubBudget
    // Hooks other parts of the daemon set. Each is optional, and a failure
    // in one never changes what this request gets.
    this.onPending = null   // (event) => void, after a request is held (F14)
    this.onPanic = null     // async ({ reason, at_ms }) => { session_requests_denied } (F16)
    // The store's pure expiry helpers (slice A). Without them preflight
    // cannot tell a live session from an expired one, so it says expired.
    this.expiryMs = opts.expiryMs ?? vaultMod.expiryMs ?? (() => -Infinity)
    this.sessionExpiryMs = opts.sessionExpiryMs ?? vaultMod.sessionExpiryMs ?? (() => -Infinity)
    // The connectors' header reader (F10). Without it nothing is observed.
    this.extractHealth = opts.extractHealth ?? profiles.extractHealth
    this.tripwires = new Tripwires(vault, this)
    this.#recoverSpend()
  }

  /**
   * Handle one proxied request.
   * @param {{method, path, query, headers, body, listener?}} req
   * @returns {Promise<{status, headers, body, requestId}>}
   */
  async handle(req) {
    // A daemon that started locked could not sweep then; it does on the
    // first request after unlock, before this one can reserve anything.
    if (!this.#spendRecovered) this.#recoverSpend()
    const requestId = id.request()
    const started = Date.now()
    // Every placeholder row this request spent. It was one variable that each
    // consume overwrote, so a request carrying two placeholders that failed
    // before connecting refunded only the last and kept charging for the
    // first, while the error told the agent its use had been refunded.
    const consumed = []
    let upstreamOpened = false
    let spentApproval = null
    // Declared out here so a DENIAL can say who was denied. Both were `const`
    // inside the try, so the catch could not see them: every policy denial was
    // filed with no session and no credential, even though authentication had
    // already succeeded and both were known. With more than one live session on
    // a credential — the normal case — a run of refusals could not be pinned to
    // the agent making it, which is the one question a run of refusals raises.
    // They stay null when the failure came before there was anything to name.
    let session = null
    let route = null
    const resources = { release: null, quota: null, spend: null }
    let streaming = false

    try {
      this.#refuseBrowsers(req)
      // Folded once, here, so authentication, the payload rules, the approval
      // and the outbound request all read the same single value.
      req = { ...req, headers: foldHeaders(req.headers) }
      session = this.#authenticate(req)
      route = this.#route(req, session)
      const result = await this.#proxy({
        req, session, route, requestId, resources,
        onConsume: (r) => { consumed.push(r) },
        onApprovalSpent: (a) => { spentApproval = a },
        markUpstream: () => { upstreamOpened = true },
      })
      this.vault.audit.write('request.allowed', {
        request_id: requestId, session_id: session.id, grant_id: route.grantId,
        credential_slug: route.slug,
        req: {
          host: result.host, method: req.method, path_glob_matched: result.rule, route_matched: result.routeMatched ?? null, status: result.status,
          // The path, which the log used to leave out entirely. Under a grant
          // of /repos/frozencrow/** every request recorded the same glob, so
          // the log could say a credential had been used forty times and not
          // which forty things it had been used on — which is the first
          // question anyone asks it. The query string still stays out: that is
          // where credentials actually appear in a URL. What remains goes
          // through the scrubber, so a secret in a path segment is redacted
          // rather than filed.
          path: result.auditPath ?? null,
          // A streamed response has no buffered body to measure at this point.
          bytes_down: result.body ? result.body.length : null,
          streamed: !!result.stream,
          redactions: result.redactions,
        },
        spend: result.spend ?? null,
        // A request held for a human also lands here, as a 202. It says so,
        // so no reader has to infer it from the status (C11). `allow` stays
        // the word for an allowed one: the CLI and UI read it, beside `deny`.
        decision: result.headers?.['av-decision'] === 'pending' ? 'held' : 'allow',
        peer: { kind: req.listener?.kind || 'loopback', listener_id: req.listener?.id || 'local' },
        duration_ms: Date.now() - started,
      })
      if (result.stream) {
        result.stream = closeAware(result.stream, () => resources.release?.())
        streaming = true
      }
      return { ...result, requestId }
    } catch (e) {
      // Every error's detail goes to the agent, including text this code did
      // not write: the upstream-failure path interpolates the underlying
      // error's message. This is a vault, so the one place a stray secret in
      // an exception must not reach is the agent. Scrub all of them.
      // Built once for this failure and reused for every field below.
      const scrubber = this.vault.locked ? null : (() => {
        try { return this.#errorScrubber() } catch { return null }
      })()
      const err = e instanceof VaultError ? e : deny('AV_INTERNAL', this.#safeMessage(e, scrubber))
      err.detail = this.#safeMessage({ message: err.detail }, scrubber)
      if (err.hint) err.hint = this.#safeMessage({ message: err.hint }, scrubber)
      // A failure before the first upstream byte refunds the use: the agent
      // should not lose budget because DNS was down.

      // And give the human's approval back, for the same reason. It moves to
      // `consumed` before the upstream call — which is what makes a resend
      // execute exactly once — so a failure in between left it consumed with
      // no stored result. The resend then read `consumed` with nothing to
      // replay, answered 202 forever, and the approval was no longer pending,
      // so the human could not approve it again either. One DNS blip wedged
      // the request until the entry expired an hour later.
      if (spentApproval && !upstreamOpened && spentApproval.state === 'consumed' && !spentApproval.result) {
        spentApproval.state = 'granted'
        this.vault.audit?.write('approval.returned', {
          approval_id: spentApproval.id, request_id: requestId, reason: 'the request never reached the upstream',
        })
      }
      // The other side of the same line: once the upstream may have acted, the
      // approval is spent even though there is no response to replay, and a
      // resend must ask a human again rather than wait on it forever.
      if (spentApproval && upstreamOpened && spentApproval.state === 'consumed' && !spentApproval.result) {
        spentApproval.executed_at = new Date().toISOString()
      }
      err.requestId = requestId
      if (this.vault.audit) {
        this.vault.audit.write(err.auditKind, {
          request_id: requestId, decision: 'deny', reason_code: err.code, rule: err.rule,
          detail: err.detail,
          ...(err.retryAfter !== undefined ? { retry_after: err.retryAfter } : {}),
          ...(err.code === 'AV_PIN_MISMATCH' ? { presented_spki: e.presented ?? [] } : {}),
          // Whoever got this far. Null before authentication, which is itself
          // the useful answer: an unauthenticated probe and a session exceeding
          // its grant are different events and no longer look the same.
          session_id: session?.id ?? null,
          credential_slug: route?.slug ?? null,
          grant_id: route?.grantId ?? null,
          // A denial recorded without what was denied says only that something
          // happened. These are the records that matter most — a run of them
          // is what an attempt looks like — so they get the same method and
          // path the allow records do, scrubbed the same way. This is the
          // request as it ARRIVED, which is the point: a denial often happens
          // before there is any decision to read it from.
          req: {
            method: req.method,
            path: this.#safePath(req.path, scrubber),
          },
          peer: { kind: req.listener?.kind || 'loopback', listener_id: req.listener?.id || 'local' },
        })
      }
      if (!upstreamOpened) {
        for (const row of consumed) this.vault.refundPlaceholder(row.id)
        if (resources.quota && route?.grant.state === 'active' && session?.state === 'active') {
          const state = route.grant.quota_state
          if (state?.window_ms === resources.quota.window_ms) {
            if (state.start === resources.quota.start) state.count = Math.max(0, state.count - 1)
            else if (state.start === resources.quota.start + state.window_ms) state.prev = Math.max(0, state.prev - 1)
          }
        }
        if (resources.spend) this.#refundSpend(resources.spend)
        if (resources.quota) this.vault.save({ durable: false })
      } else if (resources.spend) this.#settleSpend(resources.spend, null)
      // After the audit record and the refund, before the agent hears back.
      // A tripwire that fails cannot cost the agent its denial: the request
      // is refused either way, and what the tripwire did is in the log.
      try {
        await this.tripwires.observe({ sessionId: session?.id ?? null, credentialId: route?.cred?.id ?? null, code: err.code, rule: err.rule })
      } catch { /* the denial below stands */ }
      return {
        status: err.http,
        headers: { 'content-type': 'application/problem+json', 'av-decision': 'deny', 'av-request-id': requestId, ...(err.http === 429 ? { 'retry-after': String(err.retryAfter ?? 1) } : {}) },
        body: Buffer.from(JSON.stringify(err.toProblem(), null, 2)),
        requestId,
        error: err,
      }
    } finally {
      if (!streaming) resources.release?.()
    }
  }

  /**
   * assertSessionLive's answer, without its side effects. Preflight must not
   * mark a session expired or kill its placeholders, and it decides with the
   * same pure helper the store does, so the two cannot disagree.
   */
  #peekSession(session) {
    if (session.state === 'revoked') throw deny('AV_SESSION_REVOKED', `session ${session.id} was revoked`)
    const expires = this.sessionExpiryMs(session)
    if (session.state === 'expired' || !(expires > Date.now())) throw deny('AV_SESSION_EXPIRED', `session ${session.id} has expired`)
  }

  /** assertGrantLive's answer, without marking anything expired. */
  #peekGrant(grant) {
    if (grant.state === 'expired') throw grantExpired(this.vault.db.credentials[grant.credential_id]?.slug)
    if (grant.state !== 'active') throw deny('AV_NO_GRANT', 'this grant is no longer active')
    if (!(this.expiryMs(grant.expires_at) > Date.now())) throw grantExpired(this.vault.db.credentials[grant.credential_id]?.slug)
  }

  #checkQuarantine(cred) {
    if (cred.quarantine) throw deny('AV_QUARANTINED', `${cred.slug} is quarantined`, { rule: 'quarantine', hint: 'A human can release it: agent-vault cred release <slug>' })
  }

  #extraPatterns() {
    const sources = new Set()
    const patterns = []
    for (const cred of Object.values(this.vault.db.credentials)) {
      for (const pattern of cred.scrub_patterns ?? []) {
        sources.add(pattern.source)
        try {
          if (!this.#patterns.has(pattern.source)) this.#patterns.set(pattern.source, compileScrubPattern(pattern.source).re)
          patterns.push({ name: pattern.id, re: this.#patterns.get(pattern.source) })
        } catch {
          throw deny('AV_UNSCANNABLE', 'a stored scrub pattern is invalid', { rule: 'scrub_pattern_invalid' })
        }
      }
    }
    for (const source of this.#patterns.keys()) if (!sources.has(source)) this.#patterns.delete(source)
    return patterns
  }

  /**
   * The request budget. A limit that is present but not a canonical integer
   * can only come from a bug or a hand edit, and its failure is silent and
   * total: `used >= NaN` is false forever. So it refuses, and so does a
   * counter that cannot count. A budget that names no limit (a legacy layer)
   * constrains nothing, as before.
   */
  #budget(grant, effective) {
    const b = effective.budget
    if (b === undefined || (b && !b.invalid && b.limit === undefined)) return
    if (!b || b.invalid || (b.unit !== undefined && b.unit !== 'requests') || !Number.isSafeInteger(b.limit) || b.limit < 0 || !Number.isSafeInteger(grant.budget_used) || grant.budget_used < 0) {
      throw deny('AV_POLICY_DENIED', 'this grant has a budget whose limit is not a whole number of requests, so no request can be counted against it', {
        rule: 'budget_invalid',
        hint: 'Recreate the grant with a numeric budget limit.',
      })
    }
    if (grant.budget_used >= b.limit) {
      throw deny('AV_POLICY_DENIED', `grant budget of ${b.limit} requests is spent`, {
        rule: 'budget',
        hint: 'A human must widen the grant or start a new session.',
      })
    }
  }

  #validLimit(effective, field) {
    const value = effective[field]
    if (value === undefined) return
    if (policyMod.validate({ [field]: value }).length) throw deny('AV_POLICY_DENIED', `the ${field} limit is invalid`, { rule: `${field}_invalid` })
  }

  #prune(map, sessions = false) {
    const records = sessions ? this.vault.db.sessions : this.vault.db.grants
    const live = new Set(Object.values(records).filter((r) => r.state === 'active' && (r.expires_at == null || Date.parse(r.expires_at) > Date.now())).map((r) => r.id))
    if (map.size > live.size) for (const key of map.keys()) if (!live.has(key)) map.delete(key)
  }

  #rate(grant, effective, peek = false) {
    this.#validLimit(effective, 'rate')
    if (effective.rate === undefined) return null
    const { count, per } = effective.rate
    const now = performance.now()
    const prior = this.#buckets.get(grant.id)
    const tokens = prior ? Math.min(count, prior.tokens + Math.max(0, now - prior.at) * count / policyMod.PER_MS[per]) : count
    if (!Number.isFinite(tokens) || tokens < 0) throw deny('AV_POLICY_DENIED', 'rate state is invalid', { rule: 'rate_invalid' })
    if (tokens < 1) throw deny('AV_QUOTA_EXCEEDED', 'the grant rate limit was reached', { rule: 'rate', retryAfter: Math.max(1, Math.ceil((1 - tokens) * policyMod.PER_MS[per] / count / 1000)) })
    if (!peek) {
      this.#buckets.set(grant.id, { tokens: tokens - 1, at: now })
      this.#prune(this.#buckets)
    }
    return tokens
  }

  #quota(grant, effective, enforce = true) {
    this.#validLimit(effective, 'quota')
    if (effective.quota === undefined) return null
    const window_ms = policyMod.WINDOW_MS[effective.quota.window]
    const now = Date.now()
    let state = grant.quota_state ? { ...grant.quota_state } : { window_ms, start: now, count: 0, prev: 0 }
    if (![state.window_ms, state.start, state.count, state.prev].every(Number.isSafeInteger) || state.window_ms <= 0 || state.count < 0 || state.prev < 0) throw deny('AV_POLICY_DENIED', 'quota state is invalid', { rule: 'quota_invalid' })
    if (state.window_ms !== window_ms) state = { window_ms, start: Math.max(now, state.start), count: state.count + state.prev, prev: 0 }
    if (now >= state.start + window_ms) {
      state.prev = now >= state.start + 2 * window_ms ? 0 : state.count
      state.start += window_ms * Math.floor((now - state.start) / window_ms)
      state.count = 0
    }
    const estimate = state.prev * (1 - Math.max(0, now - state.start) / window_ms) + state.count
    if (enforce && estimate + 1 > effective.quota.count) throw deny('AV_QUOTA_EXCEEDED', 'the rolling quota was reached', { rule: 'quota', retryAfter: Math.max(1, Math.ceil((state.start + window_ms - now) / 1000)) })
    return state
  }

  #acquire(grant, effective) {
    this.#validLimit(effective, 'max_concurrent')
    const n = this.#inFlight.get(grant.id) ?? 0
    if (effective.max_concurrent !== undefined && n >= effective.max_concurrent) throw deny('AV_QUOTA_EXCEEDED', 'the concurrency limit was reached', { rule: 'max_concurrent', retryAfter: 1 })
    this.#inFlight.set(grant.id, n + 1)
    this.#prune(this.#inFlight)
    let released = false
    return () => {
      if (released) return
      released = true
      const count = this.#inFlight.get(grant.id) ?? 0
      if (count <= 1) this.#inFlight.delete(grant.id)
      else this.#inFlight.set(grant.id, count - 1)
    }
  }

  #effectiveFor(grant) {
    const cred = this.vault.db.credentials[grant.credential_id]
    return policyMod.intersect([getProfile(cred.connector_kind).policyCeiling, this.vault.db.sessions[grant.session_id]?.policy, grant.policy])
  }

  limitsFor(grantId) {
    const grant = this.vault.db.grants[grantId]
    if (!grant) return null
    const effective = this.#effectiveFor(grant)
    const prior = this.#buckets.get(grantId)
    const rate = effective.rate
    const validRate = rate && !policyMod.validate({ rate }).length
    const tokens = validRate ? Math.min(rate.count, prior ? prior.tokens + Math.max(0, performance.now() - prior.at) * rate.count / policyMod.PER_MS[rate.per] : rate.count) : null
    let quota = null
    try {
      const state = this.#quota(grant, effective, false)
      if (state) quota = { ...effective.quota, estimate: state.prev * (1 - Math.max(0, Date.now() - state.start) / state.window_ms) + state.count }
    } catch {}
    return { rate: validRate ? { ...rate, tokens_now: tokens } : null, max_concurrent: { limit: effective.max_concurrent ?? null, in_flight: this.#inFlight.get(grantId) ?? 0 }, quota }
  }

  #spendState(grant) {
    const state = grant.spend ?? { tokens_used: 0, usd_micros_used: 0, reserved: {} }
    if (!Number.isSafeInteger(state.tokens_used) || state.tokens_used < 0 || !Number.isSafeInteger(state.usd_micros_used) || state.usd_micros_used < 0 || !state.reserved || typeof state.reserved !== 'object' || Array.isArray(state.reserved)) throw deny('AV_POLICY_DENIED', 'spend state is invalid', { rule: 'spend_invalid' })
    for (const reservation of Object.values(state.reserved)) {
      if (!reservation || ![reservation.tokens, reservation.usd_micros, reservation.at].every(Number.isSafeInteger) || reservation.tokens < 0 || reservation.usd_micros < 0) throw deny('AV_POLICY_DENIED', 'spend reservation is invalid', { rule: 'spend_invalid' })
    }
    return state
  }

  /**
   * Stage 5: could this call stay inside the spend limit? It reserves
   * nothing yet; stage 10 does, in the same synchronous block as the consume.
   * What is already reserved by calls still in flight counts, so two calls
   * that fit alone but not together cannot both start.
   */
  #checkSpend(grant, effective, route, req, decision) {
    if (effective.spend === undefined || !models.METERED_KINDS.includes(route.cred.connector_kind)) return null
    const limit = effective.spend
    if (!limit || limit.invalid || Object.entries(limit).some(([k, v]) => !['tokens', 'usd_micros'].includes(k) || !Number.isSafeInteger(v) || v < 0)) {
      throw deny('AV_POLICY_DENIED', 'this grant has a spend limit that is not a whole number', { rule: 'spend_invalid' })
    }
    const kind = route.cred.connector_kind
    const meter = models.meterRequest(kind, { method: decision.method, path: decision.path, contentType: sub.getHeader(req, 'content-type'), body: req.body })
    if (meter.unmodeled) {
      throw deny('AV_POLICY_DENIED', `${decision.method} ${decision.path} is not an endpoint whose cost can be bounded, so it cannot run under a spend limit`, { rule: 'spend_unmodeled' })
    }
    if (!meter.metered || meter.free) return null
    const reservation = models.reservationFor(kind, meter, { usd: limit.usd_micros !== undefined })
    const state = this.#spendState(grant)
    for (const key of ['tokens', 'usd_micros']) {
      const reserved = Object.values(state.reserved).reduce((n, r) => n + r[key], 0)
      const committed = state[`${key}_used`] + reserved
      const total = committed + reservation[key]
      if (!Number.isSafeInteger(total)) throw deny('AV_POLICY_DENIED', 'this grant\'s spend counters are not whole numbers', { rule: 'spend_invalid' })
      if (limit[key] !== undefined && total > limit[key]) {
        const left = Math.max(0, limit[key] - committed)
        const say = key === 'tokens' ? (n) => `${n} more tokens` : (n) => `$${(n / 1e6).toFixed(2)} more`
        throw deny('AV_POLICY_DENIED', 'this call could cost more than the spend limit has left', {
          rule: 'spend',
          hint: `This grant may spend ${say(left)}; this call could cost up to ${key === 'tokens' ? `${reservation.tokens} tokens` : `$${(reservation.usd_micros / 1e6).toFixed(2)}`}.`,
        })
      }
    }
    return { kind, meter, reservation }
  }

  /**
   * Charge, in full, every reservation a previous process left behind. A
   * crash never refunds: the call may have run and been billed.
   */
  #recoverSpend() {
    if (this.vault.locked) return
    this.#spendRecovered = true
    let changed = false
    for (const grant of Object.values(this.vault.db.grants)) {
      let state
      try { state = this.#spendState(grant) } catch { continue }
      for (const [rid, reservation] of Object.entries(state.reserved)) {
        this.vault.audit.write('spend.reservation_charged', { grant_id: grant.id, reservation_id: rid, reason: 'restart' })
        state.tokens_used += reservation.tokens
        state.usd_micros_used += reservation.usd_micros
        delete state.reserved[rid]
        changed = true
      }
    }
    if (changed) this.vault.save({ durable: false })
  }

  #refundSpend(spending) {
    if (spending.settled) return
    delete spending.grant.spend.reserved[spending.rid]
    spending.settled = true
    this.vault.save({ durable: false })
  }

  #spendAudit(spending) {
    return spending ? { reserved_tokens: spending.reservation.tokens, charged_tokens: 0, charged_usd_micros: 0, settled: 'pending' } : null
  }

  #settleSpend(spending, usage, streamed = false) {
    if (!spending || spending.settled) return null
    const charge = models.chargeFor(spending.kind, spending.meter, spending.reservation, usage)
    const result = { reserved_tokens: spending.reservation.tokens, charged_tokens: charge.tokens, charged_usd_micros: charge.usd_micros, settled: usage ? 'usage' : 'reservation' }
    if (streamed) this.vault.audit.write('spend.settled', { request_id: spending.requestId, grant_id: spending.grant.id, charged_tokens: charge.tokens, charged_usd_micros: charge.usd_micros, settled: result.settled })
    const state = spending.grant.spend
    state.tokens_used += charge.tokens
    state.usd_micros_used += charge.usd_micros
    delete state.reserved[spending.rid]
    spending.settled = true
    this.vault.save({ durable: false })
    return result
  }

  spendFor(grantId) {
    const grant = this.vault.db.grants[grantId]
    if (!grant) return null
    const limit = this.#effectiveFor(grant).spend
    if (!limit) return null
    const state = this.#spendState(grant)
    return { tokens_used: state.tokens_used, usd_micros_used: state.usd_micros_used,
      reserved_tokens: Object.values(state.reserved).reduce((n, r) => n + r.tokens, 0),
      reserved_usd_micros: Object.values(state.reserved).reduce((n, r) => n + r.usd_micros, 0),
      limit_tokens: limit.tokens ?? null, limit_usd_micros: limit.usd_micros ?? null, prices_version: models.PRICES_VERSION }
  }

  /**
   * Settle a streamed call when its stream is finished with, however that
   * happens. Usage is read from the events the agent was sent (they are
   * already scrubbed, and the counters are integers). A stream that was cut,
   * aborted or never finished is charged its full reservation: it may have
   * run to the end upstream, and charging less than it could have cost is the
   * one direction a limit must not err in.
   */
  #trackStream(stream, spending, closeSource, state) {
    let partial = '', usage = null, failed = false
    return closeAware(stream, (complete) => {
      closeSource()
      this.#settleSpend(spending, complete && !failed && !state.cut ? usage : null, true)
    }, (chunk) => {
      if (!spending || failed) return
      // The scrubber emits LF-framed events; CRLF is normalised anyway, so a
      // reframing upstream of here cannot hide the usage event.
      partial += chunk.toString('utf8').replace(/\r\n?/g, '\n')
      let boundary
      while ((boundary = partial.indexOf('\n\n')) !== -1) {
        const event = partial.slice(0, boundary)
        partial = partial.slice(boundary + 2)
        if (/^event: error$/m.test(event)) failed = true
        const data = event.split('\n').filter((line) => line.startsWith('data:')).map((line) => line.slice(5).replace(/^ /, '')).join('\n')
        usage = models.usageFromEvent(spending.kind, data, usage)
      }
      // One event cannot outgrow what the scrubber would hold, but this copy
      // is bounded on its own terms: past it, usage is not read at all.
      if (partial.length > MAX_EVENT_BYTES) { failed = true; partial = '' }
    })
  }

  /**
   * F10: what the response says about the credential itself. Every request
   * here substituted the credential, so a 401 or 403 is about it. This runs
   * after the upstream acted, so nothing in it may turn the response into a
   * failure: the store records it or does not.
   */
  #observeHealth(route, res) {
    try {
      const health = this.extractHealth?.(route.profile, res.headers)
      const patch = { source: 'response', checked_at: new Date().toISOString() }
      if (typeof health?.observed_expires_at === 'string') patch.observed_expires_at = health.observed_expires_at
      if (res.status === 401 || res.status === 403) {
        patch.status = res.status === 401 ? 'unauthorized' : 'forbidden'
        patch.http_status = res.status
      }
      if (patch.status || patch.observed_expires_at) this.vault.recordHealth?.(route.cred.id, patch)
    } catch { /* observation only */ }
  }

  /**
   * F20: would this request be allowed, held, or refused? Stages 1 to 8 of the
   * real pipeline, run with nothing spent: the session is not touched, no
   * rate token is taken, quota and spend are only peeked, no approval is
   * created, nothing is minted or consumed, and a denial here never reaches
   * the tripwires. Advisory: the real request is checked again from scratch.
   *
   * A refusal of the preflight itself (no session, throttled, too big) is
   * thrown, so the caller answers with the normal problem body.
   */
  async preflight(req, { assumePlaceholder = false } = {}) {
    if (!this.#spendRecovered) this.#recoverSpend()
    const requestId = id.request()
    const checks = []
    let current = 'session', session = null, route = null, effective = null
    const stage = (next) => {
      if (next === current) return
      checks.push({ stage: current, ok: true })
      current = next
    }
    this.#refuseBrowsers(req)
    req = { ...req, headers: foldHeaders(req.headers) }
    session = this.#authenticate(req, { touch: false })
    const now = performance.now()
    const prior = this.#preflightBuckets.get(session.id)
    const bucket = !prior || now - prior.at >= 1000 ? { count: 0, at: now } : { ...prior }
    if (bucket.count >= 10) throw deny('AV_QUOTA_EXCEEDED', 'preflight rate limit was reached', { rule: 'preflight_rate', retryAfter: 1 })
    bucket.count++
    this.#preflightBuckets.set(session.id, bucket)
    this.#prune(this.#preflightBuckets, true)
    if (req.body?.length > 1024 * 1024) throw deny('AV_POLICY_DENIED', 'a preflight body may be at most 1 MiB', { rule: 'preflight_size' })
    let would, code = null, rule = null, approvalState
    try {
      stage('route')
      route = this.#route(req, session, stage, true)
      effective = policyMod.describeEffective(policyMod.intersect([route.profile.policyCeiling, session.policy, route.grant.policy]))
      const result = await this.#proxy({ req, session, route, requestId, preflight: true, assumePlaceholder, stage })
      checks.push({ stage: current, ok: true })
      would = result.would
      approvalState = result.approval_state
    } catch (e) {
      const err = e instanceof VaultError ? e : deny('AV_INTERNAL', 'preflight could not finish')
      code = err.code; rule = err.rule ?? null; would = 'deny'
      const scrubber = (() => { try { return this.#errorScrubber() } catch { return null } })()
      checks.push({
        stage: current, ok: false, code, rule,
        detail: this.#safeMessage({ message: err.detail }, scrubber),
        ...(err.hint ? { hint: this.#safeMessage({ message: err.hint }, scrubber) } : {}),
      })
    }
    // One record per call, bounded by the throttle. It names the verdict,
    // never the request.
    this.vault.audit.write('request.preflighted', { request_id: requestId, session_id: session.id, credential_slug: route?.slug ?? null, would, code: code ?? null, rule: rule ?? null })
    return { would, request_id: requestId, checks, effective, ...(approvalState ? { approval_state: approvalState } : {}), advisory: 'A prediction, not a permission. The real request is checked again and can still be refused.' }
  }

  /**
   * F6: follow a redirect only where the grant would have allowed the request
   * it leads to. Each hop is checked like a request of its own (policy, the
   * query rules, budget, rate, quota, pins) and charged like one, before the
   * credential goes anywhere. The first check that fails stops the chain and
   * the agent gets the last 3xx, with `av-redirect-stopped` saying why.
   * Never for a method other than GET and HEAD, and never where the method
   * needs a human: each hop would need its own decision.
   */
  async #redirects(response, { route, effective, decision, headers, upstreamUrl, requestId }) {
    let res = response, current = upstreamUrl, hops = 0
    const method = decision.method
    while ([301, 302, 303, 307, 308].includes(res.status)) {
      let reason = null, next = null
      const max = effective.redirects?.max
      if (!['GET', 'HEAD'].includes(method) || policyMod.needsApproval(effective, { method, firstUse: false })) reason = 'approval'
      else if (!Number.isInteger(max) || max < 0 || max > 5 || hops >= max) reason = 'max'
      if (!reason) {
        try { if (typeof res.headers.location !== 'string') throw new Error('missing location'); next = new URL(res.headers.location, current) } catch { reason = 'host' }
      }
      if (!reason && (next.username || next.password)) reason = 'host'
      if (!reason && (!['http:', 'https:'].includes(next.protocol) || (route.scheme === 'https' && next.protocol !== 'https:'))) reason = 'scheme'
      let hop, quota
      if (!reason) {
        try { hop = policyMod.evaluateHttp(effective, { method, host: next.hostname, path: next.pathname }) }
        catch (e) { reason = e.rule === 'hosts' ? 'host' : 'path' }
      }
      // The port, which policy does not see. A request only ever reaches the
      // port the credential names for its own host, or the scheme's default;
      // a Location must not choose another service on an allowed host.
      if (!reason) {
        const credHost = policyMod.hostOnly(route.cred.connector?.host || '')
        const credPort = route.port && credHost === hop.host ? route.port : ''
        if (next.port !== credPort) reason = 'host'
      }
      if (!reason) {
        // Every payload rule, as for any body-less GET. The query and GraphQL
        // rules read the URL, which a hop has: a GraphQL document in
        // `?query=` is a request the grant decides on like any other, and
        // keeping only the query rules let a Location carry a mutation the
        // grant denies. The body rules see no body, exactly as a direct GET
        // does: a body field the grant requires is missing, so the hop stops.
        try { evaluatePayload(effective.payload_sets, { method, query: next.search.slice(1), body: null, path: hop.path }) } catch { reason = 'path' }
      }
      if (!reason) { try { this.#budget(route.grant, effective) } catch { reason = 'budget' } }
      if (!reason) { try { this.#rate(route.grant, effective) } catch { reason = 'rate' } }
      if (!reason) { try { quota = this.#quota(route.grant, effective) } catch { reason = 'quota' } }
      if (!reason && route.cred.pins?.[hop.host] != null && next.protocol !== 'https:') reason = 'pins'
      if (!reason && !this.vault.chargeGrant?.(route.grant.id)) reason = 'budget'
      if (reason) {
        this.vault.audit.write('request.redirect_returned', { request_id: requestId, hop: hops, status: res.status, to_host: hop?.host ?? (next ? this.#safeMessage({ message: next.hostname }) : null), reason })
        return { ...res, redirectStopped: reason }
      }
      if (quota) { quota.count += 1; route.grant.quota_state = quota; this.vault.save({ durable: false }) }
      const hopHeaders = Object.fromEntries(Object.entries(headers).filter(([name]) => !['content-type', 'content-length', 'host'].includes(name.toLowerCase())))
      hopHeaders.host = next.host
      next.pathname = policyMod.encodePathForWire(hop.path)
      let following
      try { following = await this.upstream({ url: next.href, method, headers: hopHeaders, body: null, pins: route.cred.pins?.[hop.host] ?? null }) }
      catch (e) {
        if (e?.code !== 'AV_PIN_MISMATCH') {
          res.res?.destroy()
          throw deny('AV_UPSTREAM_UNREACHABLE', `could not reach ${hop.host} while following a redirect`, { rule: 'upstream', refunded: false })
        }
        this.vault.audit.write('request.redirect_returned', { request_id: requestId, hop: hops, status: res.status, to_host: hop.host, reason: 'pins' })
        return { ...res, redirectStopped: 'pins' }
      }
      // The hop's own response is discarded unread; only the last one is
      // scrubbed and returned.
      res.res?.destroy()
      this.vault.audit.write('request.redirect_followed', { request_id: requestId, hop: ++hops, status: res.status, to_host: hop.host, to_path: this.#safePath(hop.path) })
      res = following
      current = next.href
    }
    return res
  }

  /** F13: what a held request would send, safe for the human to read. */
  #previewOf(req, substitutions, decision) {
    const scrubber = this.#errorScrubber()
    return approvalPreview({
      req, decision,
      substitutions: substitutions.map((s) => ({
        text: s.occ.text,
        label: `${this.vault.db.credentials[s.row.credential_id].slug}.${s.row.field}`,
        location: sub.describeLocation(s.occ.location),
        part: previewPart(s.occ.location.region),
      })),
      scrub: (text) => { const r = scrubber.scrub(text); return r.unscannable ? '[withheld: unscannable]' : r.text },
    })
  }

  /**
   * Deny held approvals in bulk: rotation, a tripwire, quarantine, panic.
   * Internal, never a route, and it returns how many, never the approvals.
   * `filter` narrows by credential, session or grants; a filter that names
   * nothing (or `all: true`) denies every held approval, because a caller
   * that lost its id should deny too much rather than too little.
   */
  denyApprovals(filter = {}, reason = 'denied') {
    if (this.vault.locked || !this.vault.audit) throw deny('AV_LOCKED', 'unlock the vault before denying approvals')
    const grantIds = Array.isArray(filter.grantIds) ? new Set(filter.grantIds) : null
    let count = 0
    for (const approval of this.approvals.values()) {
      // Held, or granted and not yet run. A consumed one has already run.
      if (approval.state !== 'pending' && !(approval.state === 'granted' && !approval.result)) continue
      if (!filter.all) {
        const grant = this.vault.db.grants[approval.grant_id]
        if (filter.sessionId && grant?.session_id !== filter.sessionId) continue
        if (filter.credentialId && grant?.credential_id !== filter.credentialId) continue
        if (grantIds && !grantIds.has(approval.grant_id)) continue
      }
      // Recorded before it changes: a denial that cannot be audited must not
      // happen.
      this.vault.audit.write('approval.denied', { approval_id: approval.id, reason })
      approval.state = 'denied'
      approval.decided_at = new Date().toISOString()
      approval.denied_reason = reason
      count++
    }
    return count
  }

  denyAllPending(reason) { return this.denyApprovals({ all: true }, reason) }

  /**
   * Panic: every held approval denied, every active session revoked (infinite
   * ones too), then the session requests through `onPanic`, then the record,
   * then the lock if asked. The steps this pipeline owns run first, so a hook
   * that fails cannot stop them; it is recorded as a partial panic and its
   * count reported as null rather than as a number nobody counted.
   *
   * Open to anyone, by design: it can only take capability away.
   */
  async panic({ reason = null, lock = false } = {}) {
    if (this.vault.locked) throw deny('AV_LOCKED', 'the vault is already locked, so nothing can be revoked')
    const at = Date.now()
    const deniedApprovals = this.denyAllPending('panic')
    let revoked = 0
    for (const session of Object.values(this.vault.db.sessions)) {
      if (session.state !== 'active') continue
      this.vault.revokeSession(session.id, 'panic')
      this.tripwires.reset(session.id)
      revoked++
    }
    let sessionRequests = null
    if (this.onPanic) {
      try {
        const out = await this.onPanic({ reason, at_ms: at })
        if (!Number.isSafeInteger(out?.session_requests_denied) || out.session_requests_denied < 0) throw new Error('the panic hook did not say how many it denied')
        sessionRequests = out.session_requests_denied
      } catch {
        this.vault.audit.write('tripwire.panic_partial', { step: 'session_requests' })
      }
    }
    const reasonText = typeof reason === 'string' ? this.#safeMessage({ message: reason.slice(0, 200) }) : null
    // Before the lock: the audit key goes with it.
    this.vault.audit.write('panic.triggered', {
      revoked_sessions: revoked, denied_approvals: deniedApprovals, denied_session_requests: sessionRequests,
      locked: !!lock, reason_untrusted: reasonText,
    })
    if (lock) this.vault.lock()
    return { revoked_sessions: revoked, denied_approvals: deniedApprovals, denied_session_requests: sessionRequests, locked: !!lock }
  }

  // ------------------------------------------------------------------ steps

  #refuseBrowsers(req) {
    const h = (n) => sub.getHeader(req, n)
    if (h('origin') || h('sec-fetch-site')) {
      throw deny('AV_BROWSER_ORIGIN', 'requests carrying Origin or Sec-Fetch-Site are refused', {
        rule: 'browser_origin',
        hint: 'This endpoint is not reachable from a web page. A DNS-rebinding attack looks exactly like this.',
      })
    }
    const host = (h('host') || '').split(':')[0]
    if (host && !this.allowedHosts.has(host) && !(req.listener?.advertise || []).includes(host)) {
      throw deny('AV_BROWSER_ORIGIN', `Host header ${host} is not an allowed gateway host`, { rule: 'allowed_hosts' })
    }
  }

  /**
   * Session carriers, in order: AV-Session, Authorization: Bearer avs1...,
   * or a valid placeholder at a declared header site whose sid names the
   * session. The third is what lets git, gh and SDK constructors work without
   * a custom header.
   */
  #authenticate(req, { touch = true } = {}) {
    const explicit = sub.getHeader(req, 'av-session')
    const auth = sub.getHeader(req, 'authorization') || ''
    const bearer = /^bearer\s+(avs1\.\S+)$/i.exec(auth)
    const token = explicit || (bearer ? bearer[1] : null)

    if (token) {
      const session = this.vault.sessionByToken(token.trim())
      if (!session) throw deny('AV_SESSION_REQUIRED', 'session token is not recognised')
      if (touch) this.vault.assertSessionLive(session)
      else this.#peekSession(session)
      if (touch) this.vault.touchSession(session)
      return session
    }

    // Placeholder-as-carrier. Refused on a network listener: across a network a
    // placeholder in a URL or a proxy log would become a bearer credential.
    const { occurrences } = sub.locate(req)
    const carrier = occurrences.find((o) => o.location.region === 'header' || o.location.region === 'basic')
    if (carrier) {
      if (req.listener?.remote) {
        throw deny('AV_SESSION_REQUIRED', 'a placeholder alone does not authorize on a network listener', {
          rule: 'remote_carrier',
          hint: 'Send the session token in Authorization: Bearer as well as the placeholder.',
        })
      }
      // Checked before the session it names is touched. The sid is the first
      // group of every placeholder, and the keyed checksum was only verified
      // later, in #proxy — so anything on loopback that knew a session id
      // could keep that session alive past its idle timeout with requests
      // that were then refused as malformed. The same checks, the same codes,
      // just early enough to matter.
      const session = this.vault.db.sessions[carrier.parsed.sid]
      if (!session) throw deny('AV_PH_CROSS_SESSION', 'the placeholder names a session that does not exist')
      if (!ph.verify(this.vault.kPh, carrier.parsed)) {
        throw deny('AV_PH_MALFORMED', `that placeholder was not minted by this vault (${sub.describeLocation(carrier.location)})`, {
          rule: 'checksum',
          hint: 'Ask for a placeholder with vault_get_placeholder, or agent-vault ph next.',
        })
      }
      if (!this.vault.resolvePlaceholder(carrier.parsed)) {
        throw deny('AV_PH_REPLAY', `unknown placeholder at ${sub.describeLocation(carrier.location)}`, {
          rule: 'placeholder_unknown',
          hint: 'This placeholder was never issued by this vault, or it was garbage-collected.',
        })
      }
      if (touch) this.vault.assertSessionLive(session)
      else this.#peekSession(session)
      if (touch) this.vault.touchSession(session)
      return session
    }

    throw deny('AV_SESSION_REQUIRED', 'no session carrier on this request', {
      next: { cli: ['agent-vault session create --cred <slug>'], mcp: { tool: 'vault_request_session' } },
      hint: 'Send Authorization: Bearer <session token>, or a placeholder at a declared header site.',
    })
  }

  /**
   * Error text with any known secret, and any placeholder, removed.
   *
   * Defence in depth, and not purely theoretical: the upstream-failure path
   * wraps the underlying error's message, which this code did not author. It
   * costs one scrub on a path that is already failing.
   *
   * Placeholders are redacted for the log's sake. `unknown route /allowed/av1…`
   * interpolates the request path verbatim, so any denial naming a path that
   * contained a placeholder filed a live bearer capability in the audit log —
   * the file that is meant to be safe to hand to someone debugging. The agent
   * loses nothing by the redaction: it is reading back its own placeholder.
   */
  #safeMessage(e, scrubber = null) {
    const raw = String(e?.message ?? e)
    const text = this.#redactPlaceholders(raw)
    try {
      if (this.vault.locked) return text
      const s = scrubber ?? this.#errorScrubber()
      return s ? s.scrub(text).text : text
    } catch {
      // If the scrubber cannot even be built, say nothing rather than guess.
      return 'internal error'
    }
  }

  /**
   * One scrubber for a failing request, built once.
   *
   * Building it calls allSecrets(), which DECRYPTS every credential in the
   * vault. The deny path called #safeMessage three times — detail, hint, path
   * — so every refused request decrypted the whole vault three times over. At
   * sixty credentials that is thousands of AES-GCM opens per denial, on the
   * event loop, on a path an agent can trigger at will simply by asking for
   * things it is not allowed to have.
   */
  #errorScrubber() {
    const secrets = this.vault.allSecrets()
    return new Scrubber(secrets.map((x) => ({ ...x, always: true })), { ...this.scrubBudget, extraPatterns: this.#extraPatterns() })
  }

  /**
   * A path as the audit log may hold it.
   *
   * Secrets are scrubbed, like any other recorded text. Placeholders have to
   * go too, and #safeMessage does not touch them: a placeholder in the path is
   * always DENIED, and a denial is exactly the record that now carries the
   * path — so the one case guaranteed to put a placeholder in front of this
   * function is the case it exists for. A placeholder is a bearer capability,
   * and the log is meant to be evidence you can hand to someone.
   */
  #safePath(p, scrubber = null) {
    return this.#safeMessage({ message: String(p ?? '').split('?')[0] }, scrubber)
  }

  /** Placeholder text swapped for a name. No decryption, so it is cheap. */
  #redactPlaceholders(text) {
    let out = String(text)
    for (const hit of ph.findAll(out)) out = out.split(hit.text).join(`av1.<${hit.slug}_${hit.field}>`)
    return out
  }

  /** /p/<slug>/<path>  or  /t/<scheme>/<host>/<path> */
  #route(req, session, stage = () => {}, peek = false) {
    const path = req.path || '/'
    if (path.startsWith('/p/')) {
      const rest = path.slice(3)
      const slash = rest.indexOf('/')
      const slug = slash === -1 ? rest : rest.slice(0, slash)
      const upstreamPath = slash === -1 ? '/' : rest.slice(slash)
      const cred = this.vault.findCredential(slug)
      if (!cred) throw deny('AV_NOT_FOUND', `no credential named ${slug}`, {
        next: { cli: ['agent-vault cred list'], mcp: { tool: 'vault_list_creds' } },
      })
      stage('quarantine')
      this.#checkQuarantine(cred)
      stage('grant')
      const grant = this.vault.grantsForSession(session.id).find((g) => g.credential_id === cred.id)
      // An expired grant drops out of grantsForSession once the store has
      // noticed. Without this the agent would be told it never had one.
      if (!grant && this.vault.findGrant?.(session.id, cred.id)?.state === 'expired') throw grantExpired(slug)
      if (!grant) throw deny('AV_NO_GRANT', `this session has no grant for ${slug}`, {
        next: { cli: ['agent-vault cred list --available'], mcp: { tool: 'vault_list_creds' } },
      })
      if (peek) this.#peekGrant(grant)
      else this.vault.assertGrantLive?.(grant)
      const profile = getProfile(cred.connector_kind)
      // A credential may name host:port and a scheme; policy always matches on
      // the hostname alone, while the connection uses the full authority.
      const raw = cred.connector.host || profile.hosts[0]
      const colon = raw.lastIndexOf(':')
      const host = colon > 0 && /^\d+$/.test(raw.slice(colon + 1)) ? raw.slice(0, colon) : raw
      const port = colon > 0 && /^\d+$/.test(raw.slice(colon + 1)) ? raw.slice(colon + 1) : null
      return {
        mode: 'reverse', slug, cred, grant, grantId: grant.id, host, port,
        scheme: cred.connector.scheme || 'https', path: upstreamPath, profile,
      }
    }

    if (path.startsWith('/t/')) {
      const parts = path.slice(3).split('/')
      const scheme = parts.shift()
      const rawHost = parts.shift()
      const upstreamPath = `/${parts.join('/')}`
      if (!scheme || !rawHost) throw deny('AV_NOT_FOUND', 'generic target form is /t/<scheme>/<host>/<path>')
      // Match and connect on the same hostname. Earlier these disagreed: the
      // grant was matched against host:port while the connection used the bare
      // host, so a port could be smuggled past the allowlist. A port is honored
      // only when it belongs to the credential's own connector, never one the
      // caller appends here.
      // The scheme comes from the URL the agent wrote. A credential that
      // declares https must not be downgraded to cleartext by asking for
      // /t/http/... — that puts the human's token on the wire in the clear.
      const host = policyMod.hostOnly(rawHost)
      const grants = this.vault.grantsForSession(session.id)
      for (const g of grants) {
        const cred = this.vault.db.credentials[g.credential_id]
        const profile = getProfile(cred.connector_kind)
        const eff = policyMod.intersect([profile.policyCeiling, session.policy, g.policy])
        if ((eff.hosts || []).some((pat) => policyMod.matchHost(pat, host))) {
          stage('quarantine')
          this.#checkQuarantine(cred)
          stage('grant')
          if (peek) this.#peekGrant(g)
          else this.vault.assertGrantLive?.(g)
          // If the credential names this exact host with a port, use that port.
          const credRaw = cred.connector.host || ''
          const credHost = policyMod.hostOnly(credRaw)
          const colon = credRaw.lastIndexOf(':')
          const credPort = credHost === host && colon > 0 && /^\d+$/.test(credRaw.slice(colon + 1))
            ? credRaw.slice(colon + 1) : null
          const credScheme = cred.connector?.scheme || 'https'
          if (scheme !== credScheme && credScheme === 'https') {
            throw deny('AV_POLICY_DENIED', `${cred.slug} is an https credential; ${scheme} would send it in the clear`, {
              rule: 'scheme_downgrade',
              hint: `Use /t/https/${host}/... or the credential's own route, /p/${cred.slug}/...`,
            })
          }
          // The other direction: an agent that asked for /t/https/ gets TLS,
          // even for a credential that declares http. It was silently sent in
          // the clear, because the credential's scheme won whatever the URL
          // said. The stronger of the two is used.
          const useScheme = scheme === 'https' ? 'https' : credScheme
          return { mode: 'target', slug: cred.slug, cred, grant: g, grantId: g.id, host, port: credPort, path: upstreamPath, scheme: useScheme, profile }
        }
      }
      throw deny('AV_NO_GRANT', `no grant in this session allows host ${policyMod.hostOnly(rawHost)}`)
    }

    throw deny('AV_NOT_FOUND', `unknown route ${path}`, {
      hint: 'Use /p/<credential>/<path> for a configured credential, or /t/<scheme>/<host>/<path>.',
    })
  }

  async #proxy({ req, session, route, requestId, resources = {}, onConsume, onApprovalSpent, markUpstream, preflight = false, assumePlaceholder = false, stage = () => {} }) {
    const { cred, grant, profile } = route
    const effective = policyMod.intersect([profile.policyCeiling, session.policy, grant.policy])
    let approvedRequestHash = null

    // --- locate every placeholder, in every encoding -----------------------
    stage('placeholders')
    const located = sub.locate(req)
    if (located.unscannable) {
      throw deny('AV_UNSCANNABLE', located.unscannable, { rule: 'body_size' })
    }
    if (sub.getHeader(req, 'content-encoding')) {
      throw deny('AV_ENCODED_BODY', 'compressed request bodies cannot be scanned for placeholders', {
        rule: 'content_encoding', hint: 'Send the body with identity encoding.',
      })
    }

    // --- resolve and site-check each occurrence ----------------------------
    const substitutions = []
    for (const occ of located.occurrences) {
      // The keyed checksum, checked before anything is looked up. It was
      // minted on every placeholder and then verified nowhere — ph.verify()
      // had no call site in the whole of src/ — so the one cheap test for
      // "this vault made this" was dead code, and the key it depends on was
      // shared with the fingerprints shown in `cred list`, which are taken
      // over a value the caller chooses. Both halves of that are fixed: the
      // keys are separate, and the check runs.
      if (!ph.verify(this.vault.kPh, occ.parsed)) {
        throw deny('AV_PH_MALFORMED', `that placeholder was not minted by this vault (${sub.describeLocation(occ.location)})`, {
          rule: 'checksum',
          hint: 'Ask for a placeholder with vault_get_placeholder, or agent-vault ph next.',
        })
      }
      const row = this.vault.resolvePlaceholder(occ.parsed)
      if (!row) {
        // Shape-valid but unknown: either forged or long dead. Either way it is
        // not substituted and the request does not proceed with it in place.
        throw deny('AV_PH_REPLAY', `unknown placeholder at ${sub.describeLocation(occ.location)}`, {
          rule: 'placeholder_unknown',
          hint: 'This placeholder was never issued by this vault, or it was garbage-collected.',
        })
      }
      if (row.sid !== session.id) {
        throw deny('AV_PH_CROSS_SESSION', `that placeholder belongs to session ${row.sid}, not ${session.id}`, {
          rule: 'placeholder_session',
        })
      }
      // The grant it was issued under is the grant it spends against. Only
      // the session and the credential were checked, while consumePlaceholder
      // charges `row.grant_id` and the policy check uses the ROUTE's grant —
      // so with two grants for one credential in a session, a placeholder
      // minted under the narrow one would be evaluated against the wide one's
      // policy and billed to the narrow one's budget. A session only ever gets
      // one such grant today, which is what kept it theoretical; it is one
      // `grantsForSession` change away from not being.
      if (row.grant_id !== grant.id) {
        throw deny('AV_PH_WRONG_CONNECTOR', 'that placeholder was issued under a different grant', {
          rule: 'placeholder_grant',
          hint: 'Use a placeholder issued under the grant that covers this route.',
        })
      }
      const phCred = this.vault.db.credentials[row.credential_id]
      if (phCred.id !== cred.id) {
        throw deny('AV_PH_WRONG_CONNECTOR', `that placeholder is for ${phCred.slug}, but the route is ${cred.slug}`, {
          rule: 'placeholder_connector',
          hint: `Send it to /p/${phCred.slug}/... instead.`,
        })
      }

      const field = phCred.fields.find((f) => f.name === row.field)
      const declared = sitesMod.parseSites(field.sites)
      const site = declared.find((s) => sub.matchesSite(occ.location, s))
      if (!site) {
        // The rule that defeats prompt injection: the placeholder is in the
        // request, so the agent tried, but it is not where this credential is
        // ever injected, so nothing is substituted and nothing is sent.
        throw deny('AV_BAD_LOCATION', `a placeholder for ${phCred.slug}.${row.field} appeared in ${sub.describeLocation(occ.location)}, which is not a declared injection site`, {
          rule: 'injection_site',
          hint: `This credential is only ever injected at: ${declared.map((s) => sitesMod.describeSite(s)).join(' | ')}.`,
        })
      }
      substitutions.push({ occ, row, field, site })
    }

    if (!substitutions.length && !assumePlaceholder) {
      throw deny('AV_SESSION_REQUIRED', 'no placeholder in this request', {
        rule: 'no_placeholder',
        hint: `Put a placeholder at: ${cred.fields.map((f) => f.sites.map((s) => sitesMod.describeSite(sitesMod.parseSite(s))).join(' | ')).join(' | ')}. Get one with: agent-vault ph next ${cred.slug}`,
        next: { cli: [`agent-vault ph next ${cred.slug}`], mcp: { tool: 'vault_get_placeholder', args: { cred: cred.slug } } },
      })
    }

    // --- policy, then the limits, in the contract's stage order -----------
    // Every check after this one reads the DECIDED method and path, the ones
    // that go on the wire. Reading the raw path here and the normalised one
    // there is two readers of one input: `/graphql/.` would not end in
    // /graphql for the payload check and would be sent as /graphql.
    stage('policy')
    const decision = policyMod.evaluateHttp(effective, { method: req.method, host: route.host, path: route.path })
    stage('payload')
    // A query only as the upstream URL will hold it. The URL parser ends the
    // query at `#`, deletes tabs and line breaks and trims trailing spaces,
    // so the rules read `fo\nrce=true` as a parameter `fo\nrce` while
    // `force=true` went on the wire, and read `x=1#&dry_run=true` as asking
    // for a dry run that was never sent. The server never passes these;
    // vault_http passes the agent's query as written.
    if (/[#\t\n\r]|[\x00-\x20]$/.test(String(req.query ?? ''))) {
      throw deny('AV_POLICY_DENIED', 'the query string contains a character a URL cannot carry as written (#, a tab, a line break, or trailing whitespace)', {
        rule: 'query_unsendable',
        hint: 'Percent-encode it, as %23, %09, %0A, %0D or %20.',
      })
    }
    evaluatePayload(effective.payload_sets, { method: decision.method, path: decision.path, query: req.query, body: req.body, contentType: sub.getHeader(req, 'content-type') })
    stage('budget')
    this.#budget(grant, effective)
    stage('spend')
    const spending = this.#checkSpend(grant, effective, route, req, decision)
    stage('rate')
    this.#rate(grant, effective, preflight)
    stage('quota')
    this.#quota(grant, effective)

    // --- method override --------------------------------------------------
    // Plenty of frameworks run a POST carrying X-HTTP-Method-Override: DELETE
    // as a DELETE. Only the request-line method was checked, so a grant of
    // GET and POST reached DELETE behaviour, and under on-write a GET that the
    // upstream runs as a DELETE was never held. Every method the upstream
    // might act on is held to the same allowlist and the same approval rule.
    const overrides = methodOverrides(req.headers)
    for (const m of overrides) {
      if (effective.methods && !effective.methods.includes(m)) {
        throw deny('AV_POLICY_DENIED', `method ${m}, asked for in a method-override header, is not allowed`, {
          rule: 'methods',
          hint: `Allowed methods: ${effective.methods.join(', ') || 'none'}.`,
        })
      }
      // And the method-bound routes (F3), which bind a method to its paths.
      // The methods allowlist is the check above, so it is left out here.
      policyMod.evaluateHttp({ ...effective, methods: null }, { method: m, host: route.host, path: route.path })
    }

    // --- approval ----------------------------------------------------------
    // The placeholder's TEXT is in the headers and may be in the body, so
    // swapping the id out of the hash is not enough on its own — the value
    // churns wherever it appears. Each occurrence is replaced by what it
    // stands for, exactly as substitution finds it, leaving a hash over what
    // the human was actually shown.
    //
    // A `<` already in the request is doubled first, so the marker cannot be
    // forged. Without that, a request carrying the marker's text literally
    // hashed the same as one carrying the placeholder there: the placeholder
    // in a header and the marker in the body collided with the two swapped,
    // and the second ran under the first one's approval with the secret in
    // the body. Placeholders never contain `<`, so this is a one-to-one map.
    const canonical = new Map(
      substitutions.map((s) => [s.occ.text, `<av:${s.row.grant_id}:${s.row.field}>`]),
    )
    const stable = (value) => {
      let out = String(value).split('<').join('<<')
      for (const [text, marker] of canonical) out = out.split(text).join(marker)
      return out
    }
    // A Basic header carries its placeholder inside base64, where the text
    // above is never found: renewing the placeholder in `user:<ph>` changed
    // the hash and held the same request for a second approval. The decoded
    // pair is made stable and encoded again — only when the header decodes
    // and encodes back to exactly itself, so two spellings the upstream may
    // read differently can never share an approval.
    const stableHeader = (name, value) => {
      const basic = String(name).toLowerCase() === 'authorization' && /^(basic\s+)(\S+)(\s*)$/i.exec(String(value))
      if (basic) {
        const decoded = Buffer.from(basic[2], 'base64').toString('utf8')
        if (Buffer.from(decoded, 'utf8').toString('base64') === basic[2]) {
          return `${basic[1]}${Buffer.from(stable(decoded), 'utf8').toString('base64')}${basic[3]}`
        }
      }
      return stable(value)
    }
    // Read and rebuilt through latin1 so a binary body survives byte-for-byte.
    const bodySha = req.body ? canon.sha256(Buffer.from(stable(req.body.toString('latin1')), 'latin1')) : ''
    const requestHash = canon.requestHash({
      method: decision.method, host: decision.host, path: decision.path,
      query: stable(req.query || ''), bodySha256: bodySha,
      credentials: substitutions.map((s) => `${s.row.grant_id}:${s.row.field}`),
      // Only what will actually be forwarded: the daemon strips its own
      // headers and the hop-by-hop ones before sending, so including them
      // would make an approval depend on bytes no upstream ever sees.
      headers: req.headers.filter(([n]) => {
        const lower = String(n).toLowerCase()
        return !HOP_BY_HOP.has(lower) && !CONSUMED.has(lower) && !lower.startsWith('av-')
      }).map(([n, v]) => [n, stableHeader(n, v)]),
    })
    stage('approval')
    const firstUse = grant.counters.requests === 0
    const needsHuman = [decision.method, ...overrides].some((method) => policyMod.needsApproval(effective, { method, firstUse }))
    // Preflight stops here. It reports an approval that already exists by its
    // state and never creates one: a prediction must not put a request in
    // front of a human.
    if (preflight) {
      const held = this.approvals.get(requestHash)
      if (needsHuman && held?.state === 'denied') throw deny('AV_POLICY_DENIED', 'a human denied this request', { rule: 'approval' })
      const allowed = !needsHuman || held?.state === 'granted' || (held?.state === 'consumed' && !!held.result)
      return { would: allowed ? 'allow' : 'hold', approval_state: held?.state ?? null }
    }
    if (needsHuman) {
      const verdict = this.#approval(requestHash, { grant, decision, overrides, requestId, req, substitutions, reason: sub.getHeader(req, 'av-reason') })
      if (verdict.status === 'pending') {
        return {
          status: 202,
          host: decision.host,
          rule: decision.rule,
          redactions: 0,
          headers: {
            'content-type': 'application/problem+json',
            'av-decision': 'pending',
            'av-approval-id': verdict.approval.id,
            'retry-after': '5',
          },
          body: Buffer.from(JSON.stringify({
            type: 'https://agent-vault.dev/errors/AV_APPROVAL_PENDING',
            code: 'AV_APPROVAL_PENDING',
            approval_id: verdict.approval.id,
            request_hash: requestHash,
            detail: 'A human must approve this request.',
            retry_after: 5,
            resend: 'resend the byte-identical request; it will execute exactly once',
            next: { cli: [`agent-vault approve ${verdict.approval.id}`], mcp: { tool: 'vault_approval_status', args: { approval_id: verdict.approval.id } } },
          }, null, 2)),
        }
      }
      if (verdict.status === 'denied') {
        throw deny('AV_POLICY_DENIED', 'a human denied this request', { rule: 'approval' })
      }
      if (verdict.status === 'replay') {
        this.vault.audit.write('approval.replayed', { approval_id: verdict.approval.id, request_id: requestId })
        return { ...verdict.approval.result, headers: { ...verdict.approval.result.headers, 'av-replayed': 'true' } }
      }
      approvedRequestHash = requestHash
      // Tell handle() which approval this request just spent, so it can be
      // given back if nothing ever reaches the upstream.
      if (verdict.status === 'granted') onApprovalSpent?.(verdict.approval)
    }

    resources.release = this.#acquire(grant, effective)
    // --- consume, then substitute -----------------------------------------
    const injected = []
    let outgoing = { method: req.method, path: decision.path, query: req.query, headers: req.headers.map(([n, v]) => [n, v]), body: req.body }
    for (const s of substitutions) {
      const row = this.vault.consumePlaceholder(s.row.id)
      onConsume(row)
      const secret = this.vault.revealField(s.row.credential_id, s.row.field)
      injected.push({ secret, label: cred.slug, replacement: s.occ.text, always: true })
      outgoing = sub.apply(outgoing, s.occ.location, s.occ.text, secret)
      this.vault.audit.write('placeholder.resolved', {
        request_id: requestId, placeholder_id: row.id, session_id: session.id,
        credential_slug: cred.slug, field: s.row.field, site: s.site.spec,
        uses: row.uses, max_uses: row.max_uses,
      })
    }
    const quota = this.#quota(grant, effective)
    if (quota) {
      grant.quota_state = quota
      quota.count += 1
      resources.quota = quota
      this.vault.save({ durable: false })
    }
    if (spending) {
      const rid = id.request()
      grant.spend ??= { tokens_used: 0, usd_micros_used: 0, reserved: {} }
      grant.spend.reserved[rid] = { ...spending.reservation, at: Date.now() }
      resources.spend = { ...spending, grant, rid, requestId }
      this.vault.save({ durable: false })
    }
    // Every placeholder the agent sent was replaced, wherever it was. Checked
    // on what will actually be sent rather than trusted from the substitution
    // above: a duplicate JSON key once left the first copy of a placeholder in
    // the body while the second was replaced, and the upstream got both.
    const left = sub.unsubstituted(outgoing, substitutions.map((s) => s.occ.parsed.nonce))
    if (left) {
      throw deny('AV_BAD_LOCATION', `a placeholder would have reached the upstream unsubstituted, in ${sub.describeLocation(left.location)}`, {
        rule: 'injection_site',
        hint: 'Put each placeholder once, at a declared injection site, and nowhere a parser could read it twice.',
      })
    }

    // --- forward -----------------------------------------------------------
    const headers = {}
    const spelled = new Map()
    for (const [n, v] of outgoing.headers) {
      const lower = n.toLowerCase()
      if (HOP_BY_HOP.has(lower) || CONSUMED.has(lower)) continue
      if (lower.startsWith('av-')) continue // never let an agent forge our own headers upstream
      if (lower.startsWith('x-forwarded-') || lower === 'forwarded') continue
      // A session token that survived substitution is a carrier, not content.
      // It authenticates to this daemon and means nothing upstream, so sending
      // it would hand a third party a capability for no reason at all.
      // Array-valued headers are sent as repeated headers by Node, and the
      // string-only test let a live session token through in one.
      const carriesToken = Array.isArray(v)
        ? v.some((x) => SESSION_TOKEN.test(String(x)))
        : SESSION_TOKEN.test(String(v))
      if (carriesToken) continue
      // One key per name, whatever its case. Two keys that differ only in
      // case reached the client as two, and Node kept the later one, while
      // every check read the first. A repeated list header goes out as
      // repeated lines, all of them, as the checks and the approval saw it.
      const key = spelled.get(lower)
      if (key === undefined) { spelled.set(lower, n); headers[n] = v } else headers[key] = [headers[key], v].flat()
    }
    headers.host = route.port ? `${decision.host}:${route.port}` : decision.host
    headers['accept-encoding'] = 'identity'
    // Content-Length is hop-by-hop above, so the agent's never goes out —
    // and nothing put one back, including the one substitution recomputes.
    // Node then chunked a POST, which upstreams that need a length refuse,
    // and sent a GET or DELETE body with no framing at all, so the upstream
    // could not tell where the request ended on a kept-alive connection.
    if (outgoing.body) headers['content-length'] = String(outgoing.body.length)

    const authority = route.port ? `${decision.host}:${route.port}` : decision.host
    // Re-encode each segment of the path policy actually approved. The
    // decision is made on a fully decoded path; putting that straight into a
    // URL lets the parser read it differently a second time, which is how a
    // tab, a `#` or a `?` ended up naming one resource here and another on
    // the wire. Encoding per segment makes the two readings identical by
    // construction.
    const wirePath = policyMod.encodePathForWire(decision.path)
    const upstreamUrl = `${route.scheme === 'http' ? 'http' : 'https'}://${authority}${wirePath}${outgoing.query ? `?${outgoing.query}` : ''}`
    let res
    try {
      res = await this.upstream({ url: upstreamUrl, method: decision.method, headers, body: outgoing.body, pins: cred.pins?.[decision.host] ?? null })
      // A response came back, so the request was certainly delivered and a
      // side effect may have happened. No refund from here on.
      markUpstream()
    } catch (e) {
      // This used to be marked BEFORE the call, so `upstreamOpened` was always
      // true by the time anything could fail and the refund in handle() was
      // unreachable — while the error told the agent its use had been
      // refunded. A failure with no connection behind it cannot have had a
      // side effect, so those are refunded; anything that might have reached
      // the server is not, because refunding a write that happened is worse
      // than charging for one that did not.
      if (e?.code === 'AV_PIN_MISMATCH') {
        const err = deny('AV_PIN_MISMATCH', `${decision.host} presented no pinned key`, { rule: e.reason === 'plaintext' ? 'pin_plaintext' : 'spki_pin', refunded: true })
        err.presented = e.presented ?? []
        throw err
      }
      if (!PRE_CONNECT_ERRORS.has(e?.code)) markUpstream()
      throw deny('AV_UPSTREAM_UNREACHABLE', `could not reach ${decision.host}: ${e.message}`, {
        rule: 'upstream',
        refunded: PRE_CONNECT_ERRORS.has(e?.code),
      })
    }

    res = await this.#redirects(res, { route, effective, decision, headers, upstreamUrl, requestId })
    // --- scrub -------------------------------------------------------------
    const scrubber = new Scrubber([...injected, ...this.vault.allSecrets().filter((s) => !injected.some((i) => i.secret === s.secret))], { ...this.scrubBudget, extraPatterns: this.#extraPatterns() })
    // The path as the audit log may hold it, computed here because this
    // scrubber already exists. Doing it in handle() meant #safeMessage, which
    // calls allSecrets() — decrypting every credential in the vault — on every
    // successful request rather than only on a failing one. More plaintext in
    // memory, more often, for no benefit.
    const auditPath = this.#redactPlaceholders(scrubber.scrub(String(decision.path ?? '').split('?')[0]).text)

    const outHeaders = res.redirectStopped ? { 'av-redirect-stopped': res.redirectStopped } : {}
    let headerRedactions = 0
    for (const [n, v] of Object.entries(res.headers)) {
      const lower = n.toLowerCase()
      if (lower.startsWith('av-')) continue // an upstream must not be able to fake our decisions
      if (lower === 'set-cookie') continue
      // Content-Encoding and Content-Length are dropped because the body that
      // leaves here is decompressed and re-lengthed; forwarding the originals
      // would describe bytes the agent never receives.
      if (HOP_BY_HOP.has(lower) || lower === 'content-encoding' || lower === 'content-length') continue
      // The NAME is upstream text too. Only values were scrubbed, so an
      // upstream that reflects input returned `x-leak-<hex of the secret>: 1`
      // and the agent decoded the credential out of the header name. A name
      // cannot be redacted in place, so a header whose name carries a secret
      // is dropped. Names arrive lowercased, so the check ignores case: a
      // secret with its case folded away is still most of a secret.
      if (scrubber.scrub(lower).redactions || scrubber.containsIgnoringCase(lower)) {
        headerRedactions += 1
        continue
      }
      const scrubbed = scrubber.scrub(String(v))
      headerRedactions += scrubbed.redactions
      outHeaders[lower] = scrubbed.text
    }

    const contentType = String(res.headers['content-type'] || '')
    const contentEncoding = String(res.headers['content-encoding'] || '').toLowerCase().trim()

    // Server-sent events stream through, scrubbed one event at a time. An LLM
    // provider's token stream is the main case: buffering it to the end would
    // turn a streaming response into a long silence and then a wall of text.
    if (contentType.startsWith('text/event-stream') && res.res) {
      // A COMPRESSED event stream has to be decompressed first, or the
      // scrubber searches DEFLATE bytes for a plaintext needle and finds
      // nothing — every time. This branch returned before the decompression
      // below ever ran, so `content-type: text/event-stream` plus
      // `content-encoding: gzip` handed the agent the credential in full:
      // scrubbed zero times, audited as `response.streamed`, and trivially
      // readable with one gunzip. Any upstream that compresses a stream, and
      // any upstream that wants to, defeated the scrubber completely.
      const compressed = !!contentEncoding && contentEncoding !== 'identity'
      const decoder = compressed ? decompressStream(contentEncoding) : new PassThrough()
      if (!decoder) {
        throw deny('AV_UNSCANNABLE', `upstream sent a ${contentEncoding} event stream that could not be decoded, so it could not be scrubbed`, {
          rule: 'content_encoding', hint: 'The response was discarded rather than passed through unread.',
        })
      }
      // stream.pipeline, not .pipe(). `.pipe()` forwards neither errors nor a
      // premature close: an upstream reset with no listener on the source was
      // an uncaught exception that took the daemon down with everyone's
      // sessions, and a reset that emitted no error left the decoder open, so
      // the agent's response hung for good. pipeline() listens on every stage
      // from the start — even before anyone reads — and ends the last one with
      // the error, which scrubEventStream turns into a closing error event.
      const source = streamPipeline(res.res, decoder, () => {})
      this.vault.audit.write('response.streamed', {
        request_id: requestId, content_type: contentType, content_encoding: contentEncoding || null,
      })
      // The request has run. There is nothing to store for a replay, but the
      // approval is spent, and a resend has to know that (see #approval).
      if (approvedRequestHash) {
        const approval = this.approvals.get(approvedRequestHash)
        if (approval) approval.executed_at = new Date().toISOString()
      }
      this.#observeHealth(route, res)
      const streamState = { cut: false }
      return {
        status: res.status, headers: outHeaders, host: decision.host, rule: decision.rule, auditPath, redactions: headerRedactions,
        stream: this.#trackStream(scrubEventStream(source, scrubber, {
          // A compressed stream is an amplifier, and zlib's maxOutputLength
          // bounds one chunk, not the stream: 71 KB of gzip streamed out 70
          // MiB. The bound is counted here, over everything decoded.
          maxBytes: compressed ? MAX_DECOMPRESSED : Infinity,
          onCut: (reason) => {
            streamState.cut = true
            this.vault.audit?.write('response.stream_cut', { request_id: requestId, reason })
          },
        }), resources.spend, () => source.destroy(), streamState),
        spend: this.#spendAudit(resources.spend), routeMatched: decision.route_matched ?? null,
      }
    }

    // Everything else is buffered, decompressed and scrubbed whole.
    let raw
    try {
      raw = res.body ?? (await collect(res.res))
    } catch (e) {
      // A body too large to scan is refused as such. Anything else is the
      // upstream failing part way — a reset mid-body came back as an
      // internal daemon error. The request was delivered, so nothing is
      // refunded.
      if (e instanceof VaultError) throw e
      throw deny('AV_UPSTREAM_UNREACHABLE', `${decision.host} failed while sending its response: ${e.message}`, {
        rule: 'upstream',
        refunded: false,
      })
    }
    const encoding = contentEncoding
    if (encoding && encoding !== 'identity') {
      try {
        raw = decompress(raw, encoding)
      } catch (e) {
        // Refusing is the only safe answer: bytes we cannot read are bytes we
        // cannot scrub, and an unscannable body could carry the secret back.
        throw deny('AV_UNSCANNABLE', `upstream sent ${encoding} that could not be decoded, so it could not be scrubbed`, {
          rule: 'content_encoding', hint: 'The response was discarded rather than passed through unread.',
        })
      }
    }

    // latin1 is a byte-for-byte round trip, so a binary body (an image, a
    // tarball, protobuf) survives unchanged while ASCII secrets still match.
    // Decoding as utf8 here silently corrupted every non-text response.
    const scrubbedBody = scrubber.scrub(raw.toString('latin1'))
    // The scrubber ran out of its layered-decode budget with a secret-bearing
    // candidate still wrapped: it could not finish scanning this body, so it
    // is refused rather than forwarded part-scanned. Same answer as a body too
    // large to buffer or an encoding we cannot decode — bytes we cannot scan.
    if (scrubbedBody.unscannable) {
      throw deny('AV_UNSCANNABLE', 'the response nested encodings deeper than could be decoded within budget, so it could not be fully scrubbed', {
        rule: 'scrub_budget', hint: 'The response was discarded rather than passed through part-scanned.',
      })
    }
    const text = scrubbedBody.text
    const redactions = scrubbedBody.redactions + headerRedactions
    outHeaders['av-request-id'] = requestId
    outHeaders['av-decision'] = 'allow'
    outHeaders['av-grant'] = grant.id
    if (redactions) outHeaders['av-redacted'] = String(redactions)

    const last = substitutions[substitutions.length - 1]
    const phRow = this.vault.db.placeholders[last.row.id]
    if (phRow) {
      outHeaders['av-placeholder-uses-remaining'] = String(Math.max(0, phRow.max_uses - phRow.uses))
      if (phRow.state !== 'active') {
        const succ = this.vault.nextPlaceholder(phRow.id)
        if (succ.placeholder) outHeaders['av-placeholder-next'] = succ.placeholder
      }
    }

    if (redactions) {
      this.vault.audit.write('response.scrubbed', { request_id: requestId, redactions })
    }

    let usage = null
    try { usage = models.usageFromBody(cred.connector_kind, JSON.parse(Buffer.from(text, 'latin1').toString('utf8'))) } catch {}
    const spent = this.#settleSpend(resources.spend, usage)
    this.#observeHealth(route, res)
    const result = {
      spend: spent, routeMatched: decision.route_matched ?? null,
      status: res.status, headers: outHeaders, body: Buffer.from(text, 'latin1'),
      host: decision.host, rule: decision.rule, auditPath, redactions,
    }
    // Store the scrubbed response against the approval so a duplicate resend
    // replays it rather than hitting the upstream a second time.
    if (approvedRequestHash) {
      const approval = this.approvals.get(approvedRequestHash)
      if (approval) {
        approval.result = result
        approval.executed_at = new Date().toISOString()
      }
    }
    return result
  }

  /**
   * Drop approvals that can no longer do anything useful.
   *
   * The map had no sweep at all. Every held request added an entry and nothing
   * ever removed one, in a daemon that runs for weeks — and a consumed
   * approval holds its entire scrubbed response body so a retry can replay it.
   * An agent with a grant set to `approval: each` produces a distinct request
   * hash per call, so it could grow this without limit simply by asking, which
   * is the one thing an agent is always able to do.
   */
  #sweepApprovals() {
    const now = Date.now()
    for (const [hash, a] of this.approvals) {
      const age = now - Date.parse(a.created_at)
      // A human who has not answered in a quarter of an hour is not about to.
      if (a.state === 'pending' && age > PENDING_TTL_MS) { this.approvals.delete(hash); continue }
      // The replay window exists for an SDK retrying in seconds, not for a
      // response body to be held for the life of the process.
      if (a.result && now - Date.parse(a.decided_at || a.created_at) > REPLAY_TTL_MS) a.result = null
      if (a.state !== 'pending' && age > DECIDED_TTL_MS) this.approvals.delete(hash)
    }
  }

  /** Approval state machine, keyed by the request hash so retries are safe. */
  #approval(requestHash, { grant, decision, overrides = [], requestId, reason, req, substitutions }) {
    const existing = this.approvals.get(requestHash)
    if (existing) {
      if (existing.state === 'granted') {
        existing.state = 'consumed' // exactly-once: a resend cannot fire twice
        return { status: 'granted', approval: existing }
      }
      if (existing.state === 'consumed') {
        // Already executed. Replay the stored response so a retrying SDK gets a
        // coherent answer without a second upstream side effect.
        if (existing.result) return { status: 'replay', approval: existing }
        // Still in flight: the resend waits on the same approval.
        if (!existing.executed_at) return { status: 'pending', approval: existing }
        // It ran and there is nothing to replay: the response was streamed, the
        // replay window closed, or the request failed after reaching the
        // upstream. This answered 202 under the spent approval, which is not
        // pending, so no human could approve it again and the resend waited
        // until the entry expired an hour later. The spent one is kept, under
        // a key no request hashes to, so its status can still be read; the
        // resend is a new request and asks a human again.
        this.approvals.delete(requestHash)
        this.approvals.set(`${requestHash}:${existing.id}`, existing)
      } else if (existing.state === 'denied') {
        return { status: 'denied', approval: existing }
      } else {
        return { status: 'pending', approval: existing }
      }
    }

    this.#sweepApprovals()
    if (this.approvals.size >= MAX_APPROVALS) {
      // Refuse rather than evict. Evicting would drop an approval a human may
      // be looking at right now, and it would let an agent flush a pending
      // request it did not like by making a thousand more.
      throw deny('AV_POLICY_DENIED', `too many requests are waiting for approval (${this.approvals.size})`, {
        rule: 'approval',
        hint: 'Approve or deny the waiting requests, or wait for them to expire.',
      })
    }

    const approval = {
      id: id.approval(),
      request_hash: requestHash,
      grant_id: grant.id,
      // A method-override header is shown, because it is what the upstream
      // may actually run. The summary is all the human sees.
      summary: overrides.length
        ? `${decision.method} (overridden to ${overrides.join(', ')}) ${decision.host}${decision.path}`
        : `${decision.method} ${decision.host}${decision.path}`,
      reason: reason ? this.#safeMessage({ message: reason }) : null,
      preview: this.#previewOf(req, substitutions, decision),
      state: 'pending',
      created_at: new Date().toISOString(),
    }
    approval.summary = this.#safeMessage({ message: approval.summary })
    this.approvals.set(requestHash, approval)
    this.vault.audit.write('approval.requested', {
      request_id: requestId, approval_id: approval.id, grant_id: grant.id, summary: approval.summary,
      agent_reason_untrusted: approval.reason,
    })
    try { this.onPending?.({ kind: 'request', id: approval.id, headline: approval.summary, created_at: approval.created_at }) } catch {}
    return { status: 'pending', approval }
  }

  /**
   * What happened to an approval, for the agent that is waiting on it.
   *
   * The 202 has always told agents to call `vault_approval_status`, and that
   * tool did not exist — the third error path in this codebase to name
   * something that was never built. It lands on the busiest one: every held
   * write hits it, and an agent that follows the instruction gets a
   * tool-not-found with no other way to learn the human answered.
   *
   * Read-only, and it reveals nothing the agent did not already send: a state,
   * and the hash it was given in the 202.
   */
  approvalStatus(approvalId) {
    for (const approval of this.approvals.values()) {
      if (approval.id !== approvalId) continue
      return {
        approval_id: approval.id,
        state: approval.state,
        request_hash: approval.request_hash,
        created_at: approval.created_at ?? null,
        decided_at: approval.decided_at ?? null,
        next: approval.state === 'granted'
          ? 'resend the request; it will execute exactly once'
          : approval.state === 'pending' ? 'a human has not answered yet' : null,
      }
    }
    return null
  }

  /**
   * A human's answer to a pending approval.
   *
   * Only a PENDING one. This used to set the state whatever it was, so
   * granting an approval that had already run armed it again and the next
   * resend executed the write a second time, and denying one handed back the
   * whole approval — its cached response included, with the successor
   * placeholder in `av-placeholder-next` — to anything on the control socket,
   * where deny is ungated. The session-request path already refused anything
   * no longer pending; this is the same rule, and a pending approval has no
   * response stored on it to hand back.
   */
  decideApproval(approvalId, granted) {
    for (const approval of this.approvals.values()) {
      if (approval.id !== approvalId) continue
      if (approval.state !== 'pending') {
        throw deny('AV_POLICY_DENIED', `already ${approval.state}`, { rule: 'approval' })
      }
      approval.state = granted ? 'granted' : 'denied'
      approval.decided_at = new Date().toISOString()
      this.vault.audit.write(granted ? 'approval.granted' : 'approval.denied', { approval_id: approvalId })
      return approval
    }
    throw deny('AV_NOT_FOUND', `no approval ${approvalId}`)
  }

  pendingApprovals() {
    return [...this.approvals.values()].filter((a) => a.state === 'pending')
  }
}

/** Headers a framework may honour in place of the request-line method. */
const METHOD_OVERRIDE_HEADERS = new Set(['x-http-method-override', 'x-http-method', 'x-method-override'])

/** Every method a method-override header asks for, uppercased, in order. */
function methodOverrides(headers) {
  const out = []
  for (const [n, v] of headers) {
    if (!METHOD_OVERRIDE_HEADERS.has(String(n).toLowerCase())) continue
    for (const one of [v].flat()) {
      for (const m of String(one).split(',')) {
        const method = m.trim().toUpperCase()
        if (method && !out.includes(method)) out.push(method)
      }
    }
  }
  return out
}

/**
 * Headers a request carries once. Every check reads one value for each, and
 * a second copy is a second reading: the payload rules read the first
 * Content-Type while the outbound object kept the last, so a body checked as
 * JSON went upstream labelled as form data.
 */
const SINGLE_VALUED = new Set(['content-type', 'content-length', 'content-encoding', 'transfer-encoding', 'authorization'])

/**
 * The request's headers with each single-valued name folded to one entry,
 * done once, before anything reads them. A copy that repeats the first
 * exactly is dropped. One that differs in value, or only in the case of its
 * name, is refused: which of the two an upstream acts on is its choice, not
 * ours, so there is no copy we could safely check instead.
 */
function foldHeaders(headers) {
  const out = []
  const first = new Map()
  for (const [name, value] of headers) {
    const lower = String(name).toLowerCase()
    if (!SINGLE_VALUED.has(lower)) { out.push([name, value]); continue }
    const values = [value].flat().map(String)
    if (!values.length) values.push('')
    const prior = first.get(lower)
    const differs = new Set(prior ? [prior[1], ...values] : values).size > 1 || (prior && prior[0] !== name)
    if (differs) {
      throw deny('AV_POLICY_DENIED', `the ${lower} header appears more than once, so the upstream could read a different one from the one checked`, {
        rule: 'header_duplicate',
        hint: `Send ${lower} once.`,
      })
    }
    if (prior) continue
    first.set(lower, [name, values[0]])
    out.push([name, values[0]])
  }
  return out
}

/**
 * Default upstream: Node's http(s) client, redirects never followed. The
 * response stream is handed back rather than buffered here, so the pipeline
 * can decide between streaming and buffering.
 */
// The connectors' pinned request (F11), loaded by its contract name. It is
// the default upstream once it exists. Until then, a request with no pins
// goes out as before, and one WITH pins is refused, unsent: a pin nothing can
// check must not quietly become no pin at all.
let pinning
async function defaultUpstream({ url, method, headers, body, pins = null }) {
  if (pinning === undefined) {
    try { pinning = await import('../connectors/pinning.js') } catch { pinning = null }
  }
  if (typeof pinning?.pinnedRequest === 'function') return pinning.pinnedRequest({ url, method, headers, body, pins })
  if (pins != null) throw Object.assign(new Error('certificate pins are set and pin checking is not available'), { code: 'AV_PIN_MISMATCH', reason: 'unavailable' })
  return new Promise((resolve, reject) => {
    const u = new URL(url)
    const fn = u.protocol === 'http:' ? httpRequest : httpsRequest
    const req = fn(
      { hostname: u.hostname, port: u.port || (u.protocol === 'http:' ? 80 : 443), path: `${u.pathname}${u.search}`, method, headers },
      (res) => resolve({ status: res.statusCode, headers: res.headers, res }),
    )
    req.on('error', reject)
    req.setTimeout(30_000, () => req.destroy(new Error('upstream timeout')))
    if (body) req.write(body)
    req.end()
  })
}

/**
 * Read a whole response into memory, bounded.
 *
 * This had no cap at all, so an upstream decided how much of the daemon's
 * memory a single request would take — and the daemon is one process holding
 * everyone's credentials. The buffered path exists because a body has to be
 * scannable; a body too large to hold is a body that cannot be scanned, which
 * is already the documented answer.
 */
function collect(stream, limit = MAX_RESPONSE_BYTES) {
  return new Promise((resolve, reject) => {
    const chunks = []
    let size = 0
    stream.on('data', (c) => {
      size += c.length
      if (size > limit) {
        stream.destroy()
        reject(deny('AV_UNSCANNABLE', `the upstream sent more than ${Math.round(limit / 1024 / 1024)} MiB, which is more than can be buffered and scanned`, {
          rule: 'response_size',
          hint: 'The response was discarded rather than passed through unread.',
        }))
        return
      }
      chunks.push(c)
    })
    stream.on('end', () => resolve(Buffer.concat(chunks)))
    stream.on('error', reject)
  })
}

/**
 * A streaming decompressor for one content-encoding, or null if we cannot read
 * it. Bounded, because a compressed stream is an amplifier: a few kilobytes of
 * upstream bytes can expand to gigabytes in this process, and the daemon is
 * single-threaded.
 */
function decompressStream(encoding) {
  const opts = { maxOutputLength: MAX_DECOMPRESSED }
  switch (encoding) {
    case 'gzip':
    case 'x-gzip': return zlib.createGunzip(opts)
    case 'deflate': return zlib.createInflate(opts)
    case 'br': return zlib.createBrotliDecompress({ maxOutputLength: MAX_DECOMPRESSED })
    case 'zstd':
      return typeof zlib.createZstdDecompress === 'function'
        ? zlib.createZstdDecompress(opts)
        : null
    default: return null
  }
}

function decompress(buf, encoding) {
  // Capped. Without maxOutputLength a 219 KB upstream response expands to
  // hundreds of megabytes in this process before anything can object, and
  // these are the SYNCHRONOUS entry points, so the expansion happens with the
  // event loop held. A compression bomb is the cheapest denial of service an
  // upstream has.
  const opts = { maxOutputLength: MAX_DECOMPRESSED }
  switch (encoding) {
    case 'gzip':
    case 'x-gzip': return zlib.gunzipSync(buf, opts)
    case 'deflate': return zlib.inflateSync(buf, opts)
    case 'br': return zlib.brotliDecompressSync(buf, { maxOutputLength: MAX_DECOMPRESSED })
    case 'zstd':
      if (typeof zlib.zstdDecompressSync === 'function') return zlib.zstdDecompressSync(buf, opts)
      throw new Error('zstd is not supported by this Node build')
    default: throw new Error(`unknown content-encoding ${encoding}`)
  }
}

/**
 * Scrub a server-sent event stream.
 *
 * Three things are going on, because one scrubber is not enough here.
 *
 * The raw bytes go through Scrubber.stream(), which holds back the longest
 * needle so a secret spanning a chunk boundary is seen whole. This used to
 * scrub each `\n\n` event in isolation, which reads as safe and is not.
 *
 * That still misses a secret the upstream splits across events, because the
 * framing — `"}\n\ndata: {"` — sits between the halves and the secret is not
 * contiguous in the bytes anywhere. So the `data:` payloads are concatenated
 * and watched separately. That catches a raw-text stream split across events.
 *
 * A secret split across *application* fields, as in `{"delta":"ghp_REAL"}`
 * then `{"delta":"SECRET"}`, is caught by reading each JSON payload and
 * concatenating the values found at the same key path — `delta.text`,
 * `choices.0.delta.content` — at the same path and indexes, wherever in an
 * array the element sits, and where an SDK continues one path at another
 * (eventRuns), which is how a client puts the text back together. When any of
 * these finds a secret the stream is cut rather than continued — the agent may
 * have received a fragment, and it will not receive the rest. It requires a
 * hostile upstream, which already holds the credential; what it buys is
 * teaching the agent a secret it was never given, and that is worth failing
 * closed over.
 *
 * The stream is also cut, never left hanging or thrown, when the upstream
 * fails part way, when one event grows past MAX_EVENT_BYTES without ending,
 * and when more than `maxBytes` has been decoded.
 */
async function* scrubEventStream(source, scrubber, { maxBytes = Infinity, onCut } = {}) {
  const frame = scrubber.stream()
  let pending = ''
  let scanned = 0
  let carry = ''
  let assembled = ''
  let total = 0
  const keep = scrubber.overlap * 4
  const runs = eventRuns(scrubber, keep)

  const cut = (reason, detail) => {
    onCut?.(reason)
    return Buffer.from(`event: error\ndata: ${JSON.stringify({ code: 'AV_UNSCANNABLE', detail })}\n\n`, 'latin1')
  }

  /**
   * Line endings as LF. The spec allows CRLF and a bare CR as well, and
   * framing only on `\n\n` meant a CRLF stream was never split at all: the
   * agent got nothing until the upstream closed, and every byte sat in
   * `pending` until then. A CR at the very end is held back, since it may be
   * the first half of a CRLF still in flight.
   */
  const lf = (text) => {
    let t = carry + text
    carry = ''
    if (t.endsWith('\r')) { carry = '\r'; t = t.slice(0, -1) }
    return t.replace(/\r\n?/g, '\n')
  }

  const dataOf = (event) => event.split('\n')
    .filter((l) => l.startsWith('data:'))
    .map((l) => l.slice(5).replace(/^ /, ''))

  /**
   * The payload so far, as a client would actually put it back together.
   *
   * An LLM token stream is `{"delta":"ghp_SSE"}` then `{"delta":"CRET"}`, and
   * every client concatenates the VALUES. So this pulls out the JSON string
   * literals that are not object keys — a literal followed by `:` is a key —
   * and joins them.
   *
   * It used to strip all punctuation instead, which is wrong in both
   * directions: it glued the key text onto the value (`delta` + `ghp_...`),
   * so an exact secret could only be caught by the loose shape patterns, and
   * those then had to match without a leading boundary — which is what made
   * them fire on ordinary English like `disk-usage_by_repository`.
   *
   * Joining every value is still not what a client does, which is why the
   * per-path view below exists: the metadata values of a real Anthropic
   * stream (`content_block_delta`, `text_delta`) land between the halves of
   * the text here, and neither half matches.
   */
  const jsonValues = (text) => {
    let out = ''
    const literal = /"((?:[^"\\]|\\.)*)"(\s*:)?/g
    let m
    while ((m = literal.exec(text)) !== null) {
      if (m[2]) continue // a key, not a value
      out += m[1].replace(/\\"/g, '"').replace(/\\\\/g, '\\')
    }
    return out
  }

  /**
   * The reason to cut because of the payload so far, however reassembled, or
   * null. A secret found in any reassembly cuts; so does a reassembly the
   * scrubber could not finish decoding within its budget, which is refused
   * rather than forwarded part-scanned.
   */
  const leaked = (text) => {
    // As a JSON client reassembles it (values only, concatenated), and a
    // last cruder pass for framing that is not JSON at all.
    for (const v of [text, jsonValues(text), text.replace(/[^A-Za-z0-9_\-+/=]/g, '')]) {
      if (!v) continue
      const r = scrubber.scrub(v)
      if (r.redactions > 0) return 'credential_split_across_events'
      if (r.unscannable) return 'response_unscannable'
    }
    return null
  }

  /** Append each string in one JSON payload to its runs; the reason to cut, or null. */
  const leakedByPath = (payload) => {
    const parsed = parseEventJson(payload)
    return parsed === undefined ? null : runs.add(parsed)
  }

  /** Every complete event now in `pending`, taken out of it. */
  const events = () => {
    const out = []
    let boundary
    // From where the last search stopped: searching the whole of a growing
    // `pending` on every chunk is quadratic in the size of one event.
    while ((boundary = pending.indexOf('\n\n', scanned)) !== -1) {
      out.push(pending.slice(0, boundary + 2))
      pending = pending.slice(boundary + 2)
      scanned = 0
    }
    scanned = Math.max(0, pending.length - 1)
    return out
  }

  /** Add one event to every reassembly; the reason to cut, or null. */
  const leaks = (event) => {
    const data = dataOf(event)
    // Searched with all of this event on, then trimmed: the same order as
    // the per-path runs, for the same reason.
    const joined = assembled + data.join('')
    // Keep only enough to span a split; an LLM response is unbounded.
    assembled = joined.length > keep ? joined.slice(-keep) : joined
    const reason = leaked(joined)
    if (reason) return reason
    return data.length > 0 ? leakedByPath(data.join('\n')) : null
  }

  const WHY = {
    credential_split_across_events: 'the upstream split a credential across events; the stream was cut',
    too_many_paths: `the upstream stream used more than ${MAX_SSE_PATHS} JSON key paths, more than can be tracked for a credential split across events; the stream was cut`,
    too_many_indexes: `the upstream stream put more than ${MAX_SSE_INDEXES} index fields over one value, more than can be tracked for a credential split across events; the stream was cut`,
    response_unscannable: 'the upstream nested encodings deeper than could be decoded within budget, so an event could not be fully scrubbed; the stream was cut',
  }

  try {
    for await (const chunk of source) {
      total += chunk.length
      if (total > maxBytes) {
        yield cut('stream_too_large', `the upstream stream decoded to more than ${Math.round(maxBytes / 1024 / 1024)} MiB; the stream was cut`)
        return
      }
      pending += lf(frame.push(chunk.toString('latin1')))
      for (const event of events()) {
        const reason = leaks(event)
        if (reason) { yield cut(reason, WHY[reason]); return }
        yield Buffer.from(event, 'latin1')
      }
      if (pending.length > MAX_EVENT_BYTES) {
        yield cut('event_too_large', `one event grew past ${Math.round(MAX_EVENT_BYTES / 1024 / 1024)} MiB without ending; the stream was cut`)
        return
      }
    }
  } catch {
    // The upstream failed part way. What is held back is an unfinished event
    // and is dropped with it; the agent is told the stream ended badly
    // rather than left waiting, and nothing is thrown at the code writing
    // the response.
    yield cut('upstream_failed', 'the upstream stream failed before it finished; the stream was cut')
    return
  }
  // What the scrubber held back can be several events, not one.
  pending += lf(frame.flush()) + (carry ? '\n' : '')
  for (const event of [...events(), pending].filter(Boolean)) {
    const reason = leaks(event)
    if (reason) { yield cut(reason, WHY[reason]); return }
    yield Buffer.from(event, 'latin1')
  }
}

/**
 * An event's `data:` as JSON, or undefined if it is not JSON.
 *
 * Python's json.loads also takes NaN, Infinity and -Infinity, and the Python
 * SDKs read events with it. JSON.parse refused such a payload, so it was never
 * reassembled by path, and an upstream that put `"p":NaN` in every event had
 * only the joined view to beat.
 */
function parseEventJson(payload) {
  try { return JSON.parse(payload) } catch { /* try it as Python would */ }
  // A scan rather than a regex: a regex over a string literal of several
  // megabytes overflows the stack.
  let swapped = ''
  let from = 0
  let inString = false
  for (let i = 0; i < payload.length; i++) {
    const c = payload[i]
    if (inString) {
      if (c === '\\') i++
      else if (c === '"') inString = false
      continue
    }
    if (c === '"') { inString = true; continue }
    const word = payload.startsWith('NaN', i) ? 3 : payload.startsWith('Infinity', i) ? 8 : 0
    if (!word) continue
    swapped += payload.slice(from, payload[i - 1] === '-' ? i - 1 : i) + 'null'
    i += word - 1
    from = i + 1
  }
  if (from === 0) return undefined
  try { return JSON.parse(swapped + payload.slice(from)) } catch { return undefined }
}

// A field a client may gather a stream by: `index`, `output_index`, ...
//
// Not `start_index` or `end_index`. Those are character offsets into the
// text, which no client groups by, and the Responses API puts both inside an
// annotation that already sits under three index fields: every ordinary
// `url_citation` event was cut for having more than MAX_SSE_INDEXES.
const INDEX_FIELD = /^(?:index|(?!start_|end_).+_index)$/

/**
 * Every string in a parsed JSON value, with its key path (`["delta","text"]`)
 * and the index fields of every object above it.
 *
 * The path is the list of segments as JSON, an array index as a number and a
 * key as a string, so no two places share one. It was the keys joined with
 * `.`, and a key may contain a dot: {"a":{"b":…}} and {"a.b":…} were both
 * `a.b`, so a value at one was appended between the halves of a secret at the
 * other and no run ever held it whole.
 */
function* jsonStringsByPath(value, path = [], indexes = []) {
  if (typeof value === 'string') { yield { path, indexes, value }; return }
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) yield* jsonStringsByPath(value[i], [...path, i], indexes)
  } else if (value && typeof value === 'object') {
    const here = Object.entries(value)
      .filter(([k, v]) => INDEX_FIELD.test(k) && (typeof v === 'number' || typeof v === 'string'))
      .map(([k, v]) => [path.length, k, v])
    const inner = here.length ? [...indexes, ...here] : indexes
    for (const [k, v] of Object.entries(value)) yield* jsonStringsByPath(v, [...path, k], inner)
  }
}

// The fields a client appends from one event to the next.
const APPENDED = new Set(['text', 'content', 'delta', 'arguments', 'partial_json', 'thinking', 'refusal', 'reasoning', 'reasoning_content'])

// What a missing index field is read as: zero, as a typed client's zero value
// does (Go, Rust, C#), and a group of its own, as a client that keys a map by
// it does.
const MISSING = [0, null]

/**
 * Values an SDK continues at another key path: a block or a part starts with
 * its text, and each delta appends to it. [event type, path, what is being
 * continued]. `{ at }` is an array position the SDK reads as that index field.
 *
 * A secret that began in a `content_block_start` and ended in the deltas
 * after it was in two runs that never met: `content_block.text` and
 * `delta.text`. The Anthropic SDK puts them in one block.
 */
const CONTINUES = [
  ['content_block_start', ['content_block', 'text'], 'text'],
  ['content_block_start', ['content_block', 'thinking'], 'thinking'],
  ['content_block_delta', ['delta', 'text'], 'text'],
  ['content_block_delta', ['delta', 'thinking'], 'thinking'],
  ['response.output_item.added', ['item', 'content', { at: 'content_index' }, 'text'], 'output_text'],
  ['response.content_part.added', ['part', 'text'], 'output_text'],
  ['response.output_text.delta', ['delta'], 'output_text'],
  ['response.output_item.added', ['item', 'content', { at: 'content_index' }, 'refusal'], 'refusal'],
  ['response.content_part.added', ['part', 'refusal'], 'refusal'],
  ['response.refusal.delta', ['delta'], 'refusal'],
  ['response.output_item.added', ['item', 'arguments'], 'arguments'],
  ['response.function_call_arguments.delta', ['delta'], 'arguments'],
  ['response.output_item.added', ['item', 'summary', { at: 'summary_index' }, 'text'], 'summary'],
  ['response.reasoning_summary_part.added', ['part', 'text'], 'summary'],
  ['response.reasoning_summary_text.delta', ['delta'], 'summary'],
]

/**
 * The ways a client may gather one string: { gathering, indexes, appended }.
 *
 * By its key path as written. By the same path with array positions left
 * out, because OpenAI's SDKs gather `choices[]` and `tool_calls[]` by their
 * `index` and not by where the element sits: a choice that moved to another
 * position between events started a new run, and the SDK still joined it to
 * the old one. And as the value an SDK continues, from CONTINUES.
 */
function* gatheringsOf({ path, indexes }, type) {
  const appended = APPENDED.has(path[path.length - 1])
  yield { gathering: JSON.stringify(path), indexes, appended }
  if (path.some((s) => typeof s === 'number')) {
    yield { gathering: JSON.stringify(path.map((s) => (typeof s === 'number' ? null : s))), indexes, appended }
  }
  for (const [eventType, pattern, continued] of CONTINUES) {
    if (eventType !== type || pattern.length !== path.length) continue
    const positions = []
    const matches = pattern.every((p, i) => {
      if (typeof p === 'string') return p === path[i]
      if (typeof path[i] !== 'number') return false
      positions.push([0, p.at, path[i]])
      return true
    })
    if (!matches) continue
    const own = indexes.filter(([depth, key]) => !positions.some((p) => depth === 0 && p[1] === key))
    yield { gathering: `#${continued}`, indexes: [...own, ...positions], appended: true }
  }
}

/**
 * The runs an event stream's strings are gathered into. `add(payload)`
 * appends every string in one parsed payload and returns the reason to cut,
 * or null.
 *
 * A run is a gathering and a choice of the index fields above the string:
 * each one either left out or given one of its values. A client gathers text
 * by key path and, usually, by an index: the Anthropic SDK by the event's
 * `index`, OpenAI's by `choices[].index` and `tool_calls[].index`, the
 * Responses API by `output_index` and `content_index`. Keyed by path alone,
 * an event at another index between the halves of a secret landed in the
 * same run and hid it. Keyed by every index, an upstream varies one the
 * client ignores. So every combination is a run.
 *
 * An index written as a string is also its number, because a JavaScript SDK
 * that indexes an array with "0" reads the element at 0. And on an appended
 * field, an index field seen anywhere at that gathering but missing from this
 * object is read as each of MISSING. A missing index that came before the
 * field was first seen cannot be filed then, so when it is first seen, every
 * run there is copied into its MISSING runs: until now, everything gathered
 * there lacked it.
 *
 * Each run is searched with ALL of the new value on it and only then
 * trimmed. Trimming first threw away the start of a long value, so the second
 * half of a secret followed by 2,000 ordinary characters was never searched
 * next to its first half.
 *
 * A run is never forgotten to make room for another. This used to evict the
 * least recently used one, and an event with 65 metadata keys between the two
 * halves of a secret evicted `delta.text`: its next value started a fresh
 * run, and the client put the secret back together. Past MAX_SSE_PATHS the
 * stream is cut. A long key is hashed, so a hostile key costs a digest, not
 * its length.
 */
function eventRuns(scrubber, keep) {
  const runs = new Map()
  // For each appended gathering: the index fields seen there, and its runs
  // with the choice each one is.
  const seen = new Map()

  const keyOf = (gathering, chosen) => {
    const key = JSON.stringify([gathering, chosen])
    return key.length > 256 ? `#${canon.sha256(key)}` : key
  }
  const bySlot = (a, b) => a[0] - b[0] || (a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0)
  const valuesOf = (v) => (typeof v === 'string' && /^(?:0|[1-9][0-9]{0,15})$/.test(v) ? [v, Number(v)] : [v])

  /** The new run's key, or the reason to cut. */
  const room = (key) => (runs.has(key) || runs.size < MAX_SSE_PATHS ? null : 'too_many_paths')

  function gather({ gathering, indexes, appended }, value) {
    let here = null
    if (appended) {
      if (!seen.has(gathering)) seen.set(gathering, { fields: new Map(), runs: new Map() })
      here = seen.get(gathering)
      for (const [depth, key] of indexes) {
        const id = JSON.stringify([depth, key])
        if (here.fields.has(id)) continue
        for (const [from, chosen] of [...here.runs]) {
          for (const missing of MISSING) {
            const choice = [...chosen, [depth, key, missing]].sort(bySlot)
            const to = keyOf(gathering, choice)
            if (runs.has(to)) continue
            const full = room(to)
            if (full) return full
            runs.set(to, runs.get(from))
            here.runs.set(to, choice)
          }
        }
        here.fields.set(id, [depth, key])
      }
    }
    const slots = indexes.map(([depth, key, v]) => [depth, key, valuesOf(v)])
    for (const [depth, key] of here?.fields.values() ?? []) {
      if (!indexes.some(([d, k]) => d === depth && k === key)) slots.push([depth, key, MISSING])
    }
    if (slots.length > MAX_SSE_INDEXES) return 'too_many_indexes'
    slots.sort(bySlot)
    let choices = [[]]
    for (const [depth, key, values] of slots) {
      choices = choices.flatMap((c) => [c, ...values.map((v) => [...c, [depth, key, v]])])
    }
    for (const chosen of choices) {
      const key = keyOf(gathering, chosen)
      const full = room(key)
      if (full) return full
      const run = (runs.get(key) ?? '') + value
      const r = scrubber.scrub(run)
      if (r.redactions > 0) return 'credential_split_across_events'
      if (r.unscannable) return 'response_unscannable'
      runs.set(key, run.length > keep ? run.slice(-keep) : run)
      here?.runs.set(key, chosen)
    }
    return null
  }

  return {
    add(payload) {
      const type = payload && typeof payload === 'object' && typeof payload.type === 'string' ? payload.type : null
      for (const string of jsonStringsByPath(payload)) {
        for (const way of gatheringsOf(string, type)) {
          const reason = gather(way, string.value)
          if (reason) return reason
        }
      }
      return null
    },
  }
}

// Request headers that commonly carry a credential. Never shown in a preview.
const PREVIEW_OMITTED = new Set(['authorization', 'proxy-authorization', 'cookie', 'x-api-key', 'x-goog-api-key'])
const PREVIEW_MAX = 8192

/**
 * F13: a held request as a human may safely read it, built from the request
 * the agent sent (before substitution).
 *
 * Each placeholder at its site becomes `«slug.field @ location»`. Any other
 * placeholder text, in any encoding the detector knows, becomes
 * `«placeholder»`, and so does a session token. Then `scrub` runs over all
 * of it, so a real secret the agent pasted shows as `[[av:redacted:…]]`.
 * Headers that carry credentials by name are left out. The whole preview is
 * at most 8 KiB. It is shown to a human and never audited.
 *
 * substitutions: [{ text, label, location, part }], where `part` is the
 * part of the request it was found in ('headers', 'query', 'body', 'path');
 * scrub: (text) => text.
 */
export function approvalPreview({ req, decision, substitutions, scrub }) {
  // One placeholder can sit at two sites, as the same text. Each part of the
  // preview is labelled with the site in THAT part, so the body never says
  // "header" for the copy that is in the body.
  const clean = (value, part) => {
    let text = String(value)
    const hits = detectAll(text)
    const ordered = [...substitutions.filter((s) => s.part === part), ...substitutions.filter((s) => s.part !== part)]
    for (const s of ordered) text = text.split(s.text).join(`«${s.label} @ ${s.location}»`)
    if (hits.length) {
      // Every other spelling, found with the detector and removed with a
      // scrubber over exactly those texts and their encodings.
      const r = new Scrubber(hits.map((h) => ({ secret: h.text, replacement: '«placeholder»', always: true, label: 'placeholder' }))).scrub(text)
      text = r.unscannable ? '«placeholder»' : r.text
    }
    text = text.replace(new RegExp(SESSION_TOKEN.source, 'g'), '«session token»')
    return scrub(text)
  }
  const cap = (text, n = 256) => (text.length > n ? `${text.slice(0, n)}…` : text)

  const raw = req.body ? Buffer.from(req.body) : Buffer.alloc(0)
  const type = sub.getHeader(req, 'content-type') || null
  let kind = raw.length ? 'text' : 'none'
  let text = raw.length ? raw.toString('utf8') : null
  if (text !== null && (!Buffer.from(text, 'utf8').equals(raw) || /[\x00-\x08\x0b\x0c\x0e-\x1f]/.test(text))) { kind = 'binary'; text = null }
  if (text !== null && /^application\/(?:json|[^/;]+\+json)\s*(?:;|$)/i.test(type ?? '')) {
    kind = 'json'
    // Pretty-printed only when it parses strictly. JSON.parse keeps the LAST
    // of two duplicate keys, so a pretty copy would show the human one value
    // while the upstream may act on the other; such a body is shown as sent.
    try { text = JSON.stringify(parseStrictJson(text), null, 2) } catch { /* shown as sent */ }
  } else if (text !== null && /^application\/x-www-form-urlencoded\s*(?:;|$)/i.test(type ?? '')) kind = 'form'

  const full = text === null ? null : clean(text, 'body')
  let shown = full === null ? null : Buffer.from(full).subarray(0, 4096).toString('utf8')
  const headers = []
  for (const [name, value] of req.headers) {
    const lower = String(name).toLowerCase()
    if (PREVIEW_OMITTED.has(lower) || HOP_BY_HOP.has(lower) || lower.startsWith('av-')) continue
    if (headers.length === 32) break
    headers.push([clean(name, 'headers'), cap(clean(value, 'headers'))])
  }
  const preview = {
    method: clean(decision.method, 'path'), host: clean(decision.host, 'path'), path: cap(clean(decision.path, 'path'), 1024),
    query: [...new URLSearchParams(req.query ?? '')].slice(0, 64).map(([name, value]) => [cap(clean(name, 'query')), cap(clean(value, 'query'))]),
    headers,
    content_type: type === null ? null : cap(clean(type, 'headers')),
    body: { text: shown, bytes: raw.length, shown_bytes: shown === null ? 0 : Buffer.byteLength(shown), truncated: full !== null && full !== shown, kind },
    placeholders: substitutions.map((s) => ({ label: s.label, location: s.location })),
    untrusted: true,
  }
  // Every variable part is bounded, not only the body: a URL alone can be
  // larger than the whole allowance.
  while (Buffer.byteLength(JSON.stringify(preview)) > PREVIEW_MAX) {
    if (preview.body.text) {
      shown = preview.body.text.slice(0, Math.max(0, preview.body.text.length - 256))
      Object.assign(preview.body, { text: shown, shown_bytes: Buffer.byteLength(shown), truncated: true })
    } else if (preview.headers.length) preview.headers.pop()
    else if (preview.query.length) preview.query.pop()
    else if (preview.placeholders.length) preview.placeholders.pop()
    else { preview.path = cap(preview.path, 256); break }
  }
  return preview
}

/** Which part of a request a located placeholder sits in. */
function previewPart(region) {
  if (region === 'header' || region === 'header-name' || region === 'basic') return 'headers'
  if (region === 'query' || region === 'query-key') return 'query'
  if (region === 'path') return 'path'
  return 'body'
}

/** The refusal for a grant whose own lifetime ran out (F18). */
function grantExpired(slug) {
  return deny('AV_GRANT_EXPIRED', `this session's grant for ${slug ?? 'this credential'} expired`, {
    rule: 'grant_ttl',
    next: { mcp: { tool: 'vault_request_session' } },
  })
}

/** Cleanup also runs when an iterator is closed before its first next(). */
function closeAware(source, finish, observe = null) {
  const iterator = source[Symbol.asyncIterator]()
  let closed = false
  const end = (complete) => { if (!closed) { closed = true; finish(complete) } }
  return {
    [Symbol.asyncIterator]() { return this },
    async next() {
      try {
        const item = await iterator.next()
        if (item.done) end(true)
        else observe?.(item.value)
        return item
      } catch (e) { end(false); throw e }
    },
    async return(value) {
      try { return await iterator.return?.(value) ?? { done: true, value } }
      finally { end(false) }
    },
    async throw(error) {
      try { if (iterator.throw) return await iterator.throw(error); throw error }
      finally { end(false) }
    },
  }
}
