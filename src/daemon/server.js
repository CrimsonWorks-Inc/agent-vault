// The daemon's listeners.
//
// Two surfaces, deliberately separated:
//   - the gateway (loopback TCP, and optionally a network listener): /p/, /t/,
//     /v1/* discovery, and /mcp. Everything here spends capability.
//   - the control API (Unix socket only, mode 0600): everything that creates or
//     widens capability. It never binds a network address, which is the rule
//     that keeps a remote peer from growing its own grants.

import { createServer } from 'node:http'
import { BlockList, isIP } from 'node:net'
import { unlinkSync, existsSync, chmodSync, chownSync, statSync, readFileSync } from 'node:fs'
import { execFileSync } from 'node:child_process'
import { Pipeline } from './pipeline.js'
import { McpServer, PROTOCOL_VERSIONS, LATEST_PROTOCOL } from './mcp.js'
import { getProfile, defaultSites, defaultField } from '../connectors/profiles.js'
import * as sitesMod from '../core/sites.js'
import { VaultError, deny } from '../core/errors.js'
import * as policyMod from '../core/policy.js'
import * as webauthn from '../ui/webauthn.js'
import { ensureCertificate, loadMaterial, tlsPaths } from './tls.js'
import { randomBytes } from 'node:crypto'
import { MIN_SECRET_LEN, compileScrubPattern } from '../core/scrub.js'
import * as ph from '../core/placeholder.js'
import {
  SessionRequests, proposalOf, overridesOf, elevationOf, OWNER_FIELDS,
  resolveTemplate, grantSpecsOf, templateCreds, templateSummary,
} from './session-requests.js'
import { sessionExpiryMs } from '../store/vault.js'
import { summarizeSession, accessReport } from '../store/activity.js'
import { exportBackup, inspectBackup, restoreBackup, bundleDigest } from '../store/backup.js'
import { runProbe } from '../connectors/probe.js'
import { checkDecisions } from '../pending.js'
import { Notifier } from './notify.js'
import { DEFAULT_RULES } from './tripwire.js'

// Read from package.json rather than written here twice. Two hardcoded copies
// of a version string are two chances to report one the code is not, and the
// CLI uses this to detect a daemon older than itself.
const VERSION = (() => {
  try {
    return JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf8')).version
  } catch {
    return '0.0.0-unknown'
  }
})()

const MAX_BODY = 16 * 1024 * 1024

// The fields of one grant in the single-credential form of a session body. A
// body with `grants` may not also carry any of these at the top level.
const GRANT_FIELDS = [
  'cred', 'hosts', 'methods', 'paths', 'deny_paths', 'budget', 'approval', 'uses', 'rate', 'max_concurrent',
  'quota', 'routes', 'payload', 'redirects', 'spend_tokens', 'spend_usd', 'grant_ttl_minutes',
]
const APPROVAL_MODES = ['each', 'on-write', 'first-use', 'auto']
const MAX_GRANTS = 16
const MAX_BATCH = 32
// What a narrowing (F15) may name: a grant spec without its credential, and
// without `uses`, which describes placeholders already handed out.
const NARROW_FIELDS = GRANT_FIELDS.filter((f) => f !== 'cred' && f !== 'uses')
// A preflight names one request (F20); bounds on the description of it.
const MAX_PREFLIGHT_HEADERS = 100
const PROBLEM_HEADERS = (err) => (err.retryAfter !== undefined ? { 'retry-after': String(err.retryAfter) } : {})

// Where `agent-vault ui` listens unless told otherwise, and so the one web UI
// origin the daemon trusts without being told. WebAuthn's relying party is
// `localhost`, which every port on the machine shares, so the ORIGIN is what
// tells the real page from a look-alike an agent serves on another port.
export const DEFAULT_UI_PORT = 7412
const UI_ORIGIN_SHAPE = /^http:\/\/localhost:(\d{1,5})$/

// Bounds on the pending-confirmation map. Both are reachable from the control
// socket, which an agent running as the human can reach.
const MAX_OPEN_CHALLENGES = 64
const MAX_OPERATION_BYTES = 8 * 1024

// Passphrase attempts. The free ones cover an ordinary typo; after that each
// further failure doubles the wait, which bounds both the guessing rate and
// the amount of event loop a caller can spend on scrypt.
const PASSPHRASE_FREE_ATTEMPTS = 5
// Capped deliberately low. The throttle counts per daemon, because a Unix
// socket gives nobody to count separately — so an agent's wrong guesses make
// the OWNER wait too. Only attempts that were actually checked extend the
// backoff (one refused during a backoff does not), so an agent cannot hold it
// open indefinitely; but the owner's worst case is still this number, and the
// difference between 30s and 60s is small for defence and doubles the wait for
// the person who owns the vault.
const PASSPHRASE_MAX_BACKOFF_MS = 30_000

// Daemons running in this process, for the process-level guard below.
const RUNNING = new Set()

/**
 * The last line of defence against a fault nothing else caught.
 *
 * #guard covers a request handler's own promise, and nothing else. An error
 * emitted on a stream with no listener — an upstream connection reset under a
 * compressed SSE response did it — is an uncaught EXCEPTION, thrown out of an
 * event emit, and with no handler in the process Node ends it: every agent's
 * session, every held approval, gone, because of one bad upstream.
 *
 * So while a daemon runs it keeps a handler. It does not swallow anything: the
 * fault goes to the audit log, where the owner looks for what happened, and to
 * stderr, where the service manager keeps it.
 */
function onProcessFault(kind) {
  return (err) => {
    const detail = String(err?.stack ?? err?.message ?? err).slice(0, 400)
    try { console.error(`agent-vault: ${kind}: ${detail}`) } catch { /* nothing better to do */ }
    for (const daemon of RUNNING) {
      // Never throw from here: an exception inside this handler is the one
      // thing that still ends the process.
      try {
        daemon.vault.audit?.write('daemon.uncaught', { fault: kind, detail: String(err?.message ?? err).slice(0, 200) })
      } catch { /* the stderr line above is the record */ }
    }
  }
}
const PROCESS_GUARDS = {
  uncaughtException: onProcessFault('uncaught exception'),
  unhandledRejection: onProcessFault('unhandled rejection'),
}

function guardProcess(daemon) {
  if (!RUNNING.size) for (const [event, fn] of Object.entries(PROCESS_GUARDS)) process.on(event, fn)
  RUNNING.add(daemon)
}

function unguardProcess(daemon) {
  if (!RUNNING.delete(daemon) || RUNNING.size) return
  for (const [event, fn] of Object.entries(PROCESS_GUARDS)) process.removeListener(event, fn)
}

export class Daemon {
  constructor(vault, { port = 7411, socketPath, host = '127.0.0.1', socketGroup = null, enrolledUid = null, uiPort = DEFAULT_UI_PORT, uiOrigins = [], notifyFetch = null } = {}) {
    this.vault = vault
    // The web UI origins whose assertions count, decided here. They used to be
    // whatever the caller minting a challenge named, so a page an agent served
    // on any localhost port could collect a signature the daemon accepted.
    this.uiPort = uiPort
    this.configuredUiOrigins = new Set()
    for (const o of uiOrigins) this.allowUiOrigin(o)
    this.port = port
    this.host = host
    this.socketPath = socketPath
    // When the daemon runs as its own service user, the control socket has to
    // be reachable by the human's account without that account being able to
    // read the vault. The group is the durable mechanism; the ACL exists
    // because group membership only takes effect at the next login.
    this.socketGroup = socketGroup
    this.enrolledUid = enrolledUid
    this.pipeline = new Pipeline(vault)
    this.mcp = new McpServer(vault, this.pipeline, () => this.currentMcpSession, this)
    this.currentMcpSession = null
    this.servers = []
    // A short window after a passphrase proof during which widening operations
    // are allowed, so the human is not prompted on every call. This is the CLI
    // analogue of the UI's presence gate: a secret the agent does not passively
    // hold, with an honest degraded-factor caveat (a swapped CLI could phish it).
    this.presenceGraceUntil = 0
    this.presenceGraceMs = 5 * 60_000
    // Outstanding op-gate challenges, each bound to one operation and good for
    // a single use within a minute. The daemon mints and verifies these itself
    // rather than trusting the UI process, which runs as the human's account
    // and is therefore reachable by an agent.
    this.opChallenges = new Map()
    // Sessions an agent has asked for and a human has not yet answered.
    this.sessionRequests = new SessionRequests(vault)
    // Consecutive failed passphrase attempts, and when to start accepting them
    // again. Every attempt costs an scrypt — deliberately, so guessing is
    // expensive — but scryptSync runs ON the event loop, so 188ms of "slow" is
    // 188ms during which the daemon answers nothing at all: not the gateway,
    // not a health check, not another agent's request. A loop of wrong
    // passphrases on the control socket was therefore a stall of the whole
    // vault as well as free online guessing, since nothing counted attempts.
    this.passphraseFailures = 0
    this.passphraseLockedUntil = 0
    // Refused listener peers already recorded, so a flood is one record.
    this.refusedPeers = new Map()
    // Telling the human something is waiting (F14): the stream `watch` reads,
    // and the owner's webhook. A signal only; nothing it sends can approve.
    this.notifier = new Notifier(vault, { fetchImpl: notifyFetch, snapshot: () => this.#waitingItems() })
    this.pipeline.onPending = (e) => this.notifier.pending(e)
    this.sessionRequests.onPending = (e) => this.notifier.pending(e)
    // Panic (F16, C1): the pipeline revokes and denies what it owns, then
    // asks this for the session requests, which only the daemon holds.
    this.pipeline.onPanic = async () => ({ session_requests_denied: this.#denyPendingSessionRequests('panic') })
  }

  /** Everything waiting for a human, as the notifier describes it. */
  #waitingItems() {
    return [
      ...this.pipeline.pendingApprovals().map((a) => ({ kind: 'request', id: a.id, headline: a.summary, created_at: a.created_at })),
      ...this.sessionRequests.pending().map((r) => ({ kind: 'session', id: r.id, headline: r.summary, created_at: r.created_at })),
    ]
  }

  /**
   * Deny every session request still waiting. Each is recorded before it
   * changes: a denial that cannot be audited must not happen. Returns how many.
   */
  #denyPendingSessionRequests(reason) {
    let n = 0
    for (const record of this.sessionRequests.pending()) {
      this.vault.audit.write('session_request.denied', { request_id: record.id, reason })
      record.state = 'denied'
      record.decided_at = new Date().toISOString()
      n++
    }
    if (n) this.sessionRequests.persist()
    return n
  }

  /**
   * Charge for a passphrase attempt before spending any time on it.
   * Returns nothing; throws when the caller must wait.
   */
  #throttlePassphrase() {
    const now = Date.now()
    if (now < this.passphraseLockedUntil) {
      const wait = Math.ceil((this.passphraseLockedUntil - now) / 1000)
      throw deny('AV_RATE_LIMITED', `too many failed passphrase attempts; try again in ${wait}s`, {
        rule: 'passphrase_throttle',
        retry_after_s: wait,
      })
    }
  }

  /** Record how an attempt went, and back off when they keep failing. */
  #recordPassphraseAttempt(ok) {
    if (ok) { this.passphraseFailures = 0; this.passphraseLockedUntil = 0; return }
    this.passphraseFailures++
    if (this.passphraseFailures < PASSPHRASE_FREE_ATTEMPTS) return
    const over = this.passphraseFailures - PASSPHRASE_FREE_ATTEMPTS
    const backoff = Math.min(1000 * 2 ** over, PASSPHRASE_MAX_BACKOFF_MS)
    this.passphraseLockedUntil = Date.now() + backoff
    this.vault.audit?.write('presence.throttled', {
      consecutive_failures: this.passphraseFailures,
      until: new Date(this.passphraseLockedUntil).toISOString(),
    })
  }


  /**
   * Make a session from a request body.
   *
   * Shared by the route a human calls and the approval of a proposal an agent
   * made, so an approved proposal cannot be created by some second, laxer
   * path. Every ceiling in here applies either way: approval supplies the
   * human, never permission.
   */
  /**
   * Settle one pending item, whatever kind it is.
   *
   * Only ever called after a gate. It exists so the bulk route and the single
   * routes converge on identical code: the moment they diverge, one of them
   * becomes the laxer path and that is the one an agent will find.
   */
  #settleOne(d) {
    if (d.kind === 'session') {
      const record = this.sessionRequests.get(d.id)
      if (!record) throw deny('AV_NOT_FOUND', `no session request ${d.id}`)
      if (record.state !== 'pending') {
        throw deny('AV_POLICY_DENIED', `already ${record.state}`, { rule: 'session_requests' })
      }
      const final = { ...record.proposal, ...overridesOf(d.overrides || {}) }
      return this.#settleSessionRequest(record, d.granted, final)
    }
    return this.#settleApproval(d.id, d.granted)
  }

  /**
   * A held request's decision, after the gate. The pipeline reads the verdict
   * however it likes, so only a real boolean reaches it.
   */
  #settleApproval(id, granted) {
    if (typeof granted !== 'boolean') {
      throw deny('AV_POLICY_DENIED', 'the verdict must be true or false', { rule: 'bulk_decision' })
    }
    return approvalView(this.pipeline.decideApproval(id, granted))
  }

  /** The decision itself, after the gate has let it through. */
  #settleSessionRequest(record, granted, final) {
    // Not truthiness, here as in checkDecisions: `granted: "false"` is a
    // string, and it approved.
    if (typeof granted !== 'boolean') {
      throw deny('AV_POLICY_DENIED', 'the verdict must be true or false', { rule: 'bulk_decision' })
    }
    if (!granted) {
      record.state = 'denied'
      record.decided_at = new Date().toISOString()
      this.sessionRequests.persist()
      this.vault.audit?.write('session_request.denied', { request_id: record.id })
      return SessionRequests.redact(record)
    }
    // A lifetime and "no lifetime" cannot both be the answer. The owner
    // added `infinite`; the agent asked for minutes; nothing picks for them.
    if (final.infinite === true && final.ttl_minutes != null) {
      throw deny('AV_POLICY_DENIED', 'an infinite session has no lifetime to set, and this request names one', { rule: 'ttl' })
    }
    // Created through the same helper the human's own route uses, so an
    // approved proposal cannot reach a second, laxer path. A ttl of 0 is
    // passed on and refused there, rather than read as "the default".
    //
    // A request made from a template (F17) carries the template's fields as
    // they were when the agent asked: that snapshot is what the human was
    // shown, so it is what gets created. The template is never read again
    // here, and an edit made since cannot reach this session.
    const created = this.#makeSession(this.#planSession({
      ...requestSpec(final),
      label: `requested by an agent (${record.id})`,
    }), { template: templateOf(record.proposal) })
    record.state = 'approved'
    record.decided_at = new Date().toISOString()
    record.granted_proposal = final
    record.result = created
    this.sessionRequests.persist()
    this.vault.audit?.write('session_request.approved', {
      request_id: record.id,
      session_id: created.session_id,
      granted: final,
      edited: JSON.stringify(final) !== JSON.stringify(record.proposal),
    })
    return { ...SessionRequests.redact(record), granted: final }
  }

  /**
   * Record an agent's request for a session (the route and MCP
   * vault_request_session both come here, so neither can be the laxer one).
   *
   * Asking creates nothing. It is refused, not trimmed, when it names an
   * owner field, when its credential is quarantined, or when it could never
   * be created as asked, so the human is never shown something that would
   * fail and the agent never believes it asked for something it did not.
   *
   * With `template` (F17) the daemon resolves the template now, with the
   * agent's narrowing on top, and the proposal is that snapshot: the human
   * approves what the agent was shown, whatever happens to the template.
   */
  proposeSessionRequest(input) {
    if (!isObject(input)) throw deny('AV_POLICY_DENIED', 'a session request is an object', { rule: 'session_shape' })
    const owned = OWNER_FIELDS.filter((f) => Object.hasOwn(input, f))
    if (owned.length) {
      throw deny('AV_POLICY_DENIED', `a session request cannot carry ${owned.join(' or ')}`, {
        rule: 'owner_only_field',
        hint: 'Only the owner can choose the approval mode or an unlimited lifetime. Ask without it and say why in reason.',
      })
    }
    let proposal
    let fromTemplate = false
    if (input.template !== undefined) {
      proposal = this.#templateProposal(input)
      fromTemplate = true
    } else {
      proposal = proposalOf(input)
    }
    if (!proposal.cred) throw deny('AV_NOT_FOUND', 'a session request must name a credential')
    const cred = this.vault.findCredential(proposal.cred)
    if (!cred) throw deny('AV_NOT_FOUND', `no credential ${proposal.cred}`)
    // Nobody is asked to approve access to a credential a human has stopped
    // (C12 note). Releasing it is the human's decision, not an agent's.
    if (cred.quarantine) throw quarantined(cred)
    // Built exactly as an approval would build it, with nothing made: a
    // proposal that could never be created is refused while the agent is
    // still there to hear why.
    this.#planSession(requestSpec(proposal))
    try {
      return this.sessionRequests.propose({ proposal, reason: input.reason, fromTemplate })
    } catch (e) {
      if (e.code === 'AV_TOO_MANY_REQUESTS') throw deny('AV_POLICY_DENIED', e.message, { rule: 'session_requests' })
      throw e
    }
  }

  /**
   * A proposal from a template (F17): one credential only, so the human
   * reviews one grant, resolved now. The template's own owner fields come
   * with it (the owner wrote them); the agent's narrowing only narrows.
   */
  #templateProposal(input) {
    if (typeof input.template !== 'string' || !input.template) {
      throw deny('AV_POLICY_DENIED', 'template is the name of a saved template', { rule: 'session_shape' })
    }
    const template = this.vault.getTemplate(input.template)
    if (!template) throw deny('AV_NOT_FOUND', `no template ${input.template}`)
    const creds = templateCreds(template.spec)
    if (creds.length !== 1 || grantSpecsOf(template.spec).length !== 1) {
      throw deny('AV_POLICY_DENIED', `template ${template.name} covers ${creds.length} credentials; a request names exactly one`, {
        rule: 'template_multi_cred',
        hint: 'Ask with a template for one credential, or name the credential and its limits yourself.',
      })
    }
    const { cred, ttl_minutes: ttlMinutes, ...narrowing } = proposalOf(input)
    if (cred !== undefined && cred !== creds[0]) {
      throw deny('AV_POLICY_DENIED', `template ${template.name} is for ${creds[0]}, not ${cred}`, { rule: 'session_shape' })
    }
    const overrides = { ...narrowing }
    if (ttlMinutes !== undefined) {
      if (typeof ttlMinutes !== 'number' || !Number.isFinite(ttlMinutes) || !(ttlMinutes > 0)) {
        throw deny('AV_POLICY_DENIED', 'ttl_minutes must be a positive number of minutes', { rule: 'ttl' })
      }
      overrides.ttl_hours = ttlMinutes / 60
    }
    const spec = resolveTemplate(template, overrides, { budgetDefault: (g) => this.#defaultBudget(g) })
    const [grant] = grantSpecsOf(spec)
    const proposal = Object.fromEntries(GRANT_FIELDS.filter((k) => grant[k] !== undefined).map((k) => [k, grant[k]]))
    if (spec.infinite === true) proposal.infinite = true
    else if (spec.ttl_hours !== undefined) proposal.ttl_minutes = spec.ttl_hours * 60
    proposal.template = template.name
    proposal.template_hash = template.hash
    proposal.template_version = template.version
    return proposal
  }

  /**
   * Hand an approved request's session over, once: whoever gets it here is
   * the only one who ever will.
   */
  #handOver(record, via) {
    const result = record.result
    record.result = null
    record.state = 'collected'
    this.sessionRequests.persist()
    this.vault.audit?.write('session_request.collected', { request_id: record.id, via })
    return result
  }

  /**
   * Read and check a session-create body without changing anything.
   *
   * Every grant is resolved and validated here, before a session exists, so a
   * refusal leaves no half-made session behind. The gate is chosen from
   * `elevated`, which is computed here once, over the same body.
   */
  #planSession(input, { dryRun = false, resolved = false } = {}) {
    const shape = (detail) => deny('AV_POLICY_DENIED', detail, {
      rule: 'session_shape',
      hint: 'A session is either one credential (cred and its limits at the top level) or grants: [{cred, …}, …], one entry per credential.',
    })
    if (!input || typeof input !== 'object' || Array.isArray(input)) throw shape('send one of cred, grants or template')
    const has = (k) => input[k] !== undefined
    if (has('template') && (has('cred') || has('grants'))) throw shape('send one of cred, grants or template')
    if (has('template')) {
      // A template's own spec never names another template; the store
      // refuses one, and a hand-edited vault does not get a loop.
      if (resolved) throw shape('a template cannot name another template')
      const { template, spec } = this.#resolveTemplateInput(input)
      return { ...this.#planSession(spec, { dryRun, resolved: true }), template: { name: template.name, version: template.version } }
    }
    if (has('grants') && GRANT_FIELDS.some(has)) throw shape('send one of cred, grants or template')
    let specs
    if (has('grants')) {
      if (!Array.isArray(input.grants) || !input.grants.length || input.grants.length > MAX_GRANTS) {
        throw shape(`grants is a list of 1 to ${MAX_GRANTS} grant specs`)
      }
      specs = input.grants
    } else {
      specs = [Object.fromEntries(GRANT_FIELDS.filter(has).map((k) => [k, input[k]]))]
    }
    // The gateway picks a grant by credential, so two grants for one
    // credential would leave it guessing which one a request spends.
    const seen = new Set()
    for (const spec of specs) {
      if (!spec || typeof spec !== 'object' || Array.isArray(spec)) throw shape('each grant spec must be an object')
      if (seen.has(spec.cred)) throw shape(`credential ${spec.cred} appears twice`)
      seen.add(spec.cred)
    }

    const invalid = (field, detail) => deny('AV_POLICY_DENIED', detail, { rule: 'policy_invalid', field })
    if (input.label != null && (typeof input.label !== 'string' || input.label.length > 80)) {
      throw invalid('label', 'label is a string of at most 80 characters')
    }
    // A lifetime is checked, never coerced. NaN became a RangeError, 0 became
    // the default, and a negative number made a session born expired.
    const ttl = (detail) => deny('AV_POLICY_DENIED', detail, { rule: 'ttl' })
    if (input.infinite != null && typeof input.infinite !== 'boolean') throw ttl('infinite is true or false')
    const infinite = input.infinite === true
    if (input.ttl_hours != null) {
      if (infinite) throw ttl('an infinite session has no lifetime to set')
      if (typeof input.ttl_hours !== 'number' || !Number.isFinite(input.ttl_hours) || !(input.ttl_hours > 0)) {
        throw ttl('ttl_hours must be a positive number of hours')
      }
    }
    if (input.remote != null && typeof input.remote !== 'boolean') {
      throw invalid('remote', 'remote is true or false')
    }
    const remote = input.remote === true
    // A capability that never ends must not be reachable from the network.
    if (infinite && remote) {
      throw deny('AV_REMOTE_FORBIDDEN', 'a session without expiry cannot be remote', { rule: 'infinite_remote' })
    }

    const strings = (v) => Array.isArray(v) && v.every((x) => typeof x === 'string' && x)
    const grants = specs.map((spec) => {
      const cred = this.vault.findCredential(spec.cred)
      if (!cred) throw deny('AV_NOT_FOUND', `no credential ${spec.cred}`)
      // The store refuses the grant too, but only after the gate has asked for
      // a passphrase and a session exists to be torn down again. A template
      // being saved is not a session, so a dry run does not ask.
      if (cred.quarantine && !dryRun) throw quarantined(cred)
      // Never a default for a mode nobody chose: an unknown one used to mean
      // auto, because needsApproval fell through to false.
      if (spec.approval != null && !APPROVAL_MODES.includes(spec.approval)) {
        throw deny('AV_POLICY_DENIED', 'approval is not one of the four modes', {
          rule: 'approval', hint: 'approval is one of: each, on-write, first-use, auto',
        })
      }
      // Read the same way elevationOf reads them: absent or null is the
      // default, and anything else must be a list of names.
      if (spec.methods != null && !strings(spec.methods)) throw invalid('methods', 'methods must be a list of method names')
      if (spec.paths != null && !strings(spec.paths)) throw invalid('paths', 'paths must be a list of path globs')
      // One reader for a budget (C4): a whole number, or the canonical
      // decimal string of one.
      const budget = spec.budget == null ? null : policyMod.budgetInteger(spec.budget)
      if (spec.budget != null && budget === null) {
        throw invalid('budget', 'budget must be a whole number of requests, 0 or more')
      }
      // A budget of 0 permits nothing at all. It used to make a session, fail
      // to issue its placeholder and tear the session down again, after the
      // human had been asked for a passphrase (C17).
      if (budget === 0) {
        throw deny('AV_POLICY_DENIED', 'a budget of 0 allows no request at all', {
          rule: 'budget', hint: 'Give a budget of at least 1, or leave it out for the connector default.',
        })
      }
      if (spec.uses != null && !(Number.isInteger(spec.uses) && spec.uses >= 1)) {
        throw invalid('uses', 'uses must be a whole number, 1 or more')
      }
      // F18: a grant may end before its session. Minutes, a whole number.
      if (spec.grant_ttl_minutes != null && !(Number.isInteger(spec.grant_ttl_minutes) && spec.grant_ttl_minutes >= 1)) {
        throw deny('AV_POLICY_DENIED', 'grant_ttl_minutes must be a whole number of minutes, 1 or more', { rule: 'grant_ttl' })
      }
      const profile = getProfile(cred.connector_kind)
      // A grant can only reach the hosts the credential itself declares.
      // Without this an agent minting its own session could aim the
      // credential at a host it controls (the exfiltration path found in
      // the pen test).
      const ceiling = policyMod.credentialHostCeiling(cred, profile.hosts)
      // The one converter from a grant spec to a policy layer (0.6). Every
      // limit a spec can carry (rate, quota, routes, payload rules, spend,
      // redirects) becomes the layer field the gateway reads, and anything
      // it cannot read is refused here rather than stored.
      const policy = policyMod.grantPolicyFromInput(spec, { profile, ceiling })
      return {
        cred, profile, spec, policy,
        ttlMs: spec.grant_ttl_minutes != null ? spec.grant_ttl_minutes * 60_000 : null,
        lint: policyMod.lint(policy, { kind: cred.connector_kind }),
      }
    })
    return {
      label: input.label, ttlMs: input.ttl_hours != null ? input.ttl_hours * 3600_000 : null,
      infinite, remote, grants, elevated: elevationOf(input), template: null,
    }
  }

  /**
   * A session-create body that names a template (F17), as the spec it stands
   * for. The hash the human was shown must be the template's hash now: an
   * edit between looking and creating is refused, never applied. Every other
   * top-level field is an override, and overrides only narrow.
   */
  #resolveTemplateInput(input) {
    if (typeof input.template !== 'string' || !input.template) {
      throw deny('AV_POLICY_DENIED', 'template is the name of a saved template', { rule: 'session_shape' })
    }
    const template = this.vault.getTemplate(input.template)
    if (!template) throw deny('AV_NOT_FOUND', `no template ${input.template}`)
    if (typeof input.template_hash !== 'string' || input.template_hash !== template.hash) {
      throw deny('AV_POLICY_DENIED', 'the template changed after you looked at it; review it again', {
        rule: 'template_changed',
        hint: 'Fetch the template again, read what it now grants, and send its current template_hash.',
      })
    }
    const { template: _name, template_hash: _hash, presence: _proof, ...overrides } = input
    return { template, spec: resolveTemplate(template, overrides, { budgetDefault: (g) => this.#defaultBudget(g) }) }
  }

  /** The budget a grant gets when its spec names none: the profile's default. */
  #defaultBudget(grantSpec) {
    const cred = this.vault.findCredential(grantSpec?.cred)
    return cred ? getProfile(cred.connector_kind).defaultBudget.limit : null
  }

  /**
   * Create what a plan describes. Only ever called after its gate.
   * `template` names the template a session request was made from, when its
   * snapshot (not the template itself) is what the plan was built from.
   */
  #makeSession(plan, { template = null } = {}) {
    const from = plan.template ?? template
    const { session, token } = this.vault.createSession({
      label: plan.label, ttlMs: plan.ttlMs, infinite: plan.infinite, elevated: plan.elevated,
      policy: {}, remote: plan.remote,
      template: from?.name ?? null, templateVersion: from?.version ?? null,
    })
    try {
      // A store that cannot keep a session open forever must not hand back
      // an ordinary one to someone who asked for "never expires".
      if (plan.infinite && session.infinite !== true) {
        throw deny('AV_POLICY_DENIED', 'this vault cannot create a session without expiry', { rule: 'ttl' })
      }
      const grants = plan.grants.map(({ cred, profile, spec, policy, ttlMs, lint }) => {
        const field = cred.fields[0]
        const grant = this.vault.createGrant({
          sessionId: session.id, credentialId: cred.id, fields: [field.name], policy, ttlMs,
        })
        // The grant's placeholder_policy is a ceiling, not a default. It sat
        // on the right of a `??`, so an agent asking for a million uses got
        // a million even where the human had configured one-time use.
        const maxUses = grant.policy?.placeholder_policy?.max_uses
        const asked = spec.uses ?? null
        const uses = maxUses == null ? asked : Math.min(asked ?? maxUses, maxUses)
        const { placeholder } = this.vault.issuePlaceholder({ grantId: grant.id, field: field.name, uses })
        return {
          cred: cred.slug, grant_id: grant.id, placeholder,
          usage: field.sites.map((s) => sitesMod.describeSite(sitesMod.parseSite(s), placeholder)),
          base_url: `http://127.0.0.1:${this.gatewayPort}/p/${cred.slug}`,
          // The profile's own read-only probe, so a caller can print an
          // example request that works instead of a made-up path.
          probe_path: profile.probe?.path || null,
          env: profile.env ? { base: profile.env.base, key: profile.env.key } : null,
          expires_at: grant.expires_at ?? null,
          lint,
        }
      })
      const [first] = grants
      return {
        session_id: session.id, token, label: session.label,
        expires_at: session.expires_at ?? null, infinite: session.infinite === true,
        grants,
        // grants[0] again, so every client written for one grant keeps working.
        grant_id: first.grant_id, placeholder: first.placeholder, usage: first.usage,
        base_url: first.base_url, probe_path: first.probe_path, lint: first.lint,
      }
    } catch (e) {
      // Nothing half-made survives a failure: the session goes, and every
      // grant and placeholder with it.
      try { this.vault.revokeSession(session.id, 'incomplete') } catch { /* the original error is the one to report */ }
      throw e
    }
  }

  /** Gate a session-create body at the level its elevation needs. Exactly one gate runs. */
  #gateSession(op, operation, elevated, presence) {
    if (elevated.length) this.#requireFreshPresence(op, operation, presence)
    else this.#requireHumanForWidening(op, operation, presence)
  }

  /**
   * Guard a capability-widening control operation. Two proofs are accepted: a
   * live passphrase window (the CLI's factor), or a WebAuthn assertion over
   * this exact operation (the UI's, and the stronger of the two). With neither
   * factor enrolled the call is open and audited as such, which is the
   * documented state of a vault with no human secret.
   */
  #requireHumanForWidening(op, operation = null, presence = null) {
    if (Date.now() < this.presenceGraceUntil) {
      // The window is daemon-wide: it admits whoever calls while it is open,
      // not only the command the human typed the passphrase for. So every
      // operation it admits is named in the log, where it used to show only
      // that a window had opened.
      this.vault.audit?.write('presence.window_used', { op })
      return
    }
    if (presence && this.#verifyOpAssertion(operation, presence)) {
      this.vault.audit?.write('presence.verified', { op, factor: 'webauthn-platform' })
      return
    }
    // An enrolled authenticator is a human secret just as much as a passphrase
    // is. Treating only the passphrase as one left anybody who set up Touch ID
    // confirmation in the UI, and nothing else, with a wide open control
    // socket — the opposite of what they thought they had configured.
    const factors = []
    if (this.vault.hasPassphrase) factors.push('passphrase')
    if (this.vault.db?.kv?.webauthn) factors.push('authenticator')
    if (!factors.length) {
      this.vault.audit?.write('control.widening_ungated', { op })
      return
    }
    // Name the factor that exists, so the caller is not told to confirm a
    // passphrase it has no way to satisfy.
    const viaPassphrase = factors.includes('passphrase')
    throw deny('AV_PRESENCE_REQUIRED', `${op} needs a human: confirm your ${factors.join(' or ')}`, {
      rule: 'human_presence',
      factors,
      hint: viaPassphrase
        ? 'Run the command again; agent-vault will ask for your passphrase.'
        : 'Confirm it in the web UI with your authenticator: agent-vault ui',
    })
  }

  /**
   * The `fresh` presence level: proof that a human is here for THIS operation.
   *
   * Used by the operations that change who can prove presence at all —
   * enrolling or replacing the presence authenticator, wrapping the master key
   * to a Touch ID secret or removing that wrap, trusting another UI origin —
   * and by anything else that must not ride on someone else's window.
   *
   * The shared passphrase window is never consulted. It admits every caller on
   * the socket while it is open, so five minutes of a human's presence for an
   * ordinary command let an agent wrap the master key to a PRF secret of its
   * own, or install its own authenticator, and keep that after the window
   * closed. The proof travels with the request: an assertion from the enrolled
   * authenticator over this exact operation, or `presence.passphrase`, checked
   * and throttled like every other attempt. A successful proof opens no window.
   * `operationFor` drops `presence`, so the passphrase is never bound into a
   * signed operation.
   */
  #requireFreshPresence(op, operation, presence) {
    if (presence?.challengeId && this.#verifyOpAssertion(operation, presence)) {
      this.vault.audit?.write('presence.verified', { op, factor: 'webauthn-platform', fresh: true })
      return
    }
    if (typeof presence?.passphrase === 'string' && this.vault.hasPassphrase) {
      this.#throttlePassphrase()
      const ok = this.vault.verifyPassphrase(presence.passphrase)
      this.#recordPassphraseAttempt(ok)
      if (!ok) throw deny('AV_PRESENCE_DENIED', 'passphrase did not verify', { rule: 'fresh_presence' })
      this.vault.audit?.write('presence.verified', { op, factor: 'passphrase', fresh: true })
      return
    }
    const factors = []
    if (this.vault.hasPassphrase) factors.push('passphrase')
    if (this.vault.db?.kv?.webauthn) factors.push('authenticator')
    // Unlike the widening gate, no factor is not a pass: there is nothing a
    // human could have proved, so nothing that needs a fresh proof can happen.
    if (!factors.length) {
      throw deny('AV_PRESENCE_REQUIRED', `${op} needs a human factor, and none is enrolled`, {
        rule: 'factor_required',
        factors: [],
        hint: 'This change needs a human factor and none is enrolled. Set one first: agent-vault passphrase set',
      })
    }
    throw deny('AV_PRESENCE_REQUIRED', `${op} needs your ${factors.join(' or ')} for this one operation`, {
      rule: 'fresh_presence',
      factors,
      hint: factors.includes('passphrase')
        ? 'This change needs your passphrase for this one operation, even inside a confirmation window. Run the command again; agent-vault will ask.'
        : 'Confirm it in the web UI with your authenticator: agent-vault ui',
    })
  }

  /** The web UI origins whose assertions this daemon accepts. */
  uiOrigins() {
    return [...new Set([
      `http://localhost:${this.uiPort}`,
      ...this.configuredUiOrigins,
      ...(this.vault.db?.kv?.ui_origins || []),
    ])]
  }

  /**
   * Trust another web UI origin, in process. This is configuration by whoever
   * runs the daemon; nothing on the socket reaches it. Over the socket the
   * same change is POST /v1/ui/origins, which needs the owner's proof.
   */
  allowUiOrigin(origin) {
    const o = String(origin || '')
    if (!uiOriginOk(o)) throw new Error(`not a web UI origin: ${JSON.stringify(origin)} (http://localhost:<port>)`)
    this.configuredUiOrigins.add(o)
  }

  /**
   * Verify an assertion against the challenge this daemon minted, and against
   * the operation actually being performed. The comparison happens here, not
   * in the UI, so a hostile page cannot show one operation and submit another.
   */
  #verifyOpAssertion(operation, presence) {
    const enrolled = this.vault.db?.kv?.webauthn
    if (!enrolled || !presence?.challengeId) return false
    const pending = this.opChallenges.get(presence.challengeId)
    this.opChallenges.delete(presence.challengeId) // single use, verified or not
    if (!pending || pending.expires < Date.now()) return false
    if (webauthn.canonicalOperation(pending.operation) !== webauthn.canonicalOperation(operation)) {
      this.vault.audit?.write('presence.denied', { reason: 'operation_mismatch' })
      return false
    }
    try {
      const result = webauthn.verifyAssertion({
        credentialId: presence.credentialId,
        authenticatorData: presence.authenticatorData,
        clientDataJSON: presence.clientDataJSON,
        signature: presence.signature,
        expectedChallenge: pending.challenge,
        // The relying party id pins the domain and nothing more: every port
        // on localhost shares it. Which ports are the real UI is the daemon's
        // list, never the one the challenge's minter supplied.
        expectedOrigins: this.uiOrigins(),
        rpId: 'localhost',
        enrolled,
      })
      if (result.signCount > 0) {
        enrolled.signCount = result.signCount
        this.vault.save()
      }
      return true
    } catch (e) {
      this.vault.audit?.write('presence.denied', { reason: e.message })
      return false
    }
  }

  /**
   * What a gated control call will actually do, in the same shape the UI shows
   * the human and signs. Derived from the request the daemon received.
   */
  #wideningOperation(route, url, input) {
    // Built from the whole request, not a field list. Whatever is not bound
    // here is a field an agent can change under someone else's signature.
    const of = (op, params) => webauthn.operationFor(op, params)
    switch (route) {
      case 'POST /v1/credentials': return of('cred.add', input)
      case 'DELETE /v1/credentials': return of('cred.remove', { slug: url.searchParams.get('slug') })
      case 'POST /v1/sessions': return of('session.create', input)
      case 'POST /v1/placeholders': return of('placeholder.issue', input)
      case 'POST /v1/placeholders/batch': return of('placeholder.issue_many', input)
      // The verdict picks the op name, the same way the UI's builder does, so
      // the human is shown which answer they are giving.
      case 'POST /v1/approvals': return of(input?.granted === false ? 'approval.deny' : 'approval.approve', input)
      // Bound to the list exactly as it was sent. Normalising here would mean
      // the human signed one thing and the daemon executed another.
      case 'POST /v1/pending/decide-many': return of('pending.decide_many', { decisions: input?.decisions })
      case 'POST /v1/listeners': return of('listener.add', input)
      // One route, two opposite actions. The op NAME is what the UI shows the
      // human, and asking someone to confirm "touchid.enroll" for a removal is
      // asking them to approve something they were not shown. `action` is
      // carried by that name rather than repeated as a field: the handler
      // reads nothing from it but "remove or not", which the name already
      // states, and repeating it made the daemon's operation differ from the
      // one the page signs, so no enrol or removal from the UI ever verified.
      case 'POST /v1/factors/webauthn': {
        const { action, ...rest } = input || {}
        return of(action === 'remove' ? 'touchid.remove' : 'touchid.enroll', action === 'remove' ? {} : rest)
      }
      // A fresh passphrase travels inside `presence`, which operationFor
      // drops, so it is never bound into the signed operation.
      case 'POST /v1/presence': return of('presence.enroll', input)
      case 'POST /v1/ui/origins': return of('ui.origin_add', input)
      // Wave 3 (A.2). Each name is the one the web UI signs. A DELETE binds
      // its query parameters, read the way every DELETE here reads them.
      case 'POST /v1/credentials/rotate': return of('cred.rotate', input)
      case 'POST /v1/credentials/scrub': return of('cred.scrub_add', input)
      case 'DELETE /v1/credentials/scrub':
        return of('cred.scrub_remove', { slug: url.searchParams.get('slug'), id: url.searchParams.get('id') })
      case 'POST /v1/credentials/expiry': return of('cred.expiry_set', input)
      case 'POST /v1/credentials/pins': return of('cred.pins_set', input)
      case 'DELETE /v1/credentials/pins':
        return of('cred.pins_remove', {
          slug: url.searchParams.get('slug'), host: url.searchParams.get('host'), spki: url.searchParams.get('spki'),
        })
      case 'POST /v1/credentials/release': return of('cred.release', input)
      case 'POST /v1/tripwires': return of('tripwires.set', input)
      case 'POST /v1/templates': return of('template.save', input)
      case 'POST /v1/backup/export': return of('backup.export', input)
      case 'POST /v1/backup/restore': return of('backup.restore', input)
      case 'POST /v1/notify': return of('notify.set', input)
      default: return null
    }
  }


  async start() {
    // Every handler below is async and its promise is not awaited by Node, so
    // any rejection that escapes is an UNHANDLED rejection — which ends the
    // process. A daemon holding everyone's credentials must not be stoppable
    // by one malformed request, whatever the bug behind it turns out to be.
    const gateway = createServer((req, res) => this.#guard(req, res, () => this.#onGateway(req, res)))
    await new Promise((resolve) => gateway.listen(this.port, this.host, resolve))
    this.servers.push(gateway)
    this.gatewayPort = gateway.address().port

    if (this.socketPath) {
      // sun_path is 104 bytes on macOS and 108 on Linux, and the kernel
      // truncates rather than complaining. Two vaults under long paths then
      // collapse onto the same socket and the symptom is EADDRINUSE on a file
      // that visibly does not exist, which explains nothing.
      const limit = process.platform === 'darwin' ? 104 : 108
      if (Buffer.byteLength(this.socketPath) >= limit) {
        throw new Error(
          `the control socket path is ${Buffer.byteLength(this.socketPath)} bytes and the limit is ${limit}: ${this.socketPath}\n`
          + 'Use a shorter AGENT_VAULT_DIR.',
        )
      }
      if (existsSync(this.socketPath)) unlinkSync(this.socketPath)
      const control = createServer((req, res) => this.#guard(req, res, () => this.#onControl(req, res)))
      // listen() creates the socket with the process umask, and #secureSocket
      // only tightens it afterwards — so between those two calls the
      // capability-widening surface of this daemon was connectable by any
      // local account. Narrow the umask across the bind so it is never created
      // permissively in the first place; #secureSocket then relaxes it to the
      // group that is meant to reach it.
      const previousUmask = process.umask(0o077)
      try {
        await new Promise((resolve) => control.listen(this.socketPath, resolve))
      } finally {
        process.umask(previousUmask)
      }
      this.#secureSocket()
      this.servers.push(control)
    }

    // Configured listeners. Until now these were recorded and validated but
    // never bound, which also meant `req.listener` was always undefined and
    // the remote rules in the pipeline could not fire.
    this.listeners = []
    for (const entry of this.vault.listListeners?.() || []) {
      try {
        this.listeners.push(await this.#bindListener(entry))
      } catch (e) {
        // A listener that cannot bind must be loud. Silently running with one
        // fewer surface than configured is how a machine ends up unreachable
        // for reasons nothing explains.
        this.vault.audit?.write('listen.bind_failed', { listener_id: entry.id, reason: e.message })
        console.error(`agent-vault: listener ${entry.id} (${entry.address}) did not bind: ${e.message}`)
      }
    }

    guardProcess(this)
    this.vault.audit?.write('daemon.start', {
      port: this.gatewayPort, socket: this.socketPath, listeners: this.listeners.map((l) => l.id),
    })
    return this
  }

  /**
   * Bind one configured listener.
   *
   * Two things make this different from the built-in loopback gateway: it may
   * carry TLS, and it only answers for the surfaces the entry declares. A
   * listener for `mcp` does not become a credential proxy because someone
   * guessed a /p/ URL.
   */
  /** Bind one listener directly. Exposed so tests can assert on the refusals. */
  bindListener(entry) { return this.#bindListener(entry) }

  async #bindListener(entry) {
    const { host, port } = parseAddress(entry.address)
    const surfaces = new Set(entry.surfaces || [])
    const remote = !isLoopbackHost(host)
    // Parsed before anything binds, so a list that cannot be read stops the
    // listener rather than leaving it open to everyone.
    const allow = parseAllowCidr(entry.allow_cidr)

    // Set when the listener is removed. A connection accepted before that can
    // still deliver a request after it — a TLS peer that held its handshake
    // open across `listen rm` was served by the removed listener — so the
    // handler itself refuses once revoked, whatever the socket's history.
    let revoked = false
    const handler = (req, res) => revoked ? req.socket.destroy() : this.#guard(req, res, async () => {
      // What the pipeline uses to decide whether this request came from the
      // machine or from the network.
      req.listener = {
        id: entry.id,
        kind: entry.tls ? 'tls' : 'tcp',
        remote,
        advertise: entry.advertise || [],
      }
      const path = new URL(req.url, 'http://placeholder').pathname
      const wanted = path === '/mcp' ? 'mcp' : 'gateway'
      if (!surfaces.has(wanted)) {
        res.writeHead(404, { 'content-type': 'application/json' })
        return res.end(JSON.stringify({
          code: 'AV_NOT_FOUND',
          detail: `listener ${entry.id} does not serve the ${wanted} surface`,
          hint: `it serves: ${[...surfaces].join(', ') || 'nothing'}`,
        }))
      }
      return this.#onGateway(req, res)
    })

    let server
    if (entry.tls) {
      const { createServer: createTlsServer } = await import('node:https')
      // `managed` means the daemon's own self-signed certificate, generated
      // and kept inside the vault directory. Anything else is a cert the human
      // supplied by path (mkcert, an internal CA, a real one).
      const material = entry.tls.managed
        ? loadMaterial(ensureCertificate(this.vault.dir))
        : loadMaterial(entry.tls)
      server = createTlsServer(material, handler)
    } else {
      if (remote) {
        // Plaintext off the loopback interface would put session tokens and
        // substituted credentials on the wire.
        throw new Error('a listener on a network address must configure TLS')
      }
      server = createServer(handler)
    }

    // Every raw connection, so revoking can drop them all. closeAllConnections()
    // only knows the sockets HTTP has seen; a TLS peer still mid-handshake is
    // invisible to it, finished the handshake after removal, and kept the
    // removal itself waiting for as long as it liked.
    const sockets = new Set()
    server.on('connection', (socket) => {
      sockets.add(socket)
      socket.once('close', () => sockets.delete(socket))
    })
    const revoke = () => {
      revoked = true
      for (const socket of sockets) socket.destroy()
      sockets.clear()
    }

    // `--allow-cidr` was stored and never read, so a listener its operator
    // believed was limited to the tailnet answered anyone who could reach the
    // port. Checked on the raw connection, before TLS or HTTP see a byte, so a
    // peer outside the list gets nothing to talk to at all.
    if (allow) {
      server.on('connection', (socket) => {
        if (peerAllowed(allow, socket.remoteAddress)) return
        this.#peerRefused(entry.id, socket.remoteAddress)
        socket.destroy()
      })
    }

    await new Promise((resolve, reject) => {
      server.once('error', reject)
      server.listen(port, host, () => { server.removeListener('error', reject); resolve() })
    })
    this.servers.push(server)
    const bound = server.address()
    this.vault.audit?.write('listen.bound', {
      listener_id: entry.id, address: `${host}:${bound.port}`, tls: !!entry.tls, surfaces: [...surfaces],
    })
    return { id: entry.id, host, port: bound.port, tls: !!entry.tls, surfaces: [...surfaces], server, revoke }
  }

  /**
   * Record a refused peer. Once per listener and address per minute: anyone
   * who can reach the port can connect as often as they like, and a record
   * per attempt would let them bury the audit log in refusals.
   */
  #peerRefused(listenerId, address) {
    const key = `${listenerId}|${address}`
    const now = Date.now()
    if (now - (this.refusedPeers.get(key) || 0) < 60_000) return
    if (this.refusedPeers.size >= 256) this.refusedPeers.clear()
    this.refusedPeers.set(key, now)
    this.vault.audit?.write('listen.peer_refused', { listener_id: listenerId, peer: String(address || 'unknown') })
  }

  /**
   * Stop serving a listener that has been removed. Deleting the record alone
   * left the bound server answering the network until the next restart, while
   * `listen list` and the CLI both said it was gone.
   */
  async #unbindListener(lid) {
    const bound = (this.listeners || []).find((l) => l.id === lid)
    if (!bound) return false
    this.listeners = this.listeners.filter((l) => l !== bound)
    this.servers = this.servers.filter((sv) => sv !== bound.server)
    const closed = new Promise((resolve) => bound.server.close(resolve))
    bound.revoke()
    await closed
    this.vault.audit?.write('listen.unbound', { listener_id: lid })
    return true
  }

  /**
   * Lock the control socket down. Without a client group this is a single-user
   * dev install and 0600 is right. With one, the socket is 0660 owned by the
   * group so an enrolled account can connect and nobody else can.
   */
  #secureSocket() {
    if (!this.socketGroup) {
      chmodSync(this.socketPath, 0o600)
      return
    }
    let wantGid = null
    try {
      wantGid = Number(execFileSync('getent', ['group', this.socketGroup], { encoding: 'utf8' }).split(':')[2])
    } catch {
      try {
        const out = execFileSync('dscl', ['.', '-read', `/Groups/${this.socketGroup}`, 'PrimaryGroupID'], { encoding: 'utf8' })
        wantGid = Number(out.split(':').pop().trim())
      } catch { wantGid = null }
    }

    if (!Number.isFinite(wantGid)) {
      // An unresolvable group must never silently widen the socket, and it has
      // to be loud: the symptom otherwise is a CLI that cannot connect for
      // reasons nothing explains.
      chmodSync(this.socketPath, 0o600)
      this.vault.audit?.write('daemon.socket_group_failed', { group: this.socketGroup, reason: 'group not found' })
      console.error(`agent-vault: group ${this.socketGroup} does not exist; the socket is 0600 and only this user can connect`)
      return
    }

    // The run directory is setgid, so the socket usually inherits the right
    // group already and no chown is needed. Where it does not, chown requires
    // the daemon to be a member of that group; the installer arranges that.
    const current = statSync(this.socketPath).gid
    if (current !== wantGid) {
      try {
        chownSync(this.socketPath, process.getuid(), wantGid)
      } catch (e) {
        chmodSync(this.socketPath, 0o600)
        this.vault.audit?.write('daemon.socket_group_failed', { group: this.socketGroup, reason: e.code })
        console.error(
          `agent-vault: cannot set the socket group to ${this.socketGroup} (${e.code}).\n` +
          `  The socket is 0600, so the CLI cannot reach it. Re-run the installer to repair group membership.`,
        )
        return
      }
    }
    chmodSync(this.socketPath, 0o660)
    if (this.enrolledUid != null) {
      try {
        if (process.platform === 'darwin') {
          execFileSync('chmod', ['+a', `user:${this.enrolledUid} allow read,write`, this.socketPath])
        } else {
          execFileSync('setfacl', ['-m', `u:${this.enrolledUid}:rw`, this.socketPath])
        }
      } catch {
        // The group still covers it after the next login; record the gap.
        this.vault.audit?.write('daemon.socket_acl_failed', { uid: this.enrolledUid })
      }
    }
  }

  async stop() {
    unguardProcess(this)
    // Open watch streams never end on their own, and a server waits for
    // every connection before it closes.
    this.notifier.close()
    for (const s of this.servers) await new Promise((r) => s.close(r))
    if (this.socketPath && existsSync(this.socketPath)) unlinkSync(this.socketPath)
    this.vault.audit?.write('daemon.stop', {})
  }

  // ------------------------------------------------------------- the gateway

  /**
   * Run a request handler so that a rejection becomes a 500 rather than the
   * end of the daemon. The specific bug this was added for is fixed; the
   * reason it is here is that the NEXT one should cost one request, not the
   * whole process.
   */
  async #guard(req, res, fn) {
    try {
      await fn()
    } catch (e) {
      this.vault.audit?.write('daemon.handler_error', { detail: String(e?.message ?? e).slice(0, 200) })
      if (!res.headersSent) {
        res.writeHead(500, { 'content-type': 'application/problem+json' })
        res.end(JSON.stringify({ code: 'AV_INTERNAL', detail: 'the request could not be handled' }))
      } else {
        res.end()
      }
    }
  }

  async #onGateway(req, res) {
    const body = await readBody(req, res)
    if (body === null) return
    const url = new URL(req.url, 'http://placeholder')

    if (url.pathname === '/mcp') return this.#onMcpHttp(req, res, body, url)
    if (url.pathname.startsWith('/v1/')) return this.#onDiscovery(req, res, url, body)

    const result = await this.pipeline.handle({
      method: req.method,
      path: url.pathname,
      query: url.search.slice(1),
      headers: Object.entries(req.headers).map(([k, v]) => [k, Array.isArray(v) ? v.join(', ') : v]),
      body: body.length ? body : null,
      // Which listener this arrived on. #bindListener sets this on the Node
      // request and then this function built a fresh object without it, so it
      // was dropped one call later and `req.listener` inside the pipeline was
      // always undefined. Three things depended on it and none of them had
      // ever run: the rule refusing a bare placeholder as a carrier on a
      // network listener, a listener's `advertise` host list, and the peer
      // recorded in the audit log — which therefore said `loopback` for every
      // request, including ones that crossed the network.
      listener: req.listener || null,
    })
    res.writeHead(result.status, result.headers)
    if (result.stream) {
      for await (const chunk of result.stream) res.write(chunk)
      return res.end()
    }
    res.end(result.body)
  }

  /** Discovery endpoints an agent with no shell can use. */
  async #onDiscovery(req, res, url, body = Buffer.alloc(0)) {
    const token = req.headers['av-session'] || (req.headers.authorization || '').replace(/^Bearer\s+/i, '')
    const session = this.vault.sessionByToken(token)
    const json = (status, obj, headers = {}) => { res.writeHead(status, { 'content-type': 'application/json', ...headers }); res.end(JSON.stringify(obj, null, 2)) }

    try {
      if (url.pathname === '/v1/status') {
        return json(200, { daemon_version: VERSION, api_version: '1', locked: this.vault.locked, ...this.vault.stats() })
      }
      // F20: would this request pass? A peek: it authenticates exactly as a
      // real request, on the listener this arrived on (C18), and changes
      // nothing — not the session's expiry, not a counter.
      if (url.pathname === '/v1/preflight') {
        if (req.method !== 'POST') return json(404, { code: 'AV_NOT_FOUND', detail: 'preflight is POST /v1/preflight' })
        if (req.headers.origin || req.headers['sec-fetch-site']) {
          return json(403, { code: 'AV_BROWSER_ORIGIN', detail: 'requests carrying Origin are refused' })
        }
        if (!session) return json(401, { code: 'AV_SESSION_REQUIRED', hint: 'send Authorization: Bearer <session token>' })
        this.vault.assertSessionUsable(session, req.listener ?? null, { peek: true })
        const described = preflightRequest(body)
        return json(200, await this.pipeline.preflight({
          ...described,
          headers: [...described.headers, ['av-session', token]],
          listener: req.listener ?? null,
        }))
      }
      if (!session) return json(401, { code: 'AV_SESSION_REQUIRED', hint: 'send Authorization: Bearer <session token>' })
      // The same question /p/ and /mcp ask. Liveness alone let an infinite
      // session read its grants and mint placeholders on a network listener.
      this.vault.assertSessionUsable(session, req.listener ?? null)

      if (url.pathname === '/v1/session') {
        return json(200, {
          id: session.id, label: session.label, expires_at: session.expires_at ?? null,
          infinite: session.infinite === true, remote: session.remote,
        })
      }
      if (url.pathname === '/v1/credentials') {
        return json(200, this.vault.grantsForSession(session.id).map((g) => {
          const cred = this.vault.db.credentials[g.credential_id]
          return {
            slug: cred.slug, kind: cred.connector_kind, base_url: `/p/${cred.slug}`,
            allowed: g.policy, budget_remaining: (g.policy?.budget?.limit ?? 0) - g.budget_used,
            usage: cred.fields.map((f) => ({ field: f.name, sites: f.sites.map((s) => sitesMod.describeSite(sitesMod.parseSite(s))) })),
          }
        }))
      }
      if (url.pathname === '/v1/placeholders' && req.method === 'POST') {
        const cred = this.vault.findCredential(url.searchParams.get('cred'))
        if (!cred) return json(404, { code: 'AV_NOT_FOUND' })
        const grant = this.vault.grantsForSession(session.id).find((g) => g.credential_id === cred.id)
        if (!grant) return json(403, { code: 'AV_NO_GRANT' })
        const { placeholder } = this.vault.issuePlaceholder({ grantId: grant.id, field: cred.fields[0].name })
        return json(200, { placeholder, usage: cred.fields[0].sites.map((s) => sitesMod.describeSite(sitesMod.parseSite(s), placeholder)) })
      }
      return json(404, { code: 'AV_NOT_FOUND', detail: `no discovery endpoint ${url.pathname}` })
    } catch (e) {
      const err = e instanceof VaultError ? e : deny('AV_INTERNAL', e.message)
      return json(err.http, err.toProblem(), PROBLEM_HEADERS(err))
    }
  }

  /** Streamable HTTP MCP. Same handler as stdio; only the framing differs. */
  async #onMcpHttp(req, res, body, url) {
    let sessionHeader = {}
    const send = (status, obj, headers = {}) => {
      res.writeHead(status, { 'content-type': 'application/json', ...sessionHeader, ...headers })
      res.end(obj === null ? '' : JSON.stringify(obj))
    }

    // A browser must never be able to drive this endpoint. The MCP
    // specification calls for exactly this check on local HTTP servers.
    if (req.headers.origin || req.headers['sec-fetch-site']) {
      return send(403, { code: 'AV_BROWSER_ORIGIN', detail: 'requests carrying Origin are refused' })
    }

    const token = req.headers['av-session'] || (req.headers.authorization || '').replace(/^Bearer\s+/i, '')
    // Authentication is per TOOL, not per connection. A session grants access
    // to CREDENTIALS; it is not what makes the protocol work. This route used
    // to refuse the whole endpoint without a live one — before parsing a single
    // message — so `initialize` itself failed and the client reported the
    // server as unreachable. The vault was fine; one session had expired.
    //
    // Worse, it put the cure behind the disease: `vault_request_session` exists
    // precisely so an agent with no session can ask a human for one, and it was
    // unreachable exactly when it was needed. So was `vault_status`, which is
    // how you would find out why.
    //
    // This is what the HTTP API already does. `/v1/status` answers before any
    // session check and `POST /v1/session-requests` has none, because asking is
    // not getting. MCP now matches: the handshake and the two ungated tools
    // work without a session, and every tool that spends capability checks for
    // itself in #callTool. An expired token is treated as no token rather than
    // as an error, so a client reconnecting after an expiry comes up and can
    // say what is wrong.
    // Usable here, not merely live: an infinite session on a network listener
    // is a dead token to this endpoint (C12), and a tool that needs a session
    // reports AV_REMOTE_FORBIDDEN, recorded, when it is called. A peek, so the
    // handshake records nothing. The listener goes with each message too, so
    // the tools and the pipeline under vault_http ask the same question.
    const listener = req.listener ?? null
    let session = this.vault.sessionByToken(token)
    if (session) {
      try { this.vault.assertSessionUsable(session, listener, { peek: true }) } catch { session = null }
    }
    this.currentMcpSession = session
    // A token that was sent and is dead says so, on every answer. The
    // handshake no longer fails with 401 for it, and 401 was the only signal
    // the stdio bridge had to switch to a session a human has since made.
    sessionHeader = token && !session ? { 'av-session-invalid': '1' } : {}
    // Not stored on the server object: it is passed with each message below.

    if (req.method === 'DELETE') {
      const sid = req.headers['mcp-session-id']
      if (sid) this.mcp.closeSession(sid, { record: !!session })
      return send(204, null)
    }

    if (req.method === 'GET') {
      // The server-initiated notification stream.
      const sid = req.headers['mcp-session-id']
      if (!sid || !this.mcp.hasSession(sid)) return send(404, { code: 'AV_MCP_SESSION_UNKNOWN' })
      res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache', connection: 'keep-alive' })
      res.write(': agent-vault notification stream\n\n')
      const keepAlive = setInterval(() => res.write(': ping\n\n'), 15000)
      req.on('close', () => clearInterval(keepAlive))
      return
    }

    if (req.method !== 'POST') return send(405, { code: 'AV_MCP_PROTOCOL', detail: 'use POST, GET or DELETE' })

    let message
    try { message = JSON.parse(body.toString('utf8')) } catch { return send(400, { jsonrpc: '2.0', error: { code: -32700, message: 'parse error' } }) }

    // `JSON.parse('null')` returns null rather than throwing, so the parse
    // guard above let it straight through and `message.method` then threw
    // inside an async handler nobody was awaiting — an unhandled rejection,
    // which ends the process. One request with a valid session and a two-word
    // body stopped the daemon for everything on the machine.
    const isRequestObject = (m) => m !== null && typeof m === 'object' && !Array.isArray(m)
    const invalid = { jsonrpc: '2.0', id: null, error: { code: -32600, message: 'invalid request' } }
    if (Array.isArray(message)) {
      if (!message.length || !message.every(isRequestObject)) return send(400, invalid)
    } else if (!isRequestObject(message)) {
      return send(400, invalid)
    }

    const isInitialize = (Array.isArray(message) ? message[0]?.method : message.method) === 'initialize'

    // The protocol version is validated on every request after initialize.
    const version = req.headers['mcp-protocol-version']
    if (!isInitialize && version && !PROTOCOL_VERSIONS.includes(version)) {
      return send(400, { code: 'AV_MCP_PROTOCOL', detail: `unsupported MCP-Protocol-Version: ${version}`, supported: PROTOCOL_VERSIONS })
    }

    // The session id routes; it never authenticates. The bearer token above is
    // the only thing that authorizes, per the MCP specification.
    let mcpSessionId = req.headers['mcp-session-id']
    const extra = {}
    if (isInitialize) {
      // Recorded only for a caller with a live session. The handshake needs
      // no session — on purpose — so a record per anonymous initialize let any
      // local process, or any peer of an mcp listener, write the audit log as
      // fast as it could send.
      mcpSessionId = this.mcp.openSession({ record: !!session })
      extra['mcp-session-id'] = mcpSessionId
      extra['mcp-protocol-version'] = LATEST_PROTOCOL
    } else if (mcpSessionId && !this.mcp.hasSession(mcpSessionId)) {
      return send(404, { code: 'AV_MCP_SESSION_UNKNOWN', detail: 'unknown Mcp-Session-Id; call initialize again' })
    }

    const messages = Array.isArray(message) ? message : [message]
    const responses = []
    for (const m of messages) {
      // The session travels with the message. It used to be read from a field
      // on this Daemon, across the await below, so a concurrent request could
      // replace it between two messages of the same batch — and the rest of
      // the batch ran as somebody else's session, against their credentials.
      const r = await this.mcp.handle(m, session, token, listener)
      if (r) responses.push(r)
    }
    if (!responses.length) return send(202, null, extra)
    return send(200, Array.isArray(message) ? responses : responses[0], extra)
  }

  // ---------------------------------------------------------- the control API

  async #onControl(req, res) {
    const body = await readBody(req, res)
    if (body === null) return
    const url = new URL(req.url, 'http://control')
    const json = (status, obj) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(obj, null, 2)) }

    // Parsing sat outside the try below. This handler is async, so a single
    // malformed byte on the control socket became an unhandled rejection and
    // took the whole daemon down — and the control socket is reachable by the
    // agent by design.
    let input
    try {
      input = body.length ? JSON.parse(body.toString('utf8')) : {}
    } catch (e) {
      return json(400, { code: 'AV_MCP_PROTOCOL', detail: `request body is not valid JSON: ${e.message}` })
    }

    try {
      const route = `${req.method} ${url.pathname}`
      switch (route) {
        case 'GET /v1/status':
          return json(200, { daemon_version: VERSION, gateway_port: this.gatewayPort, ...this.vault.stats() })

        case 'POST /v1/credentials': {
          this.#requireHumanForWidening('cred add', this.#wideningOperation(route, url, input), input.presence)
          const kind = input.kind || 'http'
          const profile = getProfile(kind)
          // A profile whose proxy is not built must not accept a real secret.
          // Storing one would hand the agent a placeholder that cannot work,
          // while the human believes the credential is being protected.
          if (profile.implemented === false) {
            throw deny('AV_POLICY_DENIED', `the ${kind} connector is not implemented yet`, {
              rule: 'connector_implemented',
              hint: 'Its profile exists but the proxy that would carry it does not, so a credential of this kind could not be used. Do not store one here yet.',
            })
          }
          const field = input.field || defaultField(kind)
          // F10: when the token expires, if the human knows. Checked before
          // the credential exists, so a bad date leaves nothing half-stored.
          if (input.expires_at != null && (typeof input.expires_at !== 'string' || Number.isNaN(Date.parse(input.expires_at)))) {
            throw deny('AV_POLICY_DENIED', 'expires_at must be an ISO date', { rule: 'expires_at' })
          }
          let cred = this.vault.addCredential({
            slug: input.slug, kind,
            connector: { host: input.host || profile.hosts[0], scheme: input.scheme || 'https' },
            fields: { [field]: input.value },
            sites: { [field]: input.sites || defaultSites(kind, field) },
          })
          if (input.expires_at != null) {
            try {
              cred = this.vault.setCredentialExpiry(cred.slug, input.expires_at)
            } catch (e) {
              try { this.vault.deleteCredential(cred.slug) } catch { /* the refusal is what to report */ }
              throw e
            }
          }
          // A value this short is scrubbed from the response to a request
          // that injected it — that one is known exactly — but NOT from other
          // responses, where the whole vault's secrets are matched by value
          // and a four-character needle would redact ordinary words. So a
          // short credential can be echoed back to the agent by an upstream
          // it was never sent to. Say so at the moment it is stored, which is
          // the only moment anyone can do anything about it.
          const warnings = []
          if (String(input.value || '').length < MIN_SECRET_LEN) {
            warnings.push(`this value is under ${MIN_SECRET_LEN} characters, so it is only scrubbed from responses to requests that used it; another credential's response could echo it back to the agent unredacted`)
          }
          return json(200, warnings.length ? { ...cred, warnings } : cred)
        }
        case 'GET /v1/credentials':
          return json(200, this.vault.listCredentials())
        case 'DELETE /v1/credentials':
          this.#requireHumanForWidening('cred delete', this.#wideningOperation(route, url, input), input.presence)
          this.vault.deleteCredential(url.searchParams.get('slug'))
          return json(200, { ok: true })

        case 'POST /v1/sessions': {
          // Checked before the gate, so nobody is asked for a passphrase to
          // make something that would be refused anyway. The check changes
          // nothing. Auto-approved writes and "never expires" each take the
          // human out of every later request, so they need a proof made for
          // this one operation; a window someone opened for something else
          // does not count.
          const plan = this.#planSession(input)
          this.#gateSession('session create', this.#wideningOperation(route, url, input), plan.elevated, input.presence)
          return json(200, this.#makeSession(plan))
        }
        // ------------------------------------------------- session requests
        //
        // An agent may ASK for a session. Asking creates nothing: no session,
        // no token, no grant. The only thing that exists afterwards is a
        // question for a human, which is why this route is not gated — there
        // is no capability here to guard.
        case 'POST /v1/session-requests': {
          const { record, collectSecret } = this.proposeSessionRequest(input)
          return json(200, {
            ...SessionRequests.redact(record),
            // Shown once, here, to the asker. Only its hash is kept.
            collect_secret: collectSecret,
            next: {
              agent: 'poll GET /v1/session-requests/collect?id=<id>&secret=<collect_secret> until a human answers',
              human: [`agent-vault approvals`, `agent-vault approve ${record.id}`],
            },
          })
        }

        case 'GET /v1/session-requests':
          return json(200, this.sessionRequests.pending().map(SessionRequests.redact))

        // The agent collects its own token, exactly once. Reading is not
        // widening: the token was authorised by the human who approved it, and
        // handing it over twice would leave a second live copy in memory.
        //
        // "Its own" is now something this route checks. It handed the token to
        // whoever presented the id first, and every pending id is listed on
        // this socket, so another agent could poll the request and take the
        // session a human granted to someone else. The asker was given a
        // secret when it asked; nobody else has it.
        case 'GET /v1/session-requests/collect': {
          const record = this.sessionRequests.get(url.searchParams.get('id'))
          if (!record) throw deny('AV_NOT_FOUND', 'no such session request')
          if (!SessionRequests.mayCollect(record, url.searchParams.get('secret'))) {
            throw deny('AV_POLICY_DENIED', 'that is not the secret this request was opened with', {
              rule: 'collect_secret',
              hint: 'Only the agent that asked can collect: pass the collect_secret it was given as &secret=.',
            })
          }
          if (record.state === 'pending') return json(200, { state: 'pending' })
          if (record.state === 'denied') return json(200, { state: 'denied' })
          if (!record.result) return json(200, { state: record.state, detail: 'the answer is no longer available; ask again' })
          return json(200, { state: 'approved', ...this.#handOver(record, 'collect') })
        }

        case 'POST /v1/session-requests/decide': {
          // Before the gate, which reads the verdict to decide what to ask for.
          if (typeof input.granted !== 'boolean') {
            throw deny('AV_POLICY_DENIED', 'the verdict must be true or false', { rule: 'bulk_decision' })
          }
          const record = this.sessionRequests.get(input.id)
          if (!record) throw deny('AV_NOT_FOUND', `no session request ${input.id}`)
          if (record.state !== 'pending') {
            throw deny('AV_POLICY_DENIED', `that request was already ${record.state}`, { rule: 'session_requests' })
          }
          // What the human is about to create, after any edit they made. The
          // gate binds to THIS, not to what the agent originally asked for —
          // the HTTP approvals bound everything about a request except its
          // headers, and an approved POST arrived as a DELETE. Whatever is
          // outside the binding is what an agent can change afterwards.
          const final = { ...record.proposal, ...overridesOf(input.overrides || {}) }
          // Bound to the decision AS SENT — the id, the verdict, and any
          // narrowing — which is the convention every other gated route uses
          // and the only thing a client can sign without predicting a merge.
          // It binds the outcome just as tightly, because the stored proposal
          // is written once when the agent asks and never touched again: the
          // id plus the overrides determine `final` exactly.
          // An approval whose result is elevated needs a fresh proof, like
          // creating one directly. A denial creates nothing.
          this.#gateSession(
            'session request approval',
            webauthn.operationFor('session_request.decide', {
              id: record.id, granted: !!input.granted, ...overridesOf(input.overrides || {}),
            }),
            input.granted ? elevationOf(final) : [],
            input.presence,
          )
          const settled = this.#settleSessionRequest(record, input.granted, final)
          // The approving human's client records the session where local
          // clients look; the daemon cannot, it runs as its own uid. It gets it
          // here, from the decision it just proved presence for, which counts
          // as the one collection.
          if (input.granted && record.result) settled.session = this.#handOver(record, 'decide')
          return json(200, settled)
        }

        // Several decisions, one act of presence.
        //
        // The signature binds the list VERBATIM, so the set is fixed at the
        // moment it is signed. "Approve everything pending" would have let an
        // agent queue one more request between the signature and the execution
        // and have it approved by a human who never saw it — the same hole as
        // headers outside the request hash, which this codebase has paid for
        // twice. Every item is named and every verdict is explicit, and
        // anything the list does not mention is not touched.
        //
        // Each item then goes through the SAME settle path as the single route,
        // so a batch cannot reach a second, laxer one. An item that is no
        // longer pending is reported rather than skipped in silence: someone
        // who decided five things is owed an answer about five things.
        case 'POST /v1/pending/decide-many': {
          const problem = checkDecisions(input?.decisions)
          if (problem) throw deny('AV_POLICY_DENIED', problem, { rule: 'bulk_decision' })
          // One elevated approval in the list makes the whole list fresh: the
          // signature covers all of it, so it is held to the strictest item.
          const elevated = input.decisions.some((d) => {
            if (d.kind !== 'session' || d.granted !== true) return false
            const record = this.sessionRequests.get(d.id)
            if (!record || record.state !== 'pending') return false
            return elevationOf({ ...record.proposal, ...overridesOf(d.overrides || {}) }).length > 0
          })
          this.#gateSession(
            'bulk decision',
            webauthn.operationFor('pending.decide_many', { decisions: input.decisions }),
            elevated ? ['approval_auto_writes'] : [],
            input.presence,
          )
          const decided = []
          for (const d of input.decisions) {
            try {
              decided.push({ id: d.id, kind: d.kind, outcome: 'decided', result: this.#settleOne(d) })
            } catch (e) {
              decided.push({ id: d.id, kind: d.kind, outcome: 'skipped', reason: e.detail || e.message })
            }
          }
          // A client can record one session, so the approving client gets the
          // session only when the batch granted exactly one. With several,
          // each asker collects its own with its secret; handing them all to
          // one client would spend every agent's single collection on a store
          // that keeps the last.
          const grantedSessions = decided.filter(
            (r) => r.kind === 'session' && r.outcome === 'decided' && r.result?.state === 'approved',
          )
          if (grantedSessions.length === 1) {
            const record = this.sessionRequests.get(grantedSessions[0].id)
            if (record?.result) grantedSessions[0].result.session = this.#handOver(record, 'decide')
          }
          this.vault.audit?.write('pending.decided_many', {
            granted: input.decisions.filter((d) => d.granted).map((d) => d.id),
            denied: input.decisions.filter((d) => !d.granted).map((d) => d.id),
            skipped: decided.filter((r) => r.outcome === 'skipped').map((r) => r.id),
          })
          return json(200, { decided })
        }

        case 'GET /v1/sessions':
          return json(200, Object.values(this.vault.db.sessions).map((s) => {
            const grants = this.vault.grantsForSession(s.id)
            const infinite = s.infinite === true
            return {
              id: s.id, label: s.label, state: s.state, expires_at: s.expires_at ?? null, remote: s.remote,
              grants: grants.length,
              // Each grant's own values, so a client can list what a session
              // can map and how each one asks.
              creds: grants.map((g) => ({
                slug: this.vault.db.credentials[g.credential_id]?.slug ?? null,
                grant_id: g.id, approval: g.policy?.approval ?? null, methods: g.policy?.methods ?? null,
              })),
              infinite,
              // Recomputed from what is stored, by the function that gated it.
              // A grant with no mode stated is read the way the gateway reads
              // it, as auto.
              elevated: elevationOf({
                infinite,
                grants: grants.map((g) => ({
                  approval: g.policy?.approval ?? 'auto', methods: g.policy?.methods, routes: g.policy?.routes,
                })),
              }),
            }
          }))
        case 'DELETE /v1/sessions':
          this.vault.revokeSession(url.searchParams.get('sid'))
          return json(200, { ok: true })

        case 'POST /v1/placeholders': {
          // Issuing a placeholder mints a fresh authorization to spend a
          // credential, so it is a widening operation and needs the same human
          // as the others. Without this gate an agent that reached the socket
          // could not create a session — and did not need one: it borrowed an
          // existing session's grant, minted a placeholder, and used it as the
          // sole carrier on loopback. The credential reached the upstream with
          // no passphrase involved at any point.
          this.#requireHumanForWidening('placeholder issue', this.#wideningOperation(route, url, input), input.presence)
          const cred = this.vault.findCredential(input.cred)
          if (!cred) throw deny('AV_NOT_FOUND', `no credential ${input.cred}`)
          // Never silently borrow. Defaulting to whichever session happened to
          // be active is how one agent's request spends another's grant.
          // Live, not merely marked active: expiry is noticed lazily, so a
          // session nobody has touched since it ran out still says 'active'.
          const now = Date.now()
          const active = Object.values(this.vault.db.sessions)
            .filter((s) => s.state === 'active' && sessionExpiryMs(s) > now)
          if (!input.sid && active.length > 1) {
            throw deny('AV_SESSION_REQUIRED', `${active.length} sessions are active; name the one to issue for`, {
              rule: 'explicit_session',
              hint: `Pass sid. Active: ${active.map((s) => s.id).join(', ')}`,
            })
          }
          const session = input.sid ? this.vault.db.sessions[input.sid] : active[0]
          // Both of these used to fall through to `session.id` and answer with
          // a TypeError.
          if (input.sid && !session) throw deny('AV_NOT_FOUND', `no session ${input.sid}`)
          if (!session) {
            throw deny('AV_SESSION_REQUIRED', 'no session is active to issue a placeholder for', {
              next: { cli: [`agent-vault session create --cred ${cred.slug}`] },
            })
          }
          this.vault.assertSessionLive(session)
          const grant = this.vault.grantsForSession(session.id).find((g) => g.credential_id === cred.id)
          if (!grant) throw deny('AV_NO_GRANT', `no grant for ${input.cred} in session ${session.id}`)
          const { placeholder } = this.vault.issuePlaceholder({ grantId: grant.id, field: cred.fields[0].name, uses: input.uses ?? null })
          return json(200, { placeholder, usage: cred.fields[0].sites.map((s) => sitesMod.describeSite(sitesMod.parseSite(s), placeholder)) })
        }

        // Several placeholders for one session, in one act of presence: what
        // `agent-vault env` and `exec --map` write into a child's environment.
        // Gated like the single route, because each one is a fresh
        // authorization to spend a credential. All or nothing: every item is
        // resolved before the first placeholder is issued.
        case 'POST /v1/placeholders/batch': {
          const shape = (detail) => deny('AV_POLICY_DENIED', detail, {
            rule: 'batch_shape',
            hint: `Send { sid, items: [{ cred, field?, uses? }] } with 1 to ${MAX_BATCH} items, one per credential field.`,
          })
          // Never defaulted. Picking whichever session is active is how one
          // agent's request spends another's grant.
          if (typeof input.sid !== 'string' || !input.sid) throw shape('name the session: sid')
          if (!Array.isArray(input.items) || !input.items.length || input.items.length > MAX_BATCH) {
            throw shape(`items is a list of 1 to ${MAX_BATCH} entries`)
          }
          if (input.purpose != null && !['env', 'exec'].includes(input.purpose)) throw shape('purpose is env, exec or null')
          const pairs = new Set()
          for (const item of input.items) {
            if (!item || typeof item !== 'object' || Array.isArray(item)) throw shape('each item must be an object')
            if (typeof item.cred !== 'string' || !item.cred) throw shape('each item names a credential: cred')
            if (item.field != null && (typeof item.field !== 'string' || !item.field)) throw shape('field is a field name')
            if (item.uses != null && !(Number.isInteger(item.uses) && item.uses >= 1)) throw shape('uses is a whole number, 1 or more')
            // Two placeholders for one field in one batch would rotate each
            // other out: the second could kill the first before anyone used it.
            const key = `${item.cred}\u0000${item.field ?? ''}`
            if (pairs.has(key)) throw shape('each credential field appears once')
            pairs.add(key)
          }
          this.#requireHumanForWidening('placeholder issue', this.#wideningOperation(route, url, input), input.presence)
          if (this.vault.locked) throw deny('AV_LOCKED', 'the vault is locked')

          const session = this.vault.db.sessions[input.sid]
          if (!session) throw deny('AV_NOT_FOUND', `no session ${input.sid}`)
          this.vault.assertSessionLive(session)
          const grants = this.vault.grantsForSession(session.id)
          const resolved = input.items.map((item) => {
            const cred = this.vault.findCredential(item.cred)
            if (!cred) throw deny('AV_NOT_FOUND', `no credential ${item.cred}`)
            if (cred.quarantine) throw quarantined(cred)
            const grant = grants.find((g) => g.credential_id === cred.id)
            if (!grant) throw deny('AV_NO_GRANT', `no grant for ${cred.slug} in session ${session.id}`)
            this.vault.assertGrantLive(grant)
            const fieldName = item.field ?? grant.fields[0]
            const field = cred.fields.find((f) => f.name === fieldName)
            if (!field || !grant.fields.includes(fieldName)) {
              throw deny('AV_NO_GRANT', `the grant for ${cred.slug} does not cover that field`)
            }
            // The grant's ceiling wins over what the caller asks for, exactly
            // as on the single route.
            const maxUses = grant.policy?.placeholder_policy?.max_uses
            const asked = item.uses ?? null
            const uses = maxUses == null ? asked : Math.min(asked ?? maxUses, maxUses)
            return { cred, grant, field, uses }
          })
          const port = this.gatewayPort
          const items = resolved.map(({ cred, grant, field, uses }) => {
            const { placeholder } = this.vault.issuePlaceholder({ grantId: grant.id, field: field.name, uses })
            const profile = getProfile(cred.connector_kind)
            return {
              cred: cred.slug, field: field.name, placeholder,
              usage: field.sites.map((st) => sitesMod.describeSite(sitesMod.parseSite(st), placeholder)),
              base_url: `http://127.0.0.1:${port}/p/${cred.slug}`,
              env: profile.env ? { base: profile.env.base, key: profile.env.key } : null,
            }
          })
          // The file a client writes from this is outside the daemon, which
          // has no audit key there. This record is the evidence that it was
          // handed placeholders, and for which credentials.
          this.vault.audit.write('placeholder.issued_batch', {
            session_id: session.id, count: items.length,
            credential_slugs: [...new Set(items.map((i) => i.cred))], purpose: input.purpose ?? null,
          })
          return json(200, { session_id: session.id, gateway_url: `http://127.0.0.1:${port}`, items })
        }

        case 'GET /v1/approvals':
          return json(200, this.pipeline.pendingApprovals().map(approvalView))
        case 'POST /v1/approvals': {
          // Granting is the entire point of the approval: an agent that could
          // approve its own held request would have defeated the one control
          // that exists to put a human in the loop.
          //
          // Denying used to be left open on the theory that it only narrows.
          // It did not: an approval that had already run kept the response
          // the agent's request got, and denying it returned that response —
          // `av-placeholder-next` included, a successor that works as a
          // carrier on its own. Every answer is a human's answer now, bound to
          // which answer it is, so a signature for "approve" cannot be spent on
          // "deny" or the other way round.
          //
          // Not truthiness, as on the session-request route: `granted: "false"`
          // is not `false`, and it approved. Refused before the gate, which
          // reads the verdict to name the operation it asks a human for.
          if (typeof input.granted !== 'boolean') {
            throw deny('AV_POLICY_DENIED', 'the verdict must be true or false', { rule: 'bulk_decision' })
          }
          const granted = input.granted
          this.#requireHumanForWidening(
            granted ? 'approval grant' : 'approval deny',
            this.#wideningOperation(route, url, input), input.presence,
          )
          return json(200, this.#settleApproval(input.id, granted))
        }

        // The audit log is keyed from the vault master key, so a locked vault
        // genuinely cannot read it. Say that, rather than dereferencing a null
        // handle and reporting an internal error for an expected state.
        case 'GET /v1/audit':
          if (!this.vault.audit) throw deny('AV_LOCKED', 'the audit log is encrypted; unlock the vault to read it')
          return json(200, this.vault.audit.read({ limit: Number(url.searchParams.get('limit') || 30) }))
        case 'GET /v1/audit/verify':
          if (!this.vault.audit) throw deny('AV_LOCKED', 'the audit log is encrypted; unlock the vault to verify it')
          return json(200, this.vault.audit.verify())

        case 'GET /v1/listeners':
          return json(200, this.vault.listListeners())
        case 'POST /v1/listeners': {
          // A new listener widens what can reach this vault — on a network
          // address, to the whole LAN. That is a human's decision.
          this.#requireHumanForWidening('listener add', this.#wideningOperation(route, url, input), input.presence)
          // Validate here, not at bind time. Storing an address that can never
          // bind and reporting success means the failure surfaces at the next
          // restart, in a log nobody is watching, as a missing surface.
          let host
          try {
            ({ host } = parseAddress(input.address))
          } catch (e) {
            throw deny('AV_NOT_FOUND', e.message, {
              rule: 'listener_address',
              hint: 'An address is <host>:<port>, for example 127.0.0.1:7443.',
            })
          }
          // Never accepted and ignored: a list that cannot be read is refused
          // here, where the person who typed it is still looking.
          try {
            parseAllowCidr(input.allow_cidr)
          } catch (e) {
            throw deny('AV_POLICY_DENIED', e.message, {
              rule: 'listener_allow_cidr',
              hint: 'Each entry is <address>/<prefix>, for example 100.64.0.0/10 or fd7a:115c:a1e0::/48.',
            })
          }
          if (!isLoopbackHost(host) && !input.tls) {
            throw deny('AV_REMOTE_FORBIDDEN', `listener ${input.id} is on a network address and has no TLS`, {
              rule: 'listener_tls',
              hint: 'Plaintext off loopback would put session tokens and substituted credentials on the wire. Add --tls managed.',
            })
          }
          return json(200, this.vault.addListener(input))
        }
        case 'DELETE /v1/listeners': {
          const lid = url.searchParams.get('id')
          this.vault.removeListener(lid)
          const unbound = await this.#unbindListener(lid)
          return json(200, { ok: true, unbound })
        }

        case 'GET /v1/presence':
          return json(200, this.vault.db.kv.webauthn || null)
        case 'POST /v1/presence': {
          // Enrolling is itself a widening operation, and the sharpest one:
          // whoever enrols can sign every other change. An agent that reached
          // this socket must not be able to install its own key and then let
          // that key authorise everything else, so this is passphrase-only —
          // accepting an assertion here would be circular.
          //
          // A passphrase must already exist, and that is the load-bearing part.
          // The gate below cannot refuse anything on a vault with no factor —
          // there is nothing to check against — so on a fresh vault an agent
          // could enrol a software key of its own, become the only party able
          // to satisfy every presence gate, and leave the owner permanently
          // unable to set a passphrase, because setting the first one is
          // itself gated and now needs the agent's authenticator. Not a race
          // the owner might win: a takeover with no way back.
          //
          // Requiring the passphrase first makes that impossible and matches
          // the unlock factor, which has always refused to enrol before one
          // exists for the same reason.
          // A REPLACEMENT is proved by the authenticator being replaced (see
          // below), so a vault whose passphrase was later removed can still
          // rotate its key. Only a first enrolment needs the passphrase to
          // exist.
          const existed = !!this.vault.db.kv.webauthn
          if (!existed && !this.vault.hasPassphrase) {
            throw deny('AV_POLICY_DENIED', 'set a passphrase before enrolling an authenticator', {
              rule: 'factor_order',
              hint: 'agent-vault passphrase set. The passphrase is the recovery factor, and enrolling first would let whoever enrolled lock everyone else out.',
              next: 'agent-vault passphrase set',
            })
          }
          // The operation and the assertion are passed through, so a human
          // with the CURRENT authenticator can rotate it. They used not to be,
          // and the comment above explains why for the FIRST enrollment —
          // accepting an assertion to authorise the key that would produce it
          // is circular. For a REPLACEMENT it is the opposite: an assertion
          // from the key being replaced is the strongest proof there is that
          // the human holds it. Without this, a vault whose passphrase had
          // since been removed could never rotate its authenticator at all.
          this.#requireFreshPresence('presence enroll', this.#wideningOperation(route, url, input), input.presence)
          // Re-enrolling replaces the only thing standing between an agent and
          // the approve button, so it is audited loudly either way. The proof
          // that came with the request is not part of the key, and a
          // passphrase must never be written into the vault in clear. The
          // store decides what may be stored: a replacement the daemon could
          // not verify a signature from is refused, and the old key stays.
          const { replaced } = this.vault.setPresenceKey(withoutProof(input))
          return json(200, { ok: true, replaced })
        }
        case 'PATCH /v1/presence': {
          // Gone, deliberately, and kept as an explicit refusal so an older UI
          // gets an answer rather than a 404 it might treat as a routing bug.
          //
          // This let any caller set the stored signature counter. A counter
          // BELOW the stored one means "cloned authenticator" and is refused
          // forever, so walking it up was a permanent kill switch on the
          // owner's own authenticator: 300 individually-legal steps of 1000
          // took it to 300,005, and the owner's real key, sitting at 6, could
          // never satisfy the presence gate again. The per-call cap bounded
          // each step and not the total, which is the same thing as no cap.
          //
          // Nothing authenticated the caller, and nothing could: the UI's
          // assertion was verified against the UI's own challenge, so the
          // daemon cannot check it. The daemon does update the counter itself
          // from every assertion IT verifies (#verifyOpAssertion), which is
          // the path that can actually prove something. Clone detection for
          // UI-verified operations is weaker for this, and that is the right
          // trade: a counter an agent can poison is worse than no counter.
          throw deny('AV_POLICY_DENIED', 'the signature counter is not settable; the daemon maintains it from assertions it verifies itself', {
            rule: 'counter_not_settable',
          })
        }

        case 'POST /v1/lock':
          this.vault.lock()
          // A lock that leaves the passphrase window open is not one: the
          // window survived lock and unlock, still admitting every caller.
          this.presenceGraceUntil = 0
          return json(200, { ok: true, locked: true })

        // Which web UI origins this daemon accepts assertions from.
        case 'GET /v1/ui':
          return json(200, { port: this.uiPort, origins: this.uiOrigins() })
        case 'POST /v1/ui/origins': {
          const origin = String(input.origin || '')
          if (!uiOriginOk(origin)) {
            throw deny('AV_POLICY_DENIED', `not a web UI origin: ${JSON.stringify(input.origin)}`, {
              rule: 'ui_origin',
              hint: 'The UI is served on loopback under the name the authenticator is bound to: http://localhost:<port>.',
            })
          }
          // Trusting an origin is trusting every page served there to ask for
          // your fingerprint, so it needs fresh presence like a factor
          // change: a shared window is not enough.
          this.#requireFreshPresence('ui origin add', this.#wideningOperation(route, url, input), input.presence)
          const list = new Set(this.vault.db.kv.ui_origins || [])
          list.add(origin)
          this.vault.db.kv.ui_origins = [...list]
          this.vault.save()
          this.vault.audit?.write('ui.origin_added', { origin })
          return json(200, { ok: true, origins: this.uiOrigins() })
        }

        case 'POST /v1/unlock': {
          if (!this.vault.locked) return json(200, { ok: true, locked: false, already: true })
          // Unlocking is how you supply the factor, so it cannot be gated on
          // having supplied it. That leaves it as the one route an agent can
          // call repeatedly for free — and each attempt runs scrypt on the
          // event loop. Charge for the attempt instead.
          const guessing = input.passphrase != null
          if (guessing) this.#throttlePassphrase()
          let factor
          try {
            factor = this.vault.unlockWith({
              passphrase: input.passphrase ?? null,
              prfSecret: input.prf_secret || null,
            })
          } catch (e) {
            if (guessing) this.#recordPassphraseAttempt(false)
            throw e
          }
          if (guessing) this.#recordPassphraseAttempt(true)
          return json(200, { ok: true, locked: false, factor, factors: this.vault.factors })
        }
        case 'GET /v1/unlock/webauthn-params': {
          // What the browser needs to reproduce the PRF secret for unlock.
          if (!this.vault.hasWebauthnUnlock) throw deny('AV_NOT_FOUND', 'no Touch ID unlock enrolled')
          return json(200, {
            rp_id: 'localhost',
            credential_id: this.vault.webauthnUnlockCredentialId,
            prf_salt: this.vault.prfSalt(),
          })
        }
        case 'POST /v1/factors/webauthn': {
          // Enroll or remove Touch ID as an *unlock* factor — a wrap of the
          // vault master key, not a presence tap. Enrolling is the sharpest
          // widening this socket offers: the caller supplies the PRF secret,
          // so an agent that reached here could wrap the VMK to a secret it
          // chose and from then on open the vault whenever it liked, without
          // the passphrase and without touching anything. That converts
          // transient access to the socket into permanent possession of the
          // key. Removing is a capability change too, and the mirror of the
          // same trick: strip the human's factor and leave your own.
          //
          // This comment used to say the route required a presence window. It
          // did not; nothing here called the gate. Now it does.
          if (this.vault.locked) throw deny('AV_LOCKED', 'unlock the vault first')
          // Without a passphrase, enrolling is refused whoever asks: the
          // passphrase is the recovery factor, and a vault must never be left
          // with the authenticator as its only way in. Said before the gate,
          // so the owner learns what to do instead of tapping for a refusal.
          // The refusal widens nothing, and enroll-params already says
          // whether a passphrase exists.
          if (input.action !== 'remove') this.vault.requireRecoveryFactor()
          this.#requireFreshPresence(
            input.action === 'remove' ? 'touch id removal' : 'touch id enrollment',
            this.#wideningOperation(route, url, input), input.presence,
          )
          if (input.action === 'remove') {
            return json(200, { ok: true, removed: this.vault.removeWebauthnUnlock() })
          }
          this.vault.addWebauthnUnlock(input.credential_id, input.prf_secret)
          return json(200, { ok: true, enrolled: true })
        }
        case 'GET /v1/factors/webauthn-enroll-params':
          return json(200, {
            rp_id: 'localhost',
            has_passphrase: this.vault.hasPassphrase,
            prf_salt: this.vault.prfSalt(),
          })
        // Mint a challenge bound to one operation. The caller (the UI) passes
        // it to the browser; the assertion comes back here to be verified
        // against this stored copy, so the UI never gets to be the judge.
        case 'POST /v1/presence/challenge': {
          const enrolled = this.vault.db?.kv?.webauthn
          if (!enrolled) throw deny('AV_PRESENCE_REQUIRED', 'no authenticator is enrolled')
          const operation = input.operation || {}
          // The operation is held in memory until it expires and is whatever
          // the caller sent. An operation nobody will ever read back is not a
          // real one, and a megabyte of it a thousand times over is a way to
          // spend the daemon's memory from the control socket.
          if (JSON.stringify(operation).length > MAX_OPERATION_BYTES) {
            throw deny('AV_POLICY_DENIED', 'that operation description is too large to sign')
          }
          const challenge = webauthn.challengeForOperation(randomBytes(32), operation)
          const id = randomBytes(12).toString('base64url')
          // Sweeping only the expired ones bounds nothing: a caller can mint
          // as many as it likes inside one 60-second window. Cap the map too,
          // and refuse rather than evict — evicting would let a flood cancel
          // the confirmation a human is looking at.
          for (const [k, v] of this.opChallenges) if (v.expires < Date.now()) this.opChallenges.delete(k)
          // Evict the oldest rather than refuse. Refusing at the cap bounded
          // the memory and handed an agent a way to block the human entirely:
          // mint sixty-four and the owner can no longer get a challenge to
          // confirm anything with. Evicting keeps the bound and leaves the
          // human a way through — their next attempt always succeeds, because
          // it is the newest. A challenge is single-use and good for a minute,
          // so nothing durable is lost either way.
          while (this.opChallenges.size >= MAX_OPEN_CHALLENGES) {
            const oldest = this.opChallenges.keys().next().value
            if (oldest === undefined) break
            this.opChallenges.delete(oldest)
          }
          // `input.origins` is not read. The caller used to name which origins
          // the assertion could come from, so an agent named its own page.
          this.opChallenges.set(id, { challenge, operation, expires: Date.now() + 60_000 })
          return json(200, {
            challengeId: id,
            challenge: webauthn.b64url(challenge),
            allowCredentials: [{ id: enrolled.credentialId, type: 'public-key' }],
            rpId: 'localhost',
          })
        }
        // The certificate for the loopback TLS listener. The key stays behind
        // this uid; only the public certificate crosses the socket, which is
        // what the client needs as a trust anchor.
        case 'POST /v1/tls/ensure': {
          // Regenerating breaks every client that already trusts the old one,
          // so replacing a working certificate needs a human. Creating the
          // first one does not.
          if (input.force) this.#requireHumanForWidening('tls regenerate', { op: 'tls.regenerate' }, input.presence)
          const info = ensureCertificate(this.vault.dir, { force: !!input.force })
          this.vault.audit?.write('tls.certificate', {
            fingerprint: info.fingerprint, not_after: info.notAfter, created: info.created,
          })
          return json(200, {
            created: info.created,
            fingerprint: info.fingerprint,
            not_after: info.notAfter,
            certificate: info.pem,
            key_path: info.key,
          })
        }
        case 'GET /v1/tls': {
          const p = tlsPaths(this.vault.dir)
          if (!existsSync(p.cert)) return json(200, { configured: false })
          const info = ensureCertificate(this.vault.dir)
          return json(200, {
            configured: true, fingerprint: info.fingerprint, not_after: info.notAfter,
            certificate: info.pem,
          })
        }
        case 'POST /v1/presence/window': {
          if (this.vault.locked) throw deny('AV_LOCKED', 'unlock the vault first')
          if (!this.vault.hasPassphrase) {
            // No passphrase means no window to open. This answered
            // `granted: true`, which reads as "a window is open" to anything
            // that checks, so say what is actually true instead — and what is
            // true depends on the authenticator. With one enrolled, which is
            // where removing the passphrase leaves a vault, every widening call
            // still needs its signature: the socket is not ungated, it is
            // gated by the one factor a window cannot stand in for. The test
            // is the gate's own, so the two cannot disagree.
            if (this.vault.db?.kv?.webauthn) {
              return json(200, {
                granted: false,
                ungated: false,
                factors: ['authenticator'],
                detail: 'this vault has no passphrase, so no window was opened; every widening change still needs your authenticator',
                next: 'agent-vault ui   (confirm it there with your authenticator)',
              })
            }
            // With no factor at all, every widening call is ungated, and
            // audited as such.
            return json(200, {
              granted: false,
              ungated: true,
              detail: 'this vault has no passphrase, so nothing is gated and no window was opened',
              next: 'agent-vault passphrase set',
            })
          }
          this.#throttlePassphrase()
          const verified = this.vault.verifyPassphrase(input.passphrase || '')
          this.#recordPassphraseAttempt(verified)
          if (!verified) throw deny('AV_PRESENCE_DENIED', 'passphrase did not verify')
          this.presenceGraceUntil = Date.now() + this.presenceGraceMs
          this.vault.audit.write('presence.window_opened', { until: new Date(this.presenceGraceUntil).toISOString() })
          return json(200, { granted: true, until: new Date(this.presenceGraceUntil).toISOString() })
        }
        case 'POST /v1/passphrase': {
          if (this.vault.locked) throw deny('AV_LOCKED', 'unlock the vault before changing its passphrase')
          // Setting the FIRST passphrase takes the vault away from its owner:
          // the 'none' wrap is dropped and only whoever chose the phrase can
          // open it again. Changing or removing an existing one already needs
          // the current phrase, which is itself the human proof, so gating
          // those too would demand two secrets for one action.
          if (!this.vault.hasPassphrase) {
            this.#requireHumanForWidening('first passphrase', { op: 'passphrase.first' }, input.presence)
          }
          // Both branches below verify the CURRENT passphrase with scrypt
          // when one exists, and this route had no throttle at all — so it was
          // an unlimited guessing oracle, and each guess also held the event
          // loop for ~190ms. The throttle was added to the other two routes
          // that spend scrypt and this one was missed, which is the whole
          // reason to count the surface rather than the fix.
          const verifying = this.vault.hasPassphrase
          if (verifying) this.#throttlePassphrase()
          try {
            if (input.action === 'remove') {
              const removed = this.vault.removePassphrase(input.current || null)
              if (verifying) this.#recordPassphraseAttempt(true)
              return json(200, { ok: true, removed })
            }
            this.vault.setPassphrase(input.passphrase, input.current || null)
          } catch (e) {
            // Only a failed PROOF counts. A rejected new passphrase (too
            // short, say) is not a guess at the old one, and counting it would
            // let a typo lock the owner out of their own vault.
            if (verifying && e?.code === 'AV_LOCKED') this.#recordPassphraseAttempt(false)
            throw e
          }
          if (verifying) this.#recordPassphraseAttempt(true)
          return json(200, { ok: true, has_passphrase: true })
        }
        case 'GET /v1/lockstate':
          return json(200, {
            locked: this.vault.locked,
            factors: this.vault.factors,
            has_passphrase: this.vault.hasPassphrase,
            has_touchid: this.vault.hasWebauthnUnlock,
            // With no key-bearing factor, unlocking needs no secret, so the
            // lock is a policy gate rather than a cryptographic one.
            needs_secret: this.vault.hasPassphrase || this.vault.hasWebauthnUnlock,
          })

        // ------------------------------------------------ F15: narrowing
        //
        // Open: it can only take capability away. The narrowing is converted
        // with no defaults and then INTERSECTED with each grant (the store's
        // narrowGrant), so nothing in it can make a grant laxer.
        case 'POST /v1/sessions/narrow':
          return json(200, this.#narrowSession(input))

        // ----------------------------------------- F19: activity and review
        case 'GET /v1/sessions/detail':
          return json(200, this.#sessionDetail(url.searchParams.get('sid')))
        case 'GET /v1/report/access': {
          if (!this.vault.audit) throw deny('AV_LOCKED', 'the audit log is encrypted; unlock the vault to read it')
          const since = reportSince(url.searchParams.get('since'))
          return json(200, accessReport(this.vault.audit.read({ limit: 100_000 }), {
            sessions: this.vault.db.sessions, grants: this.vault.db.grants,
            credentials: Object.values(this.vault.db.credentials).map((c) => ({ ...this.vault.publicCredential(c), id: c.id })),
            since,
          }))
        }

        // ------------------------------------------- credential records
        //
        // Every write to a credential record is gated (0.3), with one
        // exception: quarantine, which only stops things and has to work in
        // an emergency.
        case 'POST /v1/credentials/rotate': {
          this.#requireHumanForWidening('cred rotate', this.#wideningOperation(route, url, input), input.presence)
          if (input.retire_hours !== undefined && !(Number.isInteger(input.retire_hours) && input.retire_hours >= 0 && input.retire_hours <= 168)) {
            throw deny('AV_POLICY_DENIED', 'retire_hours is a whole number from 0 to 168', { rule: 'retire_window' })
          }
          const result = this.vault.rotateCredential(input.slug, {
            field: input.field ?? null, value: input.value, mode: input.mode ?? 'keep',
            retireMs: input.retire_hours !== undefined ? input.retire_hours * 3600_000 : undefined,
            // Absent clears the expiry: it described the old token.
            expiresAt: Object.hasOwn(input, 'expires_at') ? input.expires_at : undefined,
          })
          // A human approved those requests against the old key, and the new
          // one may reach further. Counts only, never the approvals.
          const invalidated = this.pipeline.denyApprovals({ credentialId: this.vault.findCredential(input.slug).id }, 'credential_rotated')
          const warnings = input.value.length < MIN_SECRET_LEN
            ? [`this value is under ${MIN_SECRET_LEN} characters, so it is only scrubbed from responses to requests that used it; another credential's response could echo it back to the agent unredacted`]
            : null
          return json(200, { ...result, invalidated_approvals: invalidated, ...(warnings ? { warnings } : {}) })
        }
        case 'POST /v1/credentials/scrub': {
          // The grammar is checked before anyone is asked for presence: a
          // pattern that would be refused needs no human to refuse it.
          if (typeof input.pattern !== 'string') throw deny('AV_POLICY_DENIED', 'pattern is the pattern text', { rule: 'scrub_pattern' })
          if (input.sample !== undefined && (typeof input.sample !== 'string' || input.sample.length > 64 * 1024)) {
            throw deny('AV_POLICY_DENIED', 'sample is text of at most 64 KiB', { rule: 'policy_invalid' })
          }
          const { re } = compileScrubPattern(input.pattern)
          this.#requireHumanForWidening('cred scrub add', this.#wideningOperation(route, url, input), input.presence)
          const added = this.vault.addScrubPattern(input.slug, input.pattern)
          if (input.sample === undefined) return json(200, added)
          // The human's own text, with the pattern applied. Never a stored
          // secret: nothing but `sample` is read here.
          let matches = 0
          const redacted = input.sample.replace(new RegExp(re.source, re.flags), () => { matches++; return '[[av:derived]]' })
          return json(200, { ...added, sample: { redacted, matches } })
        }
        case 'DELETE /v1/credentials/scrub': {
          this.#requireHumanForWidening('cred scrub remove', this.#wideningOperation(route, url, input), input.presence)
          const removed = this.vault.removeScrubPattern(url.searchParams.get('slug'), url.searchParams.get('id'))
          return json(200, { ok: true, removed })
        }
        case 'POST /v1/credentials/expiry': {
          this.#requireHumanForWidening('cred expiry', this.#wideningOperation(route, url, input), input.presence)
          if (!(input.expires_at === null || typeof input.expires_at === 'string')) {
            throw deny('AV_POLICY_DENIED', 'expires_at is an ISO date, or null to clear it', { rule: 'expires_at' })
          }
          return json(200, this.vault.setCredentialExpiry(input.slug, input.expires_at))
        }
        case 'POST /v1/credentials/pins': {
          this.#requireHumanForWidening('cred pins', this.#wideningOperation(route, url, input), input.presence)
          if (!Array.isArray(input.pins)) throw deny('AV_POLICY_DENIED', 'pins is a list of sha256/<base64> values', { rule: 'pin_format' })
          return json(200, this.vault.setPins(input.slug, input.host, input.pins))
        }
        case 'DELETE /v1/credentials/pins': {
          this.#requireHumanForWidening('cred pins remove', this.#wideningOperation(route, url, input), input.presence)
          const remaining = this.vault.clearPins(
            url.searchParams.get('slug'), url.searchParams.get('host'), url.searchParams.get('spki'),
          )
          return json(200, { ok: true, remaining })
        }
        case 'POST /v1/credentials/test': {
          // Open, and throttled to once a minute per credential by the probe
          // itself: it spends the credential, on the profile's own read-only
          // method and path, and nothing in this body reaches the request.
          if (this.vault.locked) throw deny('AV_LOCKED', 'unlock the vault to test a credential')
          if (input.all !== undefined && input.all !== true) throw deny('AV_POLICY_DENIED', 'all is true, or absent', { rule: 'policy_invalid' })
          if (input.all === true) {
            const results = []
            for (const cred of Object.values(this.vault.db.credentials)) {
              try {
                results.push({ slug: cred.slug, ...await this.#probe(cred) })
              } catch (e) {
                const err = e instanceof VaultError ? e : deny('AV_INTERNAL', 'the probe could not finish')
                results.push({ slug: cred.slug, error: err.code, ...(err.rule ? { rule: err.rule } : {}), ...(err.retryAfter !== undefined ? { retry_after: err.retryAfter } : {}) })
              }
            }
            return json(200, { results })
          }
          const cred = this.vault.findCredential(input.slug)
          if (!cred) throw deny('AV_NOT_FOUND', `no credential ${input.slug}`)
          return json(200, await this.#probe(cred))
        }
        case 'POST /v1/credentials/quarantine': {
          // Open, deliberately: it only stops things. An agent can deny the
          // human's sessions this way and gain nothing.
          if (input.reason != null && typeof input.reason !== 'string') {
            throw deny('AV_POLICY_DENIED', 'reason is text', { rule: 'policy_invalid' })
          }
          if (this.vault.locked) throw deny('AV_LOCKED', 'unlock the vault to quarantine a credential')
          const cred = this.vault.findCredential(input.slug)
          if (!cred) throw deny('AV_NOT_FOUND', `no credential ${input.slug}`)
          const quarantine = this.vault.setQuarantine(cred.slug, { by: 'control', reason: this.#untrustedText(input.reason) })
          const denied = this.pipeline.denyApprovals({ credentialId: cred.id }, 'quarantined')
          return json(200, { slug: cred.slug, quarantine, denied_approvals: denied })
        }
        case 'POST /v1/credentials/release': {
          this.#requireHumanForWidening('cred release', this.#wideningOperation(route, url, input), input.presence)
          const cred = this.vault.findCredential(input.slug)
          if (!cred) throw deny('AV_NOT_FOUND', `no credential ${input.slug}`)
          return json(200, { slug: cred.slug, released: this.vault.clearQuarantine(cred.slug) })
        }

        // ----------------------------------------------- F16: containment
        case 'POST /v1/panic': {
          // Open: it only takes capability away, and an emergency is no time
          // to look for a fingerprint.
          if (input.lock !== undefined && typeof input.lock !== 'boolean') {
            throw deny('AV_POLICY_DENIED', 'lock is true or false', { rule: 'policy_invalid' })
          }
          if (input.reason != null && (typeof input.reason !== 'string' || input.reason.length > 200)) {
            throw deny('AV_POLICY_DENIED', 'reason is text of at most 200 characters', { rule: 'policy_invalid' })
          }
          if (this.vault.locked) {
            const err = deny('AV_LOCKED', 'the vault is already locked, so nothing was revoked')
            return json(err.http, { ...err.toProblem(), locked: true, already: true })
          }
          const result = await this.pipeline.panic({ reason: input.reason ?? null, lock: input.lock === true })
          // A lock that leaves the passphrase window open is not one.
          if (result.locked) this.presenceGraceUntil = 0
          return json(200, result)
        }
        case 'GET /v1/tripwires': {
          const t = this.vault.getSettings().tripwires || {}
          return json(200, { enabled: t.enabled === true, rules: Array.isArray(t.rules) ? t.rules : null, defaults: DEFAULT_RULES })
        }
        case 'POST /v1/tripwires': {
          // Turning tripwires on only narrows, so exactly that is open: one
          // key, `enabled`, and the boolean true. Anything else (turning them
          // off, changing a rule, `'true'`, an extra key) changes what a
          // human chose, and needs one (C20).
          const { presence, ...body } = isObject(input) ? input : {}
          const keys = Object.keys(body)
          const enableOnly = keys.length === 1 && keys[0] === 'enabled' && body.enabled === true
          if (!enableOnly) this.#requireHumanForWidening('tripwires set', this.#wideningOperation(route, url, input), presence)
          const unknown = keys.filter((k) => k !== 'enabled' && k !== 'rules')
          if (unknown.length) throw deny('AV_POLICY_DENIED', `tripwires has no setting ${unknown[0]}`, { rule: 'tripwire_rule' })
          if (body.enabled !== undefined && typeof body.enabled !== 'boolean') {
            throw deny('AV_POLICY_DENIED', 'enabled is true or false', { rule: 'tripwire_rule' })
          }
          if (body.rules !== undefined && body.rules !== 'defaults' && !Array.isArray(body.rules)) {
            throw deny('AV_POLICY_DENIED', "rules is a list of rules, or 'defaults'", { rule: 'tripwire_rule' })
          }
          const current = this.vault.getSettings().tripwires || {}
          const next = {
            enabled: body.enabled ?? current.enabled === true,
            // Rules that were never set are the defaults, which is what the
            // gateway uses for them anyway; they are stored so the record
            // says what is in force.
            rules: body.rules === 'defaults' ? structuredClone(DEFAULT_RULES)
              : (body.rules ?? (Array.isArray(current.rules) ? current.rules : structuredClone(DEFAULT_RULES))),
          }
          const saved = this.vault.updateSettings({ tripwires: next }).tripwires
          return json(200, { enabled: saved.enabled === true, rules: saved.rules })
        }

        // ------------------------------------------------- F17: templates
        case 'GET /v1/templates': {
          const name = url.searchParams.get('name')
          if (name !== null) {
            const t = this.vault.getTemplate(name)
            if (!t) throw deny('AV_NOT_FOUND', `no template ${name}`)
            return json(200, { ...t, summary: templateSummary(t.spec), creds: templateCreds(t.spec), elevated: elevationOf(t.spec) })
          }
          return json(200, this.vault.listTemplates().map((t) => ({
            name: t.name, version: t.version, hash: t.hash, summary: templateSummary(t.spec),
            creds: templateCreds(t.spec), elevated: elevationOf(t.spec), updated_at: t.updated_at,
          })))
        }
        case 'POST /v1/templates': {
          // Configuration, not standing approval: a session made from it
          // still passes its own gate. Saving is gated because the next
          // human may trust the name. The spec is checked the way a create
          // would check it, with nothing made, before anyone is asked.
          const spec = input.spec
          if (!isObject(spec)) throw deny('AV_POLICY_DENIED', 'spec is a session-create object', { rule: 'session_shape' })
          for (const k of ['template', 'template_hash', 'presence']) {
            if (Object.hasOwn(spec, k)) throw deny('AV_POLICY_DENIED', `a template spec cannot carry ${k}`, { rule: 'session_shape' })
          }
          const plan = this.#planSession(spec, { dryRun: true })
          this.#requireHumanForWidening('template save', this.#wideningOperation(route, url, input), input.presence)
          const saved = this.vault.saveTemplate(input.name, spec)
          return json(200, {
            name: saved.name, version: saved.version, hash: saved.hash, spec: saved.spec,
            lint: plan.grants.flatMap((g) => g.lint), elevated: elevationOf(saved.spec),
          })
        }
        case 'DELETE /v1/templates':
          // Open: removing a shape grants nothing.
          return json(200, { ok: true, removed: this.vault.deleteTemplate(url.searchParams.get('name')) })

        // ---------------------------------------------------- F8: backup
        case 'POST /v1/backup/export': {
          if (this.vault.locked) throw deny('AV_LOCKED', 'unlock the vault to export it')
          // Fresh, never the window: the bundle is every secret, under a
          // passphrase whoever runs this chooses. An agent riding a window
          // would choose its own.
          this.#requireFreshPresence('backup export', this.#wideningOperation(route, url, input), input.presence)
          return json(200, await exportBackup(this.vault, { recoveryPassphrase: input.recovery_passphrase }))
        }
        case 'POST /v1/backup/inspect': {
          if (this.vault.locked) throw deny('AV_LOCKED', 'unlock the vault to inspect a backup')
          // Open, and charged like a passphrase attempt: each one is an
          // scrypt, and a wrong recovery passphrase is a guess. Only a wrong
          // one counts. A right one does not clear the count: an agent could
          // inspect a bundle it made itself to reset the throttle on the
          // vault passphrase it is guessing at.
          this.#throttlePassphrase()
          let inspected
          try {
            inspected = await inspectBackup(input.bundle, { recoveryPassphrase: input.recovery_passphrase })
          } catch (e) {
            if (e?.rule === 'backup_auth') this.#recordPassphraseAttempt(false)
            if (e?.rule && !this.vault.locked) this.vault.audit.write('backup.refused', { reason: e.rule })
            throw e
          }
          this.vault.audit.write('backup.inspected', { credentials: inspected.credentials.length, bundle_sha256: bundleDigest(input.bundle) })
          return json(200, inspected)
        }
        case 'POST /v1/backup/restore': {
          this.#requireHumanForWidening('backup restore', this.#wideningOperation(route, url, input), input.presence)
          if (this.vault.locked) throw deny('AV_LOCKED', 'unlock the vault to restore into it')
          this.#throttlePassphrase()
          try {
            return json(200, await restoreBackup(this.vault, input.bundle, {
              recoveryPassphrase: input.recovery_passphrase, onConflict: input.on_conflict ?? 'skip',
            }))
          } catch (e) {
            if (e?.rule === 'backup_auth') this.#recordPassphraseAttempt(false)
            throw e
          }
        }

        // ----------------------------------------- F9: audit export, witness
        case 'GET /v1/audit/export': {
          if (!this.vault.audit) throw deny('AV_LOCKED', 'the audit log is encrypted; unlock the vault to read it')
          return json(200, this.vault.audit.export({
            sinceSeq: wholeParam(url.searchParams.get('since_seq'), 0, 'since_seq'),
            limit: wholeParam(url.searchParams.get('limit'), 5000, 'limit'),
          }))
        }
        case 'GET /v1/audit/checkpoint':
          if (!this.vault.audit) throw deny('AV_LOCKED', 'the audit log is encrypted; unlock the vault to witness it')
          return json(200, this.vault.audit.checkpoint())
        case 'POST /v1/audit/verify-witness':
          if (!this.vault.audit) throw deny('AV_LOCKED', 'the audit log is encrypted; unlock the vault to verify it')
          return json(200, this.vault.audit.verifyWitness(input.checkpoints))

        // ---------------------------------------------- F14: notifications
        //
        // The stream resolves no session and needs none (C20): it reads what
        // GET /v1/approvals and GET /v1/session-requests already show anyone
        // on this socket, and a token sent to it is not read.
        case 'GET /v1/pending/stream':
          this.notifier.subscribe(res)
          return
        case 'GET /v1/notify':
          return json(200, { webhook: this.vault.notifyConfig() })
        case 'POST /v1/notify': {
          // The URL decides where the signal goes, and it is a credential in
          // its own right, so setting it needs the owner.
          this.#requireHumanForWidening('notify set', this.#wideningOperation(route, url, input), input.presence)
          return json(200, { webhook: this.vault.setNotifyWebhook({ url: input.webhook_url, detail: input.detail ?? 'minimal' }) })
        }
        case 'DELETE /v1/notify':
          // Open: it narrows what leaves the machine.
          if (this.vault.locked) throw deny('AV_LOCKED', 'unlock the vault to remove the webhook')
          return json(200, { ok: true, removed: this.vault.clearNotifyWebhook() })
        case 'POST /v1/notify/test':
          return json(200, await this.notifier.test())

        default:
          return json(404, { code: 'AV_NOT_FOUND', detail: `no control route ${route}` })
      }
    } catch (e) {
      const err = e instanceof VaultError ? e : deny('AV_INTERNAL', e.message)
      if (res.headersSent) return res.end()
      return json(err.http, err.toProblem())
    }
  }

  /** Run a credential's read-only probe (F12) and record that it ran. */
  async #probe(cred) {
    if (cred.quarantine) throw quarantined(cred)
    const result = await runProbe({ vault: this.vault, cred, profile: getProfile(cred.connector_kind) })
    this.vault.audit.write('cred.tested', {
      credential_slug: cred.slug, status: result.status, http_status: result.http_status, latency_ms: result.latency_ms,
    })
    return result
  }

  /**
   * Text an agent may have written, as it may be stored: no placeholder and
   * no stored secret, bounded. It is recorded as `*_untrusted` either way.
   */
  #untrustedText(text, max = 200) {
    if (typeof text !== 'string' || !text) return null
    let out = text.slice(0, max)
    for (const hit of ph.findAll(out).reverse()) out = `${out.slice(0, hit.offset)}«placeholder»${out.slice(hit.end)}`
    for (const { secret, label } of this.vault.allSecrets()) {
      if (typeof secret === 'string' && secret.length >= MIN_SECRET_LEN) out = out.split(secret).join(`[[av:redacted:${label}]]`)
    }
    return out
  }

  /**
   * Narrow a live session (F15). Open, because it can only take capability
   * away: every grant's new policy is the intersection of its old one with
   * the narrowing (the store's narrowGrant), and lifetimes only come closer.
   * Everything is checked and converted before anything changes.
   */
  #narrowSession(input) {
    const bad = (detail, rule = 'policy_invalid') => deny('AV_POLICY_DENIED', detail, { rule })
    if (!isObject(input)) throw bad('send { sid, cred?, narrow, session_ttl_minutes?, grant_ttl_minutes? }')
    if (typeof input.sid !== 'string' || !input.sid) throw deny('AV_NOT_FOUND', 'name the session: sid')
    if (this.vault.locked) throw deny('AV_LOCKED', 'unlock the vault to narrow a session')
    const session = Object.hasOwn(this.vault.db.sessions, input.sid) ? this.vault.db.sessions[input.sid] : null
    if (!session) throw deny('AV_NOT_FOUND', `no session ${input.sid}`)
    if (input.cred !== undefined && (typeof input.cred !== 'string' || !input.cred)) throw bad('cred is a credential slug')
    if (input.narrow !== undefined && !isObject(input.narrow)) throw bad('narrow is an object of grant limits')
    const narrow = input.narrow ?? {}
    const unknown = Object.keys(narrow).filter((k) => !NARROW_FIELDS.includes(k))
    if (unknown.length) throw bad(`a narrowing cannot carry ${unknown[0]}`)
    const minutes = (v, rule) => {
      if (v === undefined) return null
      if (!(Number.isInteger(v) && v >= 1)) throw bad('a lifetime is a whole number of minutes, 1 or more', rule)
      return v
    }
    const sessionTtl = minutes(input.session_ttl_minutes, 'ttl')
    // The grant lifetime may be given in the narrowing or beside it; the
    // shorter one wins.
    const grantTtls = [minutes(input.grant_ttl_minutes, 'grant_ttl'), minutes(narrow.grant_ttl_minutes, 'grant_ttl')].filter((v) => v !== null)
    const grantTtl = grantTtls.length ? Math.min(...grantTtls) : null
    const fields = Object.keys(narrow).filter((k) => k !== 'grant_ttl_minutes')
    // Doing nothing is refused, so nobody believes they narrowed something.
    if (!fields.length && sessionTtl === null && grantTtl === null) {
      throw bad('name at least one limit or lifetime to narrow', 'narrow_empty')
    }
    // The one field whose absence means "off" (0.6): stating any other
    // value on a grant that never stated one would turn it on.
    if (Object.hasOwn(narrow, 'redirects') && narrow.redirects !== 0) {
      throw bad('a narrowing can only turn redirect following off: redirects 0', 'narrow_widens')
    }
    if (narrow.approval !== undefined && !APPROVAL_MODES.includes(narrow.approval)) {
      throw deny('AV_POLICY_DENIED', 'approval is not one of the four modes', { rule: 'approval', hint: 'approval is one of: each, on-write, first-use, auto' })
    }
    if (narrow.budget !== undefined && policyMod.budgetInteger(narrow.budget) === null) {
      throw bad('budget must be a whole number of requests, 0 or more')
    }
    // Revoked or ended sessions have nothing left to narrow. On the control
    // socket, which is this machine.
    this.vault.assertSessionUsable(session, null)

    let grants = this.vault.grantsForSession(session.id)
    if (input.cred !== undefined) {
      grants = grants.filter((g) => this.vault.db.credentials[g.credential_id]?.slug === input.cred)
      if (!grants.length) throw deny('AV_NOT_FOUND', `session ${session.id} has no grant for ${input.cred}`)
    }
    const describe = (g, profile) => policyMod.describeEffective(policyMod.intersect([profile.policyCeiling, session.policy, g.policy]))
    const planned = grants.map((g) => {
      const cred = this.vault.db.credentials[g.credential_id]
      const profile = getProfile(cred.connector_kind)
      const ceiling = policyMod.credentialHostCeiling(cred, profile.hosts)
      const spec = Object.fromEntries(fields.map((k) => [k, narrow[k]]))
      // No defaults: a narrowing that names only methods must not also
      // "set" every path and the default budget.
      const layer = fields.length ? policyMod.grantPolicyFromInput(spec, { profile, ceiling, defaults: false }) : null
      return { g, cred, profile, layer, before: describe(g, profile) }
    })

    if (sessionTtl !== null) this.vault.shortenSession(session.id, sessionTtl * 60_000)
    const out = planned.map(({ g, cred, profile, layer, before }) => {
      if (layer) this.vault.narrowGrant(g.id, layer)
      if (grantTtl !== null) this.vault.shortenGrant(g.id, grantTtl * 60_000)
      const now = this.vault.db.grants[g.id]
      return { cred: cred.slug, grant_id: g.id, before, after: describe(now, profile), expires_at: now.expires_at ?? null }
    })
    return { session_id: session.id, expires_at: session.expires_at ?? null, infinite: session.infinite === true, grants: out }
  }

  /** One session in full (F19): metadata, never a placeholder or a token. */
  #sessionDetail(sid) {
    if (!this.vault.audit) throw deny('AV_LOCKED', 'the audit log is encrypted; unlock the vault to read it')
    const session = typeof sid === 'string' && Object.hasOwn(this.vault.db.sessions, sid) ? this.vault.db.sessions[sid] : null
    if (!session) throw deny('AV_NOT_FOUND', `no session ${sid}`)
    const grants = Object.values(this.vault.db.grants).filter((g) => g.session_id === session.id)
    const rows = this.vault.audit.read({ limit: 100_000 })
    return {
      session: {
        id: session.id, label: session.label, state: session.state, created_at: session.created_at,
        expires_at: session.expires_at ?? null, infinite: session.infinite === true, remote: session.remote === true,
        last_seen_at: session.last_seen_at ?? null, template: session.template ?? null,
        elevated: Array.isArray(session.elevated) ? session.elevated : [],
      },
      grants: grants.map((g) => {
        const cred = this.vault.db.credentials[g.credential_id]
        const profile = cred ? getProfile(cred.connector_kind) : null
        const effective = policyMod.intersect([profile?.policyCeiling, session.policy, g.policy])
        // The one budget reader (C4). No limit is null; an unreadable one is
        // reported as such, and nothing is remaining under it.
        const limit = policyMod.budgetLimit(effective.budget)
        const used = Number.isSafeInteger(g.budget_used) ? g.budget_used : null
        let spend = null
        try { spend = this.pipeline.spendFor(g.id) } catch { spend = { invalid: true } }
        return {
          grant_id: g.id, cred: cred?.slug ?? null, state: g.state, expires_at: g.expires_at ?? null,
          effective: policyMod.describeEffective(effective),
          budget: {
            limit: Number.isInteger(limit) ? limit : null, used,
            remaining: Number.isInteger(limit) && used !== null ? Math.max(0, limit - used) : (limit === null ? 0 : null),
            ...(limit === null ? { invalid: true } : {}),
          },
          limits: this.pipeline.limitsFor(g.id), spend, counters: g.counters ?? null,
          // Ledger rows, never the placeholder text.
          placeholders: Object.values(this.vault.db.placeholders).filter((p) => p.grant_id === g.id).map((p) => ({
            id: p.id, field: p.field, uses: p.uses, max_uses: p.max_uses, state: p.state,
            dead_reason: p.dead_reason ?? null, expires_at: p.expires_at ?? null,
          })),
        }
      }),
      activity: summarizeSession(rows, { session, grants }),
    }
  }
}

/** `since` for the access report: an ISO date, `<n>d` or `<n>h`; 7 days when absent. */
function reportSince(raw) {
  const text = raw ?? '7d'
  const rel = /^([1-9][0-9]{0,4})([dh])$/.exec(text)
  if (rel) return new Date(Date.now() - Number(rel[1]) * (rel[2] === 'd' ? 86_400_000 : 3_600_000)).toISOString()
  if (/^\d{4}-\d{2}-\d{2}/.test(text) && !Number.isNaN(Date.parse(text))) return new Date(Date.parse(text)).toISOString()
  throw deny('AV_POLICY_DENIED', 'since is an ISO date, or a span like 7d or 24h', { rule: 'report_since' })
}

/** A whole-number query parameter, or the default when absent. Anything else is refused, never coerced. */
function wholeParam(raw, fallback, name) {
  if (raw === null) return fallback
  if (!/^(0|[1-9][0-9]{0,15})$/.test(raw)) {
    throw deny('AV_POLICY_DENIED', `${name} must be a whole number`, { rule: 'audit_range' })
  }
  return Number(raw)
}

const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v)

/**
 * A session request's spec (a proposal, with any human edits) as the
 * session-create input it stands for. Minutes become hours, and the template
 * it was made from is metadata, not a template to resolve again: the proposal
 * already holds that template's fields as they were when the agent asked.
 */
function requestSpec(final) {
  const { ttl_minutes: ttlMinutes, template: _t, template_hash: _h, template_version: _v, ...spec } = final
  // A non-number is passed on as one, and refused there as a ttl.
  if (ttlMinutes != null) spec.ttl_hours = typeof ttlMinutes === 'number' ? ttlMinutes / 60 : ttlMinutes
  return spec
}

/**
 * The request a gateway preflight describes (F20), read strictly. The body
 * is text or base64, never both; headers are pairs or an object of strings.
 * The caller's own session headers and Host are dropped: the route sets the
 * session from the token it authenticated, and the request is one to this
 * gateway.
 */
function preflightRequest(raw) {
  const refuse = (detail) => deny('AV_POLICY_DENIED', detail, {
    rule: 'preflight_shape',
    hint: 'Send { method, path: "/p/<slug>/…", query?, headers?, body? | body_base64? }.',
  })
  let input
  try { input = JSON.parse(raw.length ? raw.toString('utf8') : '{}') } catch { throw refuse('the body is not JSON') }
  if (!isObject(input)) throw refuse('the body is a JSON object')
  if (typeof input.method !== 'string' || !/^[A-Za-z]{1,16}$/.test(input.method)) throw refuse('method is an HTTP method name')
  if (typeof input.path !== 'string' || !/^\/(p|t)\//.test(input.path)) throw refuse('path starts with /p/<slug>/ or /t/<scheme>/<host>/')
  if (input.query !== undefined && typeof input.query !== 'string') throw refuse('query is a string')
  if (input.body !== undefined && input.body_base64 !== undefined) throw refuse('send body or body_base64, not both')
  if (input.body !== undefined && typeof input.body !== 'string') throw refuse('body is a string')
  if (input.body_base64 !== undefined && (typeof input.body_base64 !== 'string' || !/^[A-Za-z0-9+/]*={0,2}$/.test(input.body_base64))) {
    throw refuse('body_base64 is base64')
  }
  let pairs = []
  if (Array.isArray(input.headers)) pairs = input.headers
  else if (isObject(input.headers)) pairs = Object.entries(input.headers)
  else if (input.headers !== undefined) throw refuse('headers are [name, value] pairs or an object')
  if (pairs.length > MAX_PREFLIGHT_HEADERS) throw refuse(`at most ${MAX_PREFLIGHT_HEADERS} headers`)
  const headers = [['host', '127.0.0.1']]
  for (const pair of pairs) {
    if (!Array.isArray(pair) || pair.length !== 2 || typeof pair[0] !== 'string' || typeof pair[1] !== 'string') {
      throw refuse('each header is a name and a string value')
    }
    if (/^av-/i.test(pair[0]) || pair[0].toLowerCase() === 'host') continue
    headers.push([pair[0], pair[1]])
  }
  const body = input.body !== undefined ? Buffer.from(input.body, 'utf8')
    : input.body_base64 !== undefined ? Buffer.from(input.body_base64, 'base64') : null
  return { method: input.method.toUpperCase(), path: input.path, query: input.query ?? '', headers, body: body?.length ? body : null }
}

/** The template a proposal was made from, as `{ name, version }`, or null. */
function templateOf(proposal) {
  return typeof proposal?.template === 'string' && Number.isSafeInteger(proposal.template_version)
    ? { name: proposal.template, version: proposal.template_version }
    : null
}

/** The store's refusal for a quarantined credential, met before anything is made. */
function quarantined(cred) {
  return deny('AV_QUARANTINED', `${cred.slug} is quarantined`, {
    rule: 'quarantine', hint: `A human can release it: agent-vault cred release ${cred.slug}`,
  })
}

/** The shape of a web UI origin this daemon will consider trusting. */
function uiOriginOk(origin) {
  const m = UI_ORIGIN_SHAPE.exec(String(origin))
  return !!m && Number(m[1]) > 0 && Number(m[1]) <= 65535
}

/**
 * A request body without the proof that rode along with it, for storing. A
 * stray top-level `passphrase` is dropped too: whatever else happens, one is
 * never written into the vault in clear.
 */
function withoutProof(input) {
  const { presence, passphrase, ...rest } = input || {}
  return rest
}

/**
 * An approval as the control API reports it: what it is and how it stands,
 * never the response the agent's request got. That response is the agent's,
 * and it carries headers — `av-placeholder-next` among them — that work as a
 * capability on their own.
 */
function approvalView(approval) {
  if (!approval || typeof approval !== 'object') return approval
  const { result, ...rest } = approval
  return rest
}

/**
 * A listener's `allow_cidr`, as something that can answer "may this peer
 * connect". Null means no restriction. Anything that is not a list of
 * <address>/<prefix> blocks throws: a restriction that cannot be read must not
 * quietly become no restriction.
 */
export function parseAllowCidr(list) {
  if (list == null) return null
  if (!Array.isArray(list)) throw new Error('allow_cidr must be a list of CIDR blocks')
  if (!list.length) return null
  const allow = new BlockList()
  for (const raw of list) {
    const m = /^([^/\s]+)\/(\d{1,3})$/.exec(String(raw).trim())
    const family = m ? isIP(m[1]) : 0
    const prefix = m ? Number(m[2]) : NaN
    if (!family || prefix > (family === 4 ? 32 : 128)) {
      throw new Error(`${JSON.stringify(raw)} is not a CIDR block`)
    }
    allow.addSubnet(m[1], prefix, family === 4 ? 'ipv4' : 'ipv6')
  }
  return allow
}

/** Whether a peer address falls inside an allow list. An unreadable one does not. */
function peerAllowed(allow, address) {
  // An IPv4 peer on a dual-stack socket arrives as ::ffff:a.b.c.d.
  const a = String(address || '').replace(/^::ffff:(?=\d+\.\d+\.\d+\.\d+$)/i, '')
  const family = isIP(a)
  if (!family) return false
  return allow.check(a, family === 4 ? 'ipv4' : 'ipv6')
}

/** `iface:port`, where iface may be a name, an IPv4 literal, or [v6]. */
export function parseAddress(address) {
  const s = String(address || '').trim()
  const m = /^\[(.+)\]:(\d+)$/.exec(s) || /^([^:]+):(\d+)$/.exec(s)
  if (!m) throw new Error(`address must be <host>:<port>, got ${JSON.stringify(address)}`)
  const port = Number(m[2])
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error(`bad port in ${s}`)
  return { host: m[1], port }
}

export function isLoopbackHost(host) {
  const h = String(host)
  if (['127.0.0.1', '::1', 'localhost', '[::1]'].includes(h)) return true
  // `/^127\./` matched NAMES as well as addresses, so `127.evil.com` and
  // `127.0.0.1.attacker.test` were both classified as loopback — and that
  // classification is what decides whether a listener may run without TLS and
  // whether a bare placeholder is allowed to authorize on it. A name resolves
  // to whatever its owner points it at, so a listener on one was a plaintext
  // network listener that the daemon believed was on the machine.
  //
  // 127.0.0.0/8, as an actual dotted quad and nothing else.
  const quad = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h)
  if (!quad) return false
  const octets = quad.slice(1).map(Number)
  if (octets.some((n) => n > 255)) return false
  return octets[0] === 127
}

function readBody(req, res) {
  return new Promise((resolve) => {
    const chunks = []
    let size = 0
    req.on('data', (c) => {
      size += c.length
      if (size > MAX_BODY) {
        res.writeHead(413, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ code: 'AV_UNSCANNABLE', detail: 'body exceeds 16 MiB' }))
        req.destroy()
        resolve(null)
        return
      }
      chunks.push(c)
    })
    req.on('end', () => resolve(Buffer.concat(chunks)))
    req.on('error', () => resolve(null))
  })
}
