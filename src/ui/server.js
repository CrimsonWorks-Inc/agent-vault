// The web UI server.
//
// A browser page is reachable by anything that can drive a browser, so this is
// built on the assumption that it will be reached. What protects you is not
// that the page is hidden, it is that the page is worth very little:
//
//   - No credential value is ever sent to the browser. Not on load, not on
//     demand, not behind a "reveal" button. There is no endpoint that returns
//     one, so there is nothing for a screenshot or a DOM read to capture.
//   - The launch token is single use. The first browser to claim it gets the
//     session and the token is burned, so if something else claims it first you
//     find out immediately: your own browser is refused.
//   - Loopback only, with an Origin check and a custom-header requirement, so a
//     web page you happen to be visiting cannot drive this one.
//   - The server exits when idle, so it is not a standing surface.
//   - Every action is written to the audit log with peer kind "ui".
//
// On top of that, every action that changes what an agent can do is gated on a
// WebAuthn assertion from an enrolled platform authenticator, with the
// challenge derived from that exact operation. An automated browser can click
// Approve and will sit at a Touch ID dialog that never resolves. See
// webauthn.js for why this is a signature the visitor cannot produce rather
// than a test the visitor passes.
//
// What remains, stated plainly: the platform's own dialog says who is asking,
// not what for, so an agent that triggers an action at the moment you were
// expecting a different one can borrow your touch. The page shows the operation
// and the audit log records it, which is detection for that last gap.

import { createServer } from 'node:http'
import { request as socketRequest } from 'node:http'
import { randomBytes, timingSafeEqual } from 'node:crypto'
import * as webauthn from './webauthn.js'
import { rememberSession } from '../client-state.js'
import { fetchPending, parseOverrides, collectApproved } from '../pending.js'
import { overridesOf } from '../daemon/session-requests.js'
import { findAll as findPlaceholders } from '../core/placeholder.js'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const HERE = dirname(fileURLToPath(import.meta.url))
const IDLE_EXIT_MS = 30 * 60_000

export class UiServer {
  /**
   * @param {string} socketPath the daemon's control socket
   * @param {{port?: number, idleMs?: number}} opts
   */
  constructor(socketPath, { port = 0, idleMs = IDLE_EXIT_MS, cli = 'agent-vault', statePath = null } = {}) {
    // Told, not derived. Deriving it from the environment means writing state
    // for whichever vault the environment names rather than the one this
    // server is actually serving, which is how a UI pointed at a scratch vault
    // overwrote the state of the real one. Default to the vault beside the
    // socket, which is the vault this server talks to.
    this.statePath = statePath || join(dirname(socketPath), 'cli-state.json')
    this.socketPath = socketPath
    this.port = port
    this.idleMs = idleMs
    // How the reader invokes the CLI, so the docs page can print commands they
    // can paste verbatim rather than a name that may not be on their PATH.
    this.cli = cli
    this.launchToken = randomBytes(24).toString('base64url')
    this.sessionCookie = null // set when the launch token is claimed
    this.claimedAt = null
    this.lastSeen = Date.now()
    this.html = servedPage()
    // Outstanding presence challenges, each bound to one operation and good
    // for one use within a minute.
    this.challenges = new Map()
    // WebAuthn requires the relying party id to be a domain. An IP literal is
    // not one, so 127.0.0.1 is rejected by the browser with "invalid domain".
    // localhost is a domain, and is a secure context over plain http, which is
    // what makes the platform authenticator available here at all.
    this.rpId = 'localhost'
  }

  async start() {
    this.server = createServer((req, res) => this.#handle(req, res))
    // Rejected, not thrown from an event: the UI now has a fixed default port,
    // so "already in use" is an ordinary answer the caller can explain.
    await new Promise((resolve, reject) => {
      this.server.once('error', reject)
      this.server.listen(this.port, '127.0.0.1', () => { this.server.removeListener('error', reject); resolve() })
    })
    this.boundPort = this.server.address().port
    this.origin = `http://localhost:${this.boundPort}`

    // localhost resolves to ::1 first on many systems, so bind both loopback
    // addresses rather than leaving the browser unable to connect.
    this.server6 = createServer((req, res) => this.#handle(req, res))
    await new Promise((resolve) => {
      this.server6.once('error', () => { this.server6 = null; resolve() })
      this.server6.listen(this.boundPort, '::1', resolve)
    })
    this.idleTimer = setInterval(() => {
      if (Date.now() - this.lastSeen > this.idleMs) this.stop()
    }, 30_000)
    this.idleTimer.unref?.()
    return this
  }

  get url() { return `${this.origin}/?t=${this.launchToken}` }

  async stop() {
    clearInterval(this.idleTimer)
    if (this.server) await new Promise((r) => this.server.close(r))
    if (this.server6) await new Promise((r) => this.server6.close(r))
    if (this.onStop) this.onStop()
  }

  // ------------------------------------------------------------------ routing

  async #handle(req, res) {
    // Not marked as activity here. Counting every request kept the server up
    // on the strength of the page's own refused polls once its cookie had
    // expired; only a caller holding the session counts (see #touch).
    const url = new URL(req.url, this.origin)

    // Arriving by IP would put the page on an origin whose domain cannot be a
    // relying party id, so the authenticator would refuse to enrol. Redirect to
    // the domain form, carrying the launch token through.
    const hostHeader = String(req.headers.host || '')
    const hostName = hostHeader.startsWith('[') ? hostHeader.slice(0, hostHeader.indexOf(']') + 1) : hostHeader.split(':')[0]
    if (hostName && hostName !== 'localhost') {
      if (!/^(127\.0\.0\.1|\[::1\]|::1)$/.test(hostName)) {
        return this.#send(res, 403, { error: `unexpected Host: ${hostName}` })
      }
      res.writeHead(302, { Location: `${this.origin}${req.url}` })
      return res.end()
    }

    // A page on another origin must not be able to drive this one. The API also
    // requires a custom header, which forces a preflight that we never answer.
    const origin = req.headers.origin
    if (origin && origin !== this.origin) return this.#send(res, 403, { error: 'cross-origin request refused' })

    if (url.pathname === '/') return this.#servePage(req, res, url)
    if (url.pathname.startsWith('/api/')) return this.#serveApi(req, res, url)
    return this.#send(res, 404, { error: 'not found' })
  }

  /**
   * The page itself. Loading it with a valid launch token claims the session
   * once and burns the token, so a second claimant gets nothing.
   */
  #servePage(req, res, url) {
    const offered = url.searchParams.get('t')
    const cookie = this.#cookieFrom(req)

    if (cookie && this.sessionCookie && safeEqual(cookie, this.sessionCookie)) {
      this.#touch(res)
      return this.#sendHtml(res, this.html)
    }

    if (offered && !this.sessionCookie && safeEqual(offered, this.launchToken)) {
      this.sessionCookie = randomBytes(32).toString('base64url')
      this.claimedAt = new Date().toISOString()
      this.#touch(res)
      // Redirect so the token leaves the address bar, browser history and any
      // Referer header the page might later send.
      res.writeHead(302, { Location: '/' })
      return res.end()
    }

    if (offered && this.sessionCookie) {
      return this.#sendHtml(res, errorPage(
        'This link was already used',
        'Another browser claimed this session first. If that was not you, close it and start a new one with <code>agent-vault ui</code>, then check <code>agent-vault audit tail</code>.',
      ), 409)
    }

    return this.#sendHtml(res, errorPage(
      'No session',
      'Open the UI with the link printed by <code>agent-vault ui</code>.',
    ), 401)
  }

  /**
   * Operations that change what an agent can do. Each needs a fresh signature
   * from the enrolled authenticator, covering that exact operation.
   */
  static GATED = new Set([
    'POST credentials', 'DELETE credentials', 'POST sessions',
    'DELETE sessions', 'POST approvals', 'POST session-requests/decide',
    'POST pending/decide-many', 'POST lock',
    'POST touchid/enroll', 'POST touchid/remove',
    // Wave 3 (contract A.6). Narrowing and deleting a template only take
    // something away, and the daemon leaves them open; the page signs them
    // anyway, because it signs every change it makes.
    'POST sessions/narrow',
    'POST credentials/rotate', 'POST credentials/scrub', 'DELETE credentials/scrub',
    'POST credentials/expiry', 'POST credentials/release',
    'POST tripwires', 'POST templates', 'DELETE templates',
    // Removing a pin takes away a check on the upstream's key (C22(4)).
    'DELETE credentials/pins',
    // Replacing the confirmation key, signed by the key being replaced.
    'POST presence/rotate',
  ])

  /**
   * The gated calls whose signature the daemon checks again for itself, because
   * they widen what an agent can do. For these the daemon owns the signature
   * counter as well, so this process must not advance it first and make the
   * daemon's own check look like a cloned credential.
   */
  static DAEMON_VERIFIED = new Set([
    'POST credentials', 'DELETE credentials', 'POST sessions',
    // A decision that makes an elevated session (auto-approved writes, or no
    // expiry) needs a fresh proof, which the daemon checks for itself.
    'POST session-requests/decide', 'POST pending/decide-many',
    // Credential-record writes, rule changes and templates widen or restore
    // capability, so the daemon gates them and checks the signature itself.
    'POST credentials/rotate', 'POST credentials/scrub', 'DELETE credentials/scrub',
    'POST credentials/expiry', 'POST credentials/release',
    'POST tripwires', 'POST templates', 'DELETE credentials/pins',
    // Enrolling a replacement key is fresh-gated in the daemon.
    'POST presence/rotate',
  ])

  /**
   * The one response that may carry a capability to the page: the hand-off
   * card for a session the human has just created here. Even that answer goes
   * through towardPage first; only the fields the card renders are put back,
   * and only on success (see handoffTowardPage).
   */
  static HANDOFF = new Set(['POST sessions'])

  async #serveApi(req, res, url) {
    const route = url.pathname.slice('/api/'.length)
    const key = `${req.method} ${route}`
    // Every answer to the page passes the same guard, so a route added later
    // cannot forget it. An error is never a hand-off, whatever route it is on:
    // the catch below uses this same send.
    const send = (status, obj) => this.#send(res, status, towardPage(obj))
    // The hand-off for a session made here: called from that route's success
    // line only, and checked against the route again.
    const handOff = (obj) => this.#send(res, 200, UiServer.HANDOFF.has(key) ? handoffTowardPage(obj) : towardPage(obj))
    const cookie = this.#cookieFrom(req)
    if (!this.sessionCookie || !cookie || !safeEqual(cookie, this.sessionCookie)) {
      return send(401, { error: 'not authenticated' })
    }
    // Requiring a header a form post cannot set is the CSRF defence.
    if (req.headers['x-av-ui'] !== '1') return send(403, { error: 'missing X-AV-UI header' })
    this.#touch(res)

    const body = await readBody(req)

    try {
      // Presence ceremonies first: they are how a caller earns the right to
      // run anything in the gated set.
      // Touch ID unlock. These are reachable while the vault is locked, because
      // unlocking is the whole point; they carry no capability of their own.
      if (key === 'GET unlock/state') {
        const ls = await this.#control('GET', '/v1/lockstate')
        return send(200, {
          locked: ls.locked, has_passphrase: ls.has_passphrase, has_touchid: ls.has_touchid,
        })
      }
      if (key === 'GET unlock/webauthn-params') {
        return send(200, await this.#control('GET', '/v1/unlock/webauthn-params'))
      }
      if (key === 'POST unlock/touchid') {
        // The PRF secret self-verifies: a wrong one fails the unwrap. No proof
        // to trust here beyond the crypto.
        return send(200, await this.#control('POST', '/v1/unlock', { prf_secret: body?.prf_secret }))
      }
      if (key === 'POST unlock/passphrase') {
        return send(200, await this.#control('POST', '/v1/unlock', { passphrase: body?.passphrase }))
      }
      if (key === 'GET touchid/enroll-params') {
        return send(200, await this.#control('GET', '/v1/factors/webauthn-enroll-params'))
      }

      // What the docs page needs to print commands that actually work on this
      // machine, rather than a generic example the reader has to translate.
      if (key === 'GET docs/context') {
        const st = await this.#control('GET', '/v1/status').catch(() => ({}))
        const creds = await this.#control('GET', '/v1/credentials').catch(() => [])
        const port = st.gateway_port || 7411
        return send(200, {
          version: st.daemon_version || null,
          gateway_port: port,
          gateway_url: `http://127.0.0.1:${port}`,
          mcp_url: `http://127.0.0.1:${port}/mcp`,
          cli: this.cli || 'agent-vault',
          cred_slugs: creds.map((c) => c.slug),
        })
      }

      // Enrolling the confirmation authenticator is passphrase-gated in the
      // daemon, so the page needs one way to prove the passphrase. It buys a
      // short window and nothing else; the fingerprint is what every later
      // change uses.
      if (key === 'POST presence/window') {
        return send(200, await this.#control('POST', '/v1/presence/window', {
          passphrase: body?.passphrase || '',
        }))
      }

      if (key === 'GET presence/state') {
        const enrolled = await this.#control('GET', '/v1/presence')
        return send(200, {
          enrolled: !!enrolled,
          credentialId: enrolled?.credentialId || null,
          rpId: this.rpId,
          origin: this.origin,
        })
      }
      if (key === 'POST presence/enroll/begin') {
        const existing = await this.#control('GET', '/v1/presence')
        if (existing) throw Object.assign(new Error('already enrolled; replace it with Replace authenticator, confirming with the one you have'), { status: 409 })
        const challenge = webauthn.newChallenge()
        this.challenges.set('enroll', { challenge, expires: Date.now() + 120_000, operation: { op: 'enroll' } })
        return send(200, {
          challenge: webauthn.b64url(challenge),
          rp: { id: this.rpId, name: 'agent-vault' },
          user: { id: webauthn.b64url(Buffer.from('agent-vault-operator')), name: 'operator', displayName: 'Vault operator' },
        })
      }
      if (key === 'POST presence/enroll/finish') {
        const pending = this.challenges.get('enroll')
        if (!pending || pending.expires < Date.now()) throw new Error('enrollment challenge expired; start again')
        this.challenges.delete('enroll')
        const credential = webauthn.verifyRegistration({
          attestationObject: body.attestationObject,
          clientDataJSON: body.clientDataJSON,
          expectedChallenge: pending.challenge,
          expectedOrigins: [this.origin],
          rpId: this.rpId,
        })
        // The passphrase goes with the enrolment itself, as fresh presence.
        // The daemon no longer accepts a passphrase window for this, because a
        // window admits every caller on the socket while it is open, not only
        // this page.
        await this.#control('POST', '/v1/presence', {
          ...credential,
          ...(typeof body?.passphrase === 'string' ? { presence: { passphrase: body.passphrase } } : {}),
        })
        return send(200, { ok: true, credentialId: credential.credentialId })
      }
      // Replacing the confirmation key. The first enrolment is passphrase-only,
      // because an assertion cannot vouch for the key that would make it. A
      // replacement is the opposite: a signature from the key being replaced
      // is the best proof there is that the human holding it wants this. So
      // the new key is registered here first, shown to the page, and enrolled
      // only with the CURRENT key's signature over exactly that record, which
      // this process and then the daemon each verify (POST presence/rotate).
      if (key === 'POST presence/rotate/begin') {
        const existing = await this.#control('GET', '/v1/presence')
        if (!existing) throw Object.assign(new Error('nothing to replace; set up change confirmation first'), { status: 412 })
        const challenge = webauthn.newChallenge()
        this.challenges.set('rotate', { challenge, expires: Date.now() + 120_000, operation: { op: 'rotate' } })
        return send(200, {
          challenge: webauthn.b64url(challenge),
          rp: { id: this.rpId, name: 'agent-vault' },
          user: { id: webauthn.b64url(Buffer.from('agent-vault-operator')), name: 'operator', displayName: 'Vault operator' },
          exclude: existing.credentialId,
        })
      }
      if (key === 'POST presence/rotate/register') {
        const pending = this.challenges.get('rotate')
        this.challenges.delete('rotate')
        if (!pending || pending.expires < Date.now()) throw Object.assign(new Error('the replacement challenge expired; start again'), { status: 401 })
        const credential = webauthn.verifyRegistration({
          attestationObject: body?.attestationObject,
          clientDataJSON: body?.clientDataJSON,
          expectedChallenge: pending.challenge,
          expectedOrigins: [this.origin],
          rpId: this.rpId,
        })
        // Public key material only; the page signs over exactly this.
        this.rotation = { credential, expires: Date.now() + 120_000 }
        return send(200, { credential })
      }

      if (key === 'POST presence/challenge') {
        const enrolled = await this.#control('GET', '/v1/presence')
        if (!enrolled) throw Object.assign(new Error('no authenticator enrolled'), { status: 412 })
        const operation = body?.operation || {}
        // The daemon mints it and keeps its own copy, because the daemon is
        // what has to be convinced. This process runs as the human's account,
        // so an agent could reach it; the daemon must not take its word.
        const minted = await this.#control('POST', '/v1/presence/challenge', {
          operation, origins: [this.origin],
        })
        this.challenges.set(minted.challengeId, {
          challenge: Buffer.from(minted.challenge, 'base64url'),
          operation,
          expires: Date.now() + 60_000,
        })
        return send(200, { ...minted, rpId: this.rpId })
      }

      // A verdict is true or false, nothing else. `!!"false"` is true, so a
      // string verdict used to reach the daemon as an approval. Refused before
      // the signature check, as the daemon refuses it before its gate.
      if ((key === 'POST approvals' || key === 'POST session-requests/decide') && typeof body?.granted !== 'boolean') {
        throw Object.assign(new Error('the verdict must be true or false'), {
          status: 403, problem: { code: 'AV_POLICY_DENIED', rule: 'bulk_decision' },
        })
      }

      // A narrowing that does not parse (a payload that is not JSON) is the
      // caller's mistake, said as such before any signature is spent.
      if (key === 'POST session-requests/decide' && body?.granted === true) {
        try { parseOverrides(body?.overrides || {}) } catch (e) {
          throw Object.assign(new Error(`the narrowing does not parse: ${e.message}`), {
            status: 400, problem: { code: 'AV_POLICY_DENIED', rule: 'policy_invalid' },
          })
        }
      }

      // A replacement key is the one this process just registered, or
      // nothing. Checked before the signature is spent, so a wrong record
      // costs the human no tap.
      if (key === 'POST presence/rotate') {
        const pending = this.rotation
        if (!pending || pending.expires < Date.now()) {
          this.rotation = null
          throw Object.assign(new Error('no replacement key is waiting; register it again'), { status: 409 })
        }
        const { presence: _proof, ...record } = body || {}
        if (canonical(record) !== canonical(pending.credential)) {
          throw Object.assign(new Error('that is not the key registered for this replacement'), { status: 409 })
        }
      }

      // Panic's one option is a lock, and only `true` means lock. A string
      // "false" is not a verdict, so it is refused rather than read.
      if (key === 'POST panic' && body?.lock !== undefined && typeof body.lock !== 'boolean') {
        throw Object.assign(new Error('lock must be true or false'), {
          status: 400, problem: { code: 'AV_POLICY_DENIED', rule: 'panic_shape' },
        })
      }

      // Everything that widens or changes capability stops here unless the
      // caller brings a signature for this exact operation.
      if (UiServer.GATED.has(key)) {
        await this.#requirePresence(key, url, body, req)
      }

      // The proof is forwarded, because the daemon checks it again for itself.
      // It used to be dropped here, so a vault with any factor refused every
      // Touch ID change made from this page as having no human behind it.
      if (key === 'POST touchid/enroll') {
        return send(200, await this.#control('POST', '/v1/factors/webauthn', {
          action: 'enroll', credential_id: body?.credential_id, prf_secret: body?.prf_secret, presence: body?.presence,
        }))
      }
      if (key === 'POST touchid/remove') {
        return send(200, await this.#control('POST', '/v1/factors/webauthn', {
          action: 'remove', presence: body?.presence,
        }))
      }
      if (key === 'POST presence/rotate') {
        // Exactly the record that was signed, and the signature with it: the
        // daemon verifies it against the key being replaced.
        const { credential } = this.rotation
        this.rotation = null
        return send(200, await this.#control('POST', '/v1/presence', {
          ...credential, presence: body.presence,
        }))
      }

      switch (key) {
        case 'GET status': return send(200, await this.#control('GET', '/v1/status'))
        case 'GET credentials': return send(200, await this.#control('GET', '/v1/credentials'))
        case 'GET sessions': return send(200, await this.#control('GET', '/v1/sessions'))
        // Everything waiting for a human, normalised by src/pending.js — the
        // same module the CLI renders from. The page paints whatever this
        // returns and decides nothing, so a new kind of decision appears in
        // both interfaces at once instead of in whichever one someone
        // remembered.
        case 'GET pending':
          return send(200, await fetchPending((path) => this.#control('GET', path)))
        case 'GET listeners': return send(200, await this.#control('GET', '/v1/listeners'))
        case 'GET audit': {
          // `kind` narrows the rows to one record kind (the tripwires card
          // reads tripwire.fired). Filtered here too, so a daemon that ignores
          // the parameter still answers the question that was asked.
          const kind = url.searchParams.get('kind')
          if (kind !== null && !/^[a-z_]+(\.[a-z_]+)*$/.test(kind)) {
            throw Object.assign(new Error('kind is a record kind, like tripwire.fired'), { status: 400 })
          }
          const limit = Number(url.searchParams.get('limit') || 40)
          const path = kind === null ? `/v1/audit?limit=${limit}` : `/v1/audit?limit=${Math.max(limit, 500)}&kind=${encodeURIComponent(kind)}`
          const rows = await this.#control('GET', path)
          return send(200, kind === null ? rows : (Array.isArray(rows) ? rows.filter((r) => r?.kind === kind).slice(-limit) : []))
        }
        case 'GET audit/checkpoint': return send(200, await this.#control('GET', '/v1/audit/checkpoint'))

        // Reads (F19, F16, F17, F14). Open in the daemon as well.
        case 'GET sessions/detail':
          return send(200, await this.#control('GET', `/v1/sessions/detail?sid=${encodeURIComponent(url.searchParams.get('sid') ?? '')}`))
        case 'GET report/access':
          return send(200, await this.#control('GET', `/v1/report/access?since=${encodeURIComponent(url.searchParams.get('since') || '7d')}`))
        case 'GET tripwires': return send(200, await this.#control('GET', '/v1/tripwires'))
        case 'GET templates': {
          const name = url.searchParams.get('name')
          return send(200, await this.#control('GET', name === null ? '/v1/templates' : `/v1/templates?name=${encodeURIComponent(name)}`))
        }
        case 'GET notify': return send(200, await this.#control('GET', '/v1/notify'))

        // Narrowing (F15). Signed above; the daemon leaves it open because it
        // can only take capability away, so the proof is not passed on.
        case 'POST sessions/narrow':
          return send(200, await this.#control('POST', '/v1/sessions/narrow', withoutProof(body)))

        // Credential-record writes. The whole signed body goes on, proof
        // included, because the daemon re-verifies it over the same body. A
        // rotation's new value passes through once and is never echoed.
        case 'POST credentials/rotate':
          return send(200, await this.#control('POST', '/v1/credentials/rotate', body))
        case 'POST credentials/scrub':
          return send(200, await this.#control('POST', '/v1/credentials/scrub', body))
        case 'DELETE credentials/scrub':
          return send(200, await this.#control(
            'DELETE', `/v1/credentials/scrub${queryOf(url, ['slug', 'id'])}`,
            { presence: body?.presence },
          ))
        case 'DELETE credentials/pins':
          return send(200, await this.#control(
            'DELETE', `/v1/credentials/pins${queryOf(url, ['slug', 'host', 'spki'])}`,
            { presence: body?.presence },
          ))
        case 'POST credentials/expiry':
          return send(200, await this.#control('POST', '/v1/credentials/expiry', body))
        case 'POST credentials/release':
          return send(200, await this.#control('POST', '/v1/credentials/release', body))
        // Open: the probe's method and path are the profile's own, so nothing
        // the page sends besides the name can steer it.
        case 'POST credentials/test':
          return send(200, await this.#control('POST', '/v1/credentials/test',
            body?.all === true ? { all: true } : { slug: body?.slug }))

        // Containment (F16). Open on purpose: in an emergency a fingerprint
        // prompt only slows things down, and each of these only takes away.
        case 'POST credentials/quarantine':
          return send(200, await this.#control('POST', '/v1/credentials/quarantine', {
            slug: body?.slug, ...(typeof body?.reason === 'string' && body.reason ? { reason: body.reason } : {}),
          }))
        case 'POST panic':
          return send(200, await this.#control('POST', '/v1/panic', {
            lock: body?.lock === true,
            ...(typeof body?.reason === 'string' && body.reason ? { reason: body.reason } : {}),
          }))
        case 'POST tripwires':
          return send(200, await this.#control('POST', '/v1/tripwires', body))

        // Templates (F17). Saving is gated in the daemon; deleting only
        // removes a shape and grants nothing, so it is signed here alone.
        case 'POST templates':
          return send(200, await this.#control('POST', '/v1/templates', body))
        case 'DELETE templates':
          return send(200, await this.#control('DELETE', `/v1/templates${queryOf(url, ['name'])}`))

        case 'POST credentials': {
          // The value arrives once, is forwarded straight to the daemon, and is
          // never stored here or echoed back in the response.
          const created = await this.#control('POST', '/v1/credentials', body)
          return send(200, created)
        }
        case 'DELETE credentials':
          // The signature travels with it: the daemon verifies this one too.
          return send(200, await this.#control(
            'DELETE', `/v1/credentials?slug=${encodeURIComponent(url.searchParams.get('slug'))}`,
            { presence: body?.presence },
          ))
        case 'POST sessions': {
          const created = await this.#control('POST', '/v1/sessions', body)
          // Record it where every local client looks. The vault keeps only
          // token_hash, so this plaintext exists exactly once — here — and
          // nothing can ever hand it back. A session created in this page used
          // to live in the vault and on the screen and nowhere else, while the
          // MCP bridge went on reading a token the CLI had written days
          // earlier and which had since expired. The docs page two panes over
          // promises "the bridge finds your current session"; this is what
          // makes that true however the session was made.
          try {
            rememberSession(created, this.statePath)
          } catch (e) {
            // Never fail the session over the bookkeeping: the human has the
            // token on screen either way, and can paste it.
            this.lastStateError = String(e?.message ?? e)
          }
          return handOff(created)
        }
        case 'DELETE sessions':
          return send(200, await this.#control('DELETE', `/v1/sessions?sid=${encodeURIComponent(url.searchParams.get('sid'))}`))
        case 'POST approvals':
          return send(200, await this.#control('POST', '/v1/approvals', body))
        // A session request is settled by its own control route, which verifies
        // its own operation shape — so this mirrors it rather than merging the
        // two behind one endpoint and having to guess which signature to make.
        // WHICH route applies to an id is the shared module's answer, carried
        // on the item the page was given.
        // One act of presence, several decisions. The page sends the list it
        // showed; the daemon binds that list verbatim and settles each item
        // through the same path a single decision takes.
        case 'POST pending/decide-many': {
          const answered = await this.#control('POST', '/v1/pending/decide-many', {
            decisions: body?.decisions,
            presence: body?.presence,
          })
          // Collecting a session token is ONCE only, and this process can hold
          // exactly one in the state file. Collecting several would consume
          // every agent's one chance and then keep only the last, destroying
          // capability a human had just granted. So this collects only when the
          // batch granted a single session; otherwise each agent collects its
          // own by polling, which is the normal path anyway.
          const grantedSessions = (answered?.decided || []).filter(
            (r) => r.kind === 'session' && r.outcome === 'decided' && r.result?.state === 'approved',
          )
          // The daemon hands the session to the approving client only when the
          // batch granted exactly one. It never goes on to the page.
          for (const r of answered?.decided || []) {
            const session = r.result?.session
            if (!session) continue
            delete r.result.session
            try {
              collectApproved({ id: r.id, kind: 'session' }, {
                answered: { session }, remember: (sn) => rememberSession(sn, this.statePath),
              })
              answered.recorded = r.id
            } catch (e) { this.lastStateError = String(e?.message ?? e) }
          }
          if (grantedSessions.length > 1) {
            answered.recorded = null
            answered.note = 'several sessions were approved, so each agent collects its own; this page records one at a time'
          }
          return send(200, answered)
        }

        case 'POST session-requests/decide': {
          const answered = await this.#control('POST', '/v1/session-requests/decide', {
            id: body?.id,
            granted: body.granted,
            overrides: body?.granted ? parseOverrides(body?.overrides || {}) : undefined,
            presence: body?.presence,
          })
          const { session, ...decision } = answered || {}
          if (!body?.granted) return send(200, decision)
          // Recorded here for the same reason the CLI does it: the daemon runs
          // as its own uid and cannot write the human's state file. This process
          // can, and the MCP bridge re-reads that file per request — so a
          // session approved in this page reaches a running agent on its next
          // call without anyone copying a token.
          let collected = null
          try {
            collected = collectApproved({ id: body.id, kind: 'session' }, {
              answered: { session }, remember: (s) => rememberSession(s, this.statePath),
            })
          } catch (e) { this.lastStateError = String(e?.message ?? e) }
          // The token itself never goes to the page. It went to the state file,
          // which is where local clients look; showing it here would put a live
          // capability in a browser for no reason.
          return send(200, {
            ...decision,
            recorded: collected ? { session_id: collected.session_id, expires_at: collected.expires_at } : null,
          })
        }
        case 'POST lock':
          return send(200, await this.#control('POST', '/v1/lock', {}))
        case 'POST unlock':
          return send(200, await this.#control('POST', '/v1/unlock', { passphrase: body?.passphrase || null }))
        case 'GET lockstate':
          return send(200, await this.#control('GET', '/v1/lockstate'))
        case 'GET audit/verify':
          return send(200, await this.#control('GET', '/v1/audit/verify'))
        default:
          return send(404, { error: `no route ${req.method} ${route}` })
      }
    } catch (e) {
      // A VaultError (a reserved operation field, say) carries its status as
      // `http`; reading only `status` made a refusal look like a crash.
      return send(e.status || e.http || 500, { error: e.message, detail: e.problem ?? e.toProblem?.() })
    }
  }

  /**
   * Verify the assertion attached to a mutating request. The operation the
   * signature covers is compared against the operation actually being run, so
   * a signature obtained for "approve request A" cannot execute "approve B".
   */
  async #requirePresence(key, url, body, req) {
    const enrolled = await this.#control('GET', '/v1/presence')
    if (!enrolled) {
      throw Object.assign(
        new Error('no authenticator is enrolled, so no change can be made from this page'),
        { status: 412 },
      )
    }
    const presence = body?.presence
    if (!presence?.challengeId) {
      throw Object.assign(new Error('this action needs a fresh authenticator signature'), { status: 401 })
    }
    const pending = this.challenges.get(presence.challengeId)
    this.challenges.delete(presence.challengeId) // single use, always
    if (!pending) throw Object.assign(new Error('unknown or already-used challenge'), { status: 401 })
    if (pending.expires < Date.now()) throw Object.assign(new Error('challenge expired; try again'), { status: 401 })

    const actual = this.#operationFor(key, url, body)
    if (canonical(pending.operation) !== canonical(actual)) {
      throw Object.assign(
        new Error('the signature was made for a different operation than the one submitted'),
        { status: 409 },
      )
    }

    const result = webauthn.verifyAssertion({
      credentialId: presence.credentialId,
      authenticatorData: presence.authenticatorData,
      clientDataJSON: presence.clientDataJSON,
      signature: presence.signature,
      expectedChallenge: pending.challenge,
      expectedOrigins: [this.origin],
      rpId: this.rpId,
      enrolled,
    })
    // The counter is not reported back any more. The route that accepted it
    // let any caller on the control socket set it, and a counter below the
    // stored one means "cloned" — so walking it up was a permanent kill switch
    // on the owner's authenticator. Nothing could authenticate this report:
    // the assertion above was verified against THIS process's challenge, which
    // the daemon has no way to check. The daemon maintains the counter from
    // the assertions it verifies itself instead.
    void result
  }

  /**
   * The canonical description of what a request will do. Both the challenge and
   * the check are derived from this, so they cannot drift apart.
   */
  #operationFor(key, url, body) {
    // The same builder the daemon uses, over the same request, so the two
    // cannot describe the operation differently — and neither can describe it
    // incompletely, which is what let a signature authorise more than it said.
    const of = (op, params) => webauthn.operationFor(op, params)
    switch (key) {
      case 'POST credentials': return of('cred.add', body)
      case 'DELETE credentials': return of('cred.remove', { slug: url.searchParams.get('slug') })
      case 'POST sessions': return of('session.create', body)
      case 'DELETE sessions': return of('session.revoke', { sid: url.searchParams.get('sid') })
      case 'POST approvals': return of(body?.granted === false ? 'approval.deny' : 'approval.approve', body)
      // Bound to the list exactly as the page sent it, which is the same thing
      // the daemon binds. Normalising on either side would let the signature
      // and the execution describe different sets.
      case 'POST pending/decide-many': return of('pending.decide_many', { decisions: body?.decisions })
      case 'POST session-requests/decide':
        // The same fields the daemon binds its own check to: the id, the
        // verdict and any narrowing. A signature for "approve, narrowed to GET
        // /user" therefore cannot be replayed to grant the wide original.
        // overridesOf is the daemon's own reader of a decision's overrides,
        // owner fields included, so the two cannot bind different things.
        return of('session_request.decide', {
          id: body?.id, granted: body?.granted, ...overridesOf(parseOverrides(body?.overrides || {})),
        })
      case 'POST lock': return of('vault.lock', {})
      // Only the fields that are forwarded, which is what the daemon binds.
      case 'POST touchid/enroll': return of('touchid.enroll', { credential_id: body?.credential_id, prf_secret: body?.prf_secret })
      case 'POST touchid/remove': return of('touchid.remove', {})
      // Wave 3: the same op names as the daemon (contract A.2), each over the
      // whole body, or over the query for a DELETE.
      case 'POST sessions/narrow': return of('session.narrow', body)
      case 'POST credentials/rotate': return of('cred.rotate', body)
      case 'POST credentials/scrub': return of('cred.scrub_add', body)
      case 'DELETE credentials/scrub': return of('cred.scrub_remove', { slug: url.searchParams.get('slug'), id: url.searchParams.get('id') })
      // C22(4): read with get(), so an absent spki ("every pin for the host")
      // is bound as null, never omitted, exactly as the daemon binds it.
      case 'DELETE credentials/pins':
        return of('cred.pins_remove', {
          slug: url.searchParams.get('slug'), host: url.searchParams.get('host'), spki: url.searchParams.get('spki'),
        })
      case 'POST credentials/expiry': return of('cred.expiry_set', body)
      case 'POST credentials/release': return of('cred.release', body)
      case 'POST tripwires': return of('tripwires.set', body)
      case 'POST templates': return of('template.save', body)
      case 'DELETE templates': return of('template.delete', { name: url.searchParams.get('name') })
      // What the daemon binds for an enrolment: the whole record.
      case 'POST presence/rotate': return of('presence.enroll', body)
      default: return { op: key }
    }
  }


  // ------------------------------------------------------------------ helpers

  /**
   * Activity by the holder of the session: it keeps the server up, and it
   * slides the cookie. The cookie was set once at claim with Max-Age equal to
   * the IDLE timeout and never refreshed, so it expired thirty minutes into
   * active use and the page could not get back in — the launch link was spent.
   */
  #touch(res) {
    this.lastSeen = Date.now()
    res.setHeader('Set-Cookie', `av_ui=${this.sessionCookie}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${Math.floor(this.idleMs / 1000)}`)
  }

  #cookieFrom(req) {
    const raw = req.headers.cookie || ''
    const match = /(?:^|;\s*)av_ui=([^;]+)/.exec(raw)
    return match ? match[1] : null
  }

  /** Forward to the daemon's control socket. The UI has no other power. */
  #control(method, path, body) {
    // Send an explicit length rather than letting Node chunk the body. A
    // chunked DELETE is refused by the server with a bare 400 and no message,
    // which is how the signature on "remove this credential" went missing.
    const payload = body === undefined || body === null ? null : Buffer.from(JSON.stringify(body))
    return new Promise((resolve, reject) => {
      const req = socketRequest(
        {
          socketPath: this.socketPath,
          path,
          method,
          headers: {
            'content-type': 'application/json',
            'av-client': 'agent-vault-ui',
            ...(payload ? { 'content-length': payload.length } : {}),
          },
        },
        (res) => {
          const chunks = []
          res.on('data', (c) => chunks.push(c))
          res.on('end', () => {
            const text = Buffer.concat(chunks).toString('utf8')
            let parsed
            try { parsed = JSON.parse(text) } catch { parsed = { raw: text } }
            if (res.statusCode >= 400) {
              reject(Object.assign(new Error(parsed.detail || parsed.error || 'daemon error'), { status: res.statusCode, problem: parsed }))
            } else resolve(parsed)
          })
        },
      )
      req.on('error', (e) => reject(Object.assign(e, { status: 503 })))
      req.end(payload ?? undefined)
    })
  }

  #send(res, status, obj) {
    const payload = JSON.stringify(obj)
    res.writeHead(status, {
      'content-type': 'application/json',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
    })
    res.end(payload)
  }

  #sendHtml(res, html, status = 200) {
    res.writeHead(status, {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
      // Everything is inline and same-origin; nothing may be loaded or sent
      // anywhere else, so a scripted page cannot beacon what it reads.
      'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; img-src data:; form-action 'none'; base-uri 'none'; frame-ancestors 'none'",
    })
    res.end(html)
  }
}

const canonical = webauthn.canonicalOperation

/** Where app.html takes the one parser of typed narrowing (contract C21). */
export const PARSER_MARKER = '/* parseOverrides: injected by src/ui/server.js from src/pending.js */'

/**
 * The page as served: app.html with parseOverrides put in at the marker, so
 * the page reads a narrowing with the same function this server rebinds the
 * signed operation with. A page without the marker is a build error, not a
 * page that cannot approve anything.
 */
export function servedPage(parser = parseOverrides) {
  const html = readFileSync(join(HERE, 'app.html'), 'utf8')
  if (html.split(PARSER_MARKER).length !== 2) throw new Error('app.html must carry the parseOverrides marker exactly once')
  // The source goes into an inline <script> as it is. Text that would end the
  // script, open an HTML comment, or put the marker back would change what
  // the page runs, so it stops the server from starting instead.
  const source = parser.toString()
  if (/<\/script/i.test(source) || source.includes('<!--') || source.includes(PARSER_MARKER)) {
    throw new Error('parseOverrides cannot be put in the page: its source holds </script, <!-- or the marker')
  }
  return html.replace(PARSER_MARKER, () => source)
}

/** The request minus its proof, for a daemon route that does not check one. */
function withoutProof(body) {
  const { presence: _proof, ...rest } = body || {}
  return rest
}

/** The named query parameters that were given, passed on exactly as given. */
function queryOf(url, names) {
  const q = new URLSearchParams()
  for (const n of names) if (url.searchParams.has(n)) q.set(n, url.searchParams.get(n))
  const text = q.toString()
  return text ? `?${text}` : ''
}

// What the page never receives, whatever a daemon route returns: a session
// token, a placeholder, a credential value, an unlock secret, a backup or its
// passphrase, a webhook URL. Keys with these names are dropped at any depth,
// in any case and with '-' read as '_', and any token- or placeholder-shaped
// text inside a string is replaced. The daemon's routes
// are not supposed to return any of it; this is what makes "never sent to the
// page" hold for a route that slips, including the agent-written text in an
// approval preview.
const WITHHELD_KEYS = new Set([
  'token', 'placeholder', 'value', 'secret', 'prf_secret', 'recovery_passphrase', 'passphrase', 'bundle', 'webhook_url',
])
const SESSION_TOKEN = /avs1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g
// Webhook_URL, webhook-url and WEBHOOK_URL are the same key to a reader.
const withheldKey = (k) => WITHHELD_KEYS.has(k.toLowerCase().replaceAll('-', '_'))

export function towardPage(value, depth = 0) {
  if (depth > 64) return null
  if (typeof value === 'string') return withheldText(value)
  if (Array.isArray(value)) return value.map((v) => towardPage(v, depth + 1))
  if (value && typeof value === 'object') {
    const out = {}
    for (const [k, v] of Object.entries(value)) {
      if (withheldKey(k)) continue
      out[k] = towardPage(v, depth + 1)
    }
    return out
  }
  return value
}

// What the hand-off card renders, and nothing else: the session's own token
// and the placeholders it was just given. A webhook URL, a value or a bundle
// in the same answer stays withheld.
const HANDOFF_FIELDS = ['token', 'session_id', 'expires_at', 'infinite', 'label', 'cli']
const HANDOFF_GRANT_FIELDS = ['placeholder', 'base_url', 'usage', 'cred', 'sites', 'probe']

/**
 * A session-create answer for the page: towardPage over all of it, then the
 * card's fields copied back from the original. A field is copied only when it
 * is a scalar or a list of scalars, so nothing nested rides along with it.
 */
export function handoffTowardPage(created) {
  const out = towardPage(created)
  if (!isRecord(created) || !isRecord(out)) return out
  copyShown(out, created, HANDOFF_FIELDS)
  // The card reads `s.grants || [s]`, and the daemon repeats grants[0] at the
  // top for clients written for one grant; so the top is a grant here too.
  copyShown(out, created, HANDOFF_GRANT_FIELDS)
  if (Array.isArray(created.grants) && Array.isArray(out.grants)) {
    created.grants.forEach((g, i) => {
      if (isRecord(g) && isRecord(out.grants[i])) copyShown(out.grants[i], g, HANDOFF_GRANT_FIELDS)
    })
  }
  return out
}

const isRecord = (v) => v !== null && typeof v === 'object' && !Array.isArray(v)
const isScalar = (v) => v === null || ['string', 'number', 'boolean'].includes(typeof v)

function copyShown(to, from, names) {
  for (const n of names) {
    if (!Object.hasOwn(from, n)) continue
    const v = from[n]
    if (isScalar(v) || (Array.isArray(v) && v.every(isScalar))) to[n] = v
  }
}

function withheldText(s) {
  let out = s.replace(SESSION_TOKEN, '«token»')
  // Last to first, so earlier offsets stay right.
  for (const p of findPlaceholders(out).reverse()) {
    out = `${out.slice(0, p.offset)}«placeholder»${out.slice(p.end)}`
  }
  return out
}

function safeEqual(a, b) {
  const ba = Buffer.from(String(a))
  const bb = Buffer.from(String(b))
  return ba.length === bb.length && timingSafeEqual(ba, bb)
}

function readBody(req) {
  return new Promise((resolve) => {
    const chunks = []
    let size = 0
    req.on('data', (c) => {
      size += c.length
      if (size > 1_000_000) { req.destroy(); resolve(null) }
      chunks.push(c)
    })
    req.on('end', () => {
      const text = Buffer.concat(chunks).toString('utf8')
      if (!text) return resolve(null)
      try { resolve(JSON.parse(text)) } catch { resolve(null) }
    })
    req.on('error', () => resolve(null))
  })
}

function errorPage(title, detail) {
  return `<!doctype html><meta charset="utf-8"><title>agent-vault</title>
<style>
  :root { color-scheme: light dark; }
  body { font: 15px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
         display: grid; place-items: center; min-height: 100vh; margin: 0; padding: 24px;
         background: Canvas; color: CanvasText; }
  .card { max-width: 30rem; border: 1px solid color-mix(in srgb, CanvasText 18%, transparent);
          border-radius: 12px; padding: 24px 28px; }
  h1 { font-size: 1.15rem; margin: 0 0 8px; }
  p { margin: 0; color: color-mix(in srgb, CanvasText 72%, transparent); }
  code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .9em;
         background: color-mix(in srgb, CanvasText 8%, transparent); padding: 1px 5px; border-radius: 4px; }
</style>
<div class="card"><h1>${title}</h1><p>${detail}</p></div>`
}
