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
    this.html = readFileSync(join(HERE, 'app.html'), 'utf8')
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
    await new Promise((resolve) => this.server.listen(this.port, '127.0.0.1', resolve))
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
    this.lastSeen = Date.now()
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
      return this.#sendHtml(res, this.html)
    }

    if (offered && !this.sessionCookie && safeEqual(offered, this.launchToken)) {
      this.sessionCookie = randomBytes(32).toString('base64url')
      this.claimedAt = new Date().toISOString()
      res.setHeader('Set-Cookie', `av_ui=${this.sessionCookie}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${Math.floor(this.idleMs / 1000)}`)
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
    'DELETE sessions', 'POST approvals', 'POST lock',
    'POST touchid/enroll', 'POST touchid/remove',
  ])

  /**
   * The gated calls whose signature the daemon checks again for itself, because
   * they widen what an agent can do. For these the daemon owns the signature
   * counter as well, so this process must not advance it first and make the
   * daemon's own check look like a cloned credential.
   */
  static DAEMON_VERIFIED = new Set(['POST credentials', 'DELETE credentials', 'POST sessions'])

  async #serveApi(req, res, url) {
    const cookie = this.#cookieFrom(req)
    if (!this.sessionCookie || !cookie || !safeEqual(cookie, this.sessionCookie)) {
      return this.#send(res, 401, { error: 'not authenticated' })
    }
    // Requiring a header a form post cannot set is the CSRF defence.
    if (req.headers['x-av-ui'] !== '1') return this.#send(res, 403, { error: 'missing X-AV-UI header' })

    const body = await readBody(req)
    const route = url.pathname.slice('/api/'.length)
    const key = `${req.method} ${route}`

    try {
      // Presence ceremonies first: they are how a caller earns the right to
      // run anything in the gated set.
      // Touch ID unlock. These are reachable while the vault is locked, because
      // unlocking is the whole point; they carry no capability of their own.
      if (key === 'GET unlock/state') {
        const ls = await this.#control('GET', '/v1/lockstate')
        return this.#send(res, 200, {
          locked: ls.locked, has_passphrase: ls.has_passphrase, has_touchid: ls.has_touchid,
        })
      }
      if (key === 'GET unlock/webauthn-params') {
        return this.#send(res, 200, await this.#control('GET', '/v1/unlock/webauthn-params'))
      }
      if (key === 'POST unlock/touchid') {
        // The PRF secret self-verifies: a wrong one fails the unwrap. No proof
        // to trust here beyond the crypto.
        return this.#send(res, 200, await this.#control('POST', '/v1/unlock', { prf_secret: body?.prf_secret }))
      }
      if (key === 'POST unlock/passphrase') {
        return this.#send(res, 200, await this.#control('POST', '/v1/unlock', { passphrase: body?.passphrase }))
      }
      if (key === 'GET touchid/enroll-params') {
        return this.#send(res, 200, await this.#control('GET', '/v1/factors/webauthn-enroll-params'))
      }

      // What the docs page needs to print commands that actually work on this
      // machine, rather than a generic example the reader has to translate.
      if (key === 'GET docs/context') {
        const st = await this.#control('GET', '/v1/status').catch(() => ({}))
        const creds = await this.#control('GET', '/v1/credentials').catch(() => [])
        const port = st.gateway_port || 7411
        return this.#send(res, 200, {
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
        return this.#send(res, 200, await this.#control('POST', '/v1/presence/window', {
          passphrase: body?.passphrase || '',
        }))
      }

      if (key === 'GET presence/state') {
        const enrolled = await this.#control('GET', '/v1/presence')
        return this.#send(res, 200, {
          enrolled: !!enrolled,
          credentialId: enrolled?.credentialId || null,
          rpId: this.rpId,
          origin: this.origin,
        })
      }
      if (key === 'POST presence/enroll/begin') {
        const existing = await this.#control('GET', '/v1/presence')
        if (existing) throw Object.assign(new Error('already enrolled; re-enrolling needs the CLI'), { status: 409 })
        const challenge = webauthn.newChallenge()
        this.challenges.set('enroll', { challenge, expires: Date.now() + 120_000, operation: { op: 'enroll' } })
        return this.#send(res, 200, {
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
        await this.#control('POST', '/v1/presence', credential)
        return this.#send(res, 200, { ok: true, credentialId: credential.credentialId })
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
        return this.#send(res, 200, { ...minted, rpId: this.rpId })
      }

      // Everything that widens or changes capability stops here unless the
      // caller brings a signature for this exact operation.
      if (UiServer.GATED.has(key)) {
        await this.#requirePresence(key, url, body, req)
      }

      if (key === 'POST touchid/enroll') {
        return this.#send(res, 200, await this.#control('POST', '/v1/factors/webauthn', {
          action: 'enroll', credential_id: body?.credential_id, prf_secret: body?.prf_secret,
        }))
      }
      if (key === 'POST touchid/remove') {
        return this.#send(res, 200, await this.#control('POST', '/v1/factors/webauthn', { action: 'remove' }))
      }

      switch (key) {
        case 'GET status': return this.#send(res, 200, await this.#control('GET', '/v1/status'))
        case 'GET credentials': return this.#send(res, 200, await this.#control('GET', '/v1/credentials'))
        case 'GET sessions': return this.#send(res, 200, await this.#control('GET', '/v1/sessions'))
        case 'GET approvals': return this.#send(res, 200, await this.#control('GET', '/v1/approvals'))
        case 'GET listeners': return this.#send(res, 200, await this.#control('GET', '/v1/listeners'))
        case 'GET audit': return this.#send(res, 200, await this.#control('GET', `/v1/audit?limit=${Number(url.searchParams.get('limit') || 40)}`))

        case 'POST credentials': {
          // The value arrives once, is forwarded straight to the daemon, and is
          // never stored here or echoed back in the response.
          const created = await this.#control('POST', '/v1/credentials', body)
          return this.#send(res, 200, created)
        }
        case 'DELETE credentials':
          // The signature travels with it: the daemon verifies this one too.
          return this.#send(res, 200, await this.#control(
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
          return this.#send(res, 200, created)
        }
        case 'DELETE sessions':
          return this.#send(res, 200, await this.#control('DELETE', `/v1/sessions?sid=${encodeURIComponent(url.searchParams.get('sid'))}`))
        case 'POST approvals':
          return this.#send(res, 200, await this.#control('POST', '/v1/approvals', body))
        case 'POST lock':
          return this.#send(res, 200, await this.#control('POST', '/v1/lock', {}))
        case 'POST unlock':
          return this.#send(res, 200, await this.#control('POST', '/v1/unlock', { passphrase: body?.passphrase || null }))
        case 'GET lockstate':
          return this.#send(res, 200, await this.#control('GET', '/v1/lockstate'))
        case 'GET audit/verify':
          return this.#send(res, 200, await this.#control('GET', '/v1/audit/verify'))
        default:
          return this.#send(res, 404, { error: `no route ${req.method} ${route}` })
      }
    } catch (e) {
      return this.#send(res, e.status || 500, { error: e.message, detail: e.problem })
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
      case 'POST lock': return of('vault.lock', {})
      case 'POST touchid/enroll': return of('touchid.enroll', body)
      case 'POST touchid/remove': return of('touchid.remove', {})
      default: return { op: key }
    }
  }


  // ------------------------------------------------------------------ helpers

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
