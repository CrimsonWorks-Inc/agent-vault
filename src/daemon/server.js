// The daemon's listeners.
//
// Two surfaces, deliberately separated:
//   - the gateway (loopback TCP, and optionally a network listener): /p/, /t/,
//     /v1/* discovery, and /mcp. Everything here spends capability.
//   - the control API (Unix socket only, mode 0600): everything that creates or
//     widens capability. It never binds a network address, which is the rule
//     that keeps a remote peer from growing its own grants.

import { createServer } from 'node:http'
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

const MAX_BODY = 16 * 1024 * 1024

export class Daemon {
  constructor(vault, { port = 7411, socketPath, host = '127.0.0.1', socketGroup = null, enrolledUid = null } = {}) {
    this.vault = vault
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
    this.mcp = new McpServer(vault, this.pipeline, () => this.currentMcpSession)
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
  }

  /**
   * Guard a capability-widening control operation. Two proofs are accepted: a
   * live passphrase window (the CLI's factor), or a WebAuthn assertion over
   * this exact operation (the UI's, and the stronger of the two). With neither
   * factor enrolled the call is open and audited as such, which is the
   * documented state of a vault with no human secret.
   */
  #requireHumanForWidening(op, operation = null, presence = null) {
    if (Date.now() < this.presenceGraceUntil) return
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
        // The page can only be served from loopback, and the relying party id
        // pins the domain; the port is whichever one `agent-vault ui` got.
        expectedOrigins: pending.origins,
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
    switch (route) {
      case 'POST /v1/credentials': return { op: 'cred.add', slug: input?.slug, kind: input?.kind }
      case 'DELETE /v1/credentials': return { op: 'cred.remove', slug: url.searchParams.get('slug') }
      case 'POST /v1/sessions':
        return { op: 'session.create', cred: input?.cred, methods: input?.methods, paths: input?.paths }
      case 'POST /v1/placeholders':
        return { op: 'placeholder.issue', cred: input?.cred, sid: input?.sid }
      case 'POST /v1/approvals':
        return { op: 'approval.approve', id: input?.id }
      case 'POST /v1/listeners':
        return { op: 'listener.add', id: input?.id, address: input?.address }
      default: return null
    }
  }

  async start() {
    const gateway = createServer((req, res) => this.#onGateway(req, res))
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
      const control = createServer((req, res) => this.#onControl(req, res))
      await new Promise((resolve) => control.listen(this.socketPath, resolve))
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

    const handler = (req, res) => {
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
    }

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

    await new Promise((resolve, reject) => {
      server.once('error', reject)
      server.listen(port, host, () => { server.removeListener('error', reject); resolve() })
    })
    this.servers.push(server)
    const bound = server.address()
    this.vault.audit?.write('listen.bound', {
      listener_id: entry.id, address: `${host}:${bound.port}`, tls: !!entry.tls, surfaces: [...surfaces],
    })
    return { id: entry.id, host, port: bound.port, tls: !!entry.tls, surfaces: [...surfaces], server }
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
    for (const s of this.servers) await new Promise((r) => s.close(r))
    if (this.socketPath && existsSync(this.socketPath)) unlinkSync(this.socketPath)
    this.vault.audit?.write('daemon.stop', {})
  }

  // ------------------------------------------------------------- the gateway

  async #onGateway(req, res) {
    const body = await readBody(req, res)
    if (body === null) return
    const url = new URL(req.url, 'http://placeholder')

    if (url.pathname === '/mcp') return this.#onMcpHttp(req, res, body, url)
    if (url.pathname.startsWith('/v1/')) return this.#onDiscovery(req, res, url)

    const result = await this.pipeline.handle({
      method: req.method,
      path: url.pathname,
      query: url.search.slice(1),
      headers: Object.entries(req.headers).map(([k, v]) => [k, Array.isArray(v) ? v.join(', ') : v]),
      body: body.length ? body : null,
    })
    res.writeHead(result.status, result.headers)
    if (result.stream) {
      for await (const chunk of result.stream) res.write(chunk)
      return res.end()
    }
    res.end(result.body)
  }

  /** Discovery endpoints an agent with no shell can use. */
  async #onDiscovery(req, res, url) {
    const token = req.headers['av-session'] || (req.headers.authorization || '').replace(/^Bearer\s+/i, '')
    const session = this.vault.sessionByToken(token)
    const json = (status, obj) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(obj, null, 2)) }

    try {
      if (url.pathname === '/v1/status') {
        return json(200, { daemon_version: '0.1.0', api_version: '1', locked: this.vault.locked, ...this.vault.stats() })
      }
      if (!session) return json(401, { code: 'AV_SESSION_REQUIRED', hint: 'send Authorization: Bearer <session token>' })
      this.vault.assertSessionLive(session)

      if (url.pathname === '/v1/session') {
        return json(200, { id: session.id, label: session.label, expires_at: session.expires_at, remote: session.remote })
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
      return json(err.http, err.toProblem())
    }
  }

  /** Streamable HTTP MCP. Same handler as stdio; only the framing differs. */
  async #onMcpHttp(req, res, body, url) {
    const send = (status, obj, headers = {}) => {
      res.writeHead(status, { 'content-type': 'application/json', ...headers })
      res.end(obj === null ? '' : JSON.stringify(obj))
    }

    // A browser must never be able to drive this endpoint. The MCP
    // specification calls for exactly this check on local HTTP servers.
    if (req.headers.origin || req.headers['sec-fetch-site']) {
      return send(403, { code: 'AV_BROWSER_ORIGIN', detail: 'requests carrying Origin are refused' })
    }

    const token = req.headers['av-session'] || (req.headers.authorization || '').replace(/^Bearer\s+/i, '')
    const session = this.vault.sessionByToken(token)
    if (!session) return send(401, { code: 'AV_SESSION_REQUIRED', detail: 'send Authorization: Bearer <session token>' })
    try { this.vault.assertSessionLive(session) } catch (e) { return send(401, e.toProblem()) }
    this.currentMcpSession = session
    this.mcp.sessionToken = token

    if (req.method === 'DELETE') {
      const sid = req.headers['mcp-session-id']
      if (sid) this.mcp.closeSession(sid)
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
      mcpSessionId = this.mcp.openSession()
      extra['mcp-session-id'] = mcpSessionId
      extra['mcp-protocol-version'] = LATEST_PROTOCOL
    } else if (mcpSessionId && !this.mcp.hasSession(mcpSessionId)) {
      return send(404, { code: 'AV_MCP_SESSION_UNKNOWN', detail: 'unknown Mcp-Session-Id; call initialize again' })
    }

    const messages = Array.isArray(message) ? message : [message]
    const responses = []
    for (const m of messages) {
      const r = await this.mcp.handle(m)
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
    const input = body.length ? JSON.parse(body.toString('utf8')) : {}

    try {
      const route = `${req.method} ${url.pathname}`
      switch (route) {
        case 'GET /v1/status':
          return json(200, { daemon_version: '0.1.0', gateway_port: this.gatewayPort, ...this.vault.stats() })

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
          const cred = this.vault.addCredential({
            slug: input.slug, kind,
            connector: { host: input.host || profile.hosts[0], scheme: input.scheme || 'https' },
            fields: { [field]: input.value },
            sites: { [field]: input.sites || defaultSites(kind, field) },
          })
          return json(200, cred)
        }
        case 'GET /v1/credentials':
          return json(200, this.vault.listCredentials())
        case 'DELETE /v1/credentials':
          this.#requireHumanForWidening('cred delete', this.#wideningOperation(route, url, input), input.presence)
          this.vault.deleteCredential(url.searchParams.get('slug'))
          return json(200, { ok: true })

        case 'POST /v1/sessions': {
          this.#requireHumanForWidening('session create', this.#wideningOperation(route, url, input), input.presence)
          const cred = this.vault.findCredential(input.cred)
          if (!cred) throw deny('AV_NOT_FOUND', `no credential ${input.cred}`)
          const profile = getProfile(cred.connector_kind)
          const { session, token } = this.vault.createSession({
            label: input.label, ttlMs: (input.ttl_hours ?? 8) * 3600_000, policy: {}, remote: !!input.remote,
          })
          // A grant can only reach the hosts the credential itself declares.
          // Without this an agent minting its own session could aim the
          // credential at a host it controls (the exfiltration path found in
          // the pen test).
          const ceiling = policyMod.credentialHostCeiling(cred, profile.hosts)
          const hosts = policyMod.confineHosts(input.hosts, ceiling)
          const policy = {
            hosts,
            methods: input.methods || ['GET', 'HEAD'],
            paths: input.paths || ['/**'],
            budget: { unit: profile.defaultBudget.unit, limit: input.budget ?? profile.defaultBudget.limit },
            approval: input.approval || 'on-write',
          }
          const problems = policyMod.lint(policy, { kind: cred.connector_kind })
          const grant = this.vault.createGrant({
            sessionId: session.id, credentialId: cred.id, fields: [cred.fields[0].name], policy,
          })
          const { placeholder } = this.vault.issuePlaceholder({ grantId: grant.id, field: cred.fields[0].name, uses: input.uses ?? null })
          return json(200, {
            session_id: session.id, token, expires_at: session.expires_at,
            grant_id: grant.id, placeholder,
            usage: cred.fields[0].sites.map((s) => sitesMod.describeSite(sitesMod.parseSite(s), placeholder)),
            base_url: `http://127.0.0.1:${this.gatewayPort}/p/${cred.slug}`,
            // The profile's own read-only probe, so a caller can print an
            // example request that works instead of a made-up path.
            probe_path: profile.probe?.path || null,
            lint: problems,
          })
        }
        case 'GET /v1/sessions':
          return json(200, Object.values(this.vault.db.sessions).map((s) => ({
            id: s.id, label: s.label, state: s.state, expires_at: s.expires_at, remote: s.remote,
            grants: this.vault.grantsForSession(s.id).length,
          })))
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
          const active = Object.values(this.vault.db.sessions).filter((s) => s.state === 'active')
          if (!input.sid && active.length > 1) {
            throw deny('AV_SESSION_REQUIRED', `${active.length} sessions are active; name the one to issue for`, {
              rule: 'explicit_session',
              hint: `Pass sid. Active: ${active.map((s) => s.id).join(', ')}`,
            })
          }
          const session = input.sid ? this.vault.db.sessions[input.sid] : active[0]
          const grant = this.vault.grantsForSession(session.id).find((g) => g.credential_id === cred.id)
          if (!grant) throw deny('AV_NO_GRANT', `no grant for ${input.cred} in session ${session.id}`)
          const { placeholder } = this.vault.issuePlaceholder({ grantId: grant.id, field: cred.fields[0].name, uses: input.uses ?? null })
          return json(200, { placeholder, usage: cred.fields[0].sites.map((s) => sitesMod.describeSite(sitesMod.parseSite(s), placeholder)) })
        }

        case 'GET /v1/approvals':
          return json(200, this.pipeline.pendingApprovals())
        case 'POST /v1/approvals': {
          // Granting is the entire point of the approval: an agent that could
          // approve its own held request would have defeated the one control
          // that exists to put a human in the loop. Denying is left open —
          // it only ever narrows, and an agent abandoning its own request is
          // a legitimate thing to want.
          const granted = input.granted !== false
          if (granted) {
            this.#requireHumanForWidening('approval grant', this.#wideningOperation(route, url, input), input.presence)
          }
          return json(200, this.pipeline.decideApproval(input.id, granted))
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
          if (!isLoopbackHost(host) && !input.tls) {
            throw deny('AV_REMOTE_FORBIDDEN', `listener ${input.id} is on a network address and has no TLS`, {
              rule: 'listener_tls',
              hint: 'Plaintext off loopback would put session tokens and substituted credentials on the wire. Add --tls managed.',
            })
          }
          return json(200, this.vault.addListener(input))
        }
        case 'DELETE /v1/listeners':
          this.vault.removeListener(url.searchParams.get('id'))
          return json(200, { ok: true })

        case 'GET /v1/presence':
          return json(200, this.vault.db.kv.webauthn || null)
        case 'POST /v1/presence': {
          // Enrolling is itself a widening operation, and the sharpest one:
          // whoever enrols can sign every other change. An agent that reached
          // this socket must not be able to install its own key and then let
          // that key authorise everything else, so this is passphrase-only —
          // accepting an assertion here would be circular.
          this.#requireHumanForWidening('presence enroll')
          // Re-enrolling replaces the only thing standing between an agent and
          // the approve button, so it is audited loudly either way.
          const existed = !!this.vault.db.kv.webauthn
          this.vault.db.kv.webauthn = input
          this.vault.save()
          this.vault.audit.write('presence.factor_added', {
            class: 'webauthn-platform', credential_id: input.credentialId, replaced_existing: existed,
          })
          return json(200, { ok: true, replaced: existed })
        }
        case 'PATCH /v1/presence': {
          // Counter bookkeeping after a successful assertion. Accepted only as
          // a small forward step: an authenticator that reports a lower count
          // than we stored is treated as cloned and refused forever, so a
          // caller able to set it to an arbitrary number could permanently
          // disable the presence gate — a denial of service against the very
          // control that stops an agent widening anything.
          const enrolled = this.vault.db.kv.webauthn
          const next = Number(input.signCount)
          if (enrolled && Number.isInteger(next) && next > (enrolled.signCount || 0)
              && next - (enrolled.signCount || 0) <= 1000) {
            enrolled.signCount = next
            this.vault.save()
            return json(200, { ok: true })
          }
          return json(200, { ok: true, ignored: true })
        }

        case 'POST /v1/lock':
          this.vault.lock()
          return json(200, { ok: true, locked: true })

        case 'POST /v1/unlock': {
          if (!this.vault.locked) return json(200, { ok: true, locked: false, already: true })
          const factor = this.vault.unlockWith({
            passphrase: input.passphrase ?? null,
            prfSecret: input.prf_secret || null,
          })
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
          // Enroll or remove Touch ID as an unlock factor. Requires the vault
          // unlocked and a live presence window, like any settings change.
          if (this.vault.locked) throw deny('AV_LOCKED', 'unlock the vault first')
          if (input.action === 'remove') {
            return json(200, { ok: true, removed: this.vault.removeWebauthnUnlock() })
          }
          if (!this.vault.hasPassphrase) {
            throw deny('AV_POLICY_DENIED', 'set a passphrase first; it is the recovery factor')
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
          const challenge = webauthn.challengeForOperation(randomBytes(32), operation)
          const id = randomBytes(12).toString('base64url')
          this.opChallenges.set(id, {
            challenge, operation, origins: input.origins || [], expires: Date.now() + 60_000,
          })
          // Never let a stale map grow without bound.
          for (const [k, v] of this.opChallenges) if (v.expires < Date.now()) this.opChallenges.delete(k)
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
          if (!this.vault.hasPassphrase) return json(200, { granted: true, ungated: true })
          if (!this.vault.verifyPassphrase(input.passphrase || '')) {
            throw deny('AV_PRESENCE_DENIED', 'passphrase did not verify')
          }
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
          if (input.action === 'remove') {
            const removed = this.vault.removePassphrase(input.current || null)
            return json(200, { ok: true, removed })
          }
          this.vault.setPassphrase(input.passphrase, input.current || null)
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

        default:
          return json(404, { code: 'AV_NOT_FOUND', detail: `no control route ${route}` })
      }
    } catch (e) {
      const err = e instanceof VaultError ? e : deny('AV_INTERNAL', e.message)
      return json(err.http, err.toProblem())
    }
  }
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
  return ['127.0.0.1', '::1', 'localhost', '[::1]'].includes(String(host))
    || /^127\./.test(String(host))
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
