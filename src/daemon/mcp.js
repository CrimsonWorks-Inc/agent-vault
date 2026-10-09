// MCP, implemented once and exposed over two transports.
//
// The tools live here, in the daemon, and both `agent-vault mcp` (stdio) and
// POST /mcp (Streamable HTTP) drive this same handler. One implementation is
// the point: if the transports had separate code, they would drift, and the
// drift would be in policy evaluation and scrubbing rather than in framing.
//
// No tool returns a secret, creates a credential, or approves anything.

import { randomUUID } from 'node:crypto'
import { getProfile } from '../connectors/profiles.js'
import * as sitesMod from '../core/sites.js'
import { VaultError } from '../core/errors.js'
import { proposalOf as srProposal } from './session-requests.js'

export const PROTOCOL_VERSIONS = ['2025-06-18', '2025-03-26']
export const LATEST_PROTOCOL = PROTOCOL_VERSIONS[0]

const SERVER_INFO = { name: 'agent-vault', version: '0.1.0' }

const INSTRUCTIONS = [
  'Credentials are placeholders, never real secrets. Never ask the user for a real secret.',
  'Prefer vault_http for API calls; use vault_get_placeholder only for tools that must run natively.',
  'Put a placeholder only where the usage field says. A placeholder anywhere else is refused.',
  'On AV_PH_EXHAUSTED or AV_PH_STALE, call vault_get_placeholder again and retry.',
  'On a denial, call vault_explain_denial with the request_id to learn the rule and the allowed alternatives.',
].join(' ')

export class McpServer {
  /**
   * @param {import('../store/vault.js').Vault} vault
   * @param {import('./pipeline.js').Pipeline} pipeline
   * @param {() => object|null} resolveSession  returns the session for this transport
   */
  constructor(vault, pipeline, resolveSession, daemon = null) {
    // The daemon owns the session-request store, because a request outlives any
    // one MCP connection: the human answers it in their own time.
    this.daemon = daemon
    this.vault = vault
    this.pipeline = pipeline
    this.resolveSession = resolveSession
    this.sessions = new Map() // Mcp-Session-Id -> { created, lastEventId, events: [] }
  }

  /** Create an MCP transport session. It is a routing key, never a credential. */
  openSession() {
    const sid = randomUUID()
    this.sessions.set(sid, { created: Date.now(), events: [], nextEventId: 1 })
    this.vault.audit?.write('mcp.session_opened', { mcp_session_id: sid })
    return sid
  }

  closeSession(sid) {
    if (this.sessions.delete(sid)) this.vault.audit?.write('mcp.session_closed', { mcp_session_id: sid })
  }

  hasSession(sid) { return this.sessions.has(sid) }

  get tools() {
    return [
      {
        name: 'vault_status',
        description: 'Whether the vault is reachable and unlocked, and a summary of the current session.',
        inputSchema: { type: 'object', properties: {} },
      },
      {
        name: 'vault_list_creds',
        description: 'Credentials this session may use, with the exact place a placeholder goes for each.',
        inputSchema: { type: 'object', properties: { available_only: { type: 'boolean' } } },
      },
      {
        name: 'vault_get_placeholder',
        description: 'Get a placeholder for a credential. Returns the placeholder plus where to put it.',
        inputSchema: {
          type: 'object',
          properties: {
            cred: { type: 'string', description: 'credential slug' },
            reason: { type: 'string', description: 'why you need it; shown to the human as an unverified claim' },
            uses: { type: 'number', description: 'optional: make it n-use instead of session-lifetime' },
          },
          required: ['cred', 'reason'],
        },
      },
      {
        name: 'vault_request_session',
        description: 'Ask a human for a session. This creates nothing by itself: it opens a request a human must approve, and they may narrow it first. Poll the returned id until they answer. Two error paths already tell you to call this.',
        inputSchema: {
          type: 'object',
          properties: {
            cred: { type: 'string', description: 'credential slug' },
            reason: { type: 'string', description: 'why you need it; shown to the human as an unverified claim' },
            methods: { type: 'array', items: { type: 'string' }, description: 'ask for the least you need' },
            paths: { type: 'array', items: { type: 'string' } },
            budget: { type: 'number', description: 'how many requests' },
            // Without this an agent could not ask for a short session even when
            // it wanted one, so every request took the eight-hour default and
            // the human was shown no lifetime at all to narrow.
            ttl_minutes: { type: 'number', description: 'how long you need it for; ask for the least you need' },
            poll_id: { type: 'string', description: 'an id from an earlier call: check whether it has been answered' },
          },
          required: ['reason'],
        },
      },
      {
        name: 'vault_approval_status',
        description: 'Whether a human has answered a held request. The 202 from a held write names this tool and the id to pass.',
        inputSchema: {
          type: 'object',
          properties: {
            approval_id: { type: 'string', description: 'the approval_id from the 202' },
          },
          required: ['approval_id'],
        },
      },
      {
        name: 'vault_http',
        description: 'Make an HTTP request through the vault. The credential is injected by the daemon; you never handle it.',
        inputSchema: {
          type: 'object',
          properties: {
            cred: { type: 'string' },
            method: { type: 'string' },
            path: { type: 'string' },
            query: { type: 'string' },
            headers: { type: 'object' },
            body: { type: 'string' },
            reason: { type: 'string' },
          },
          required: ['cred', 'method', 'path', 'reason'],
        },
      },
      {
        name: 'vault_explain_denial',
        description: 'Explain why a request was denied and what this session is allowed to do instead.',
        inputSchema: { type: 'object', properties: { request_id: { type: 'string' } }, required: ['request_id'] },
      },
    ]
  }

  /** Handle one JSON-RPC message. Returns a response object, or null for notifications. */
  /**
   * @param {object} message a JSON-RPC message
   * @param {object|null} [forSession] the session this message belongs to.
   *   Passed explicitly because the HTTP transport handles a batch in a loop
   *   with an `await` in it, and reading the session from shared state across
   *   that await let a concurrent request swap it mid-batch: one agent's
   *   second call ran as another agent's session.
   */
  async handle(message, forSession, forToken) {
    const { id, method, params } = message
    // Resolved once, here, and then carried explicitly. Reading it again
    // deeper in would reintroduce the race this parameter exists to close.
    const session = forSession !== undefined ? forSession : this.resolveSession()
    // The token travels with the message too, for exactly the reason the
    // session does. It was a field on this object, set per HTTP request, so a
    // concurrent request overwrote it between two messages of the same batch
    // and the rest of the batch authenticated as somebody else. Fixing the
    // session and leaving the token behind fixed half a race.
    const token = forToken !== undefined ? forToken : this.sessionToken
    const ok = (result) => (id === undefined ? null : { jsonrpc: '2.0', id, result })
    const fail = (code, msg, data) => (id === undefined ? null : { jsonrpc: '2.0', id, error: { code, message: msg, data } })

    try {
      switch (method) {
        case 'initialize':
          return ok({
            protocolVersion: PROTOCOL_VERSIONS.includes(params?.protocolVersion) ? params.protocolVersion : LATEST_PROTOCOL,
            capabilities: { tools: { listChanged: false }, resources: { listChanged: false } },
            serverInfo: SERVER_INFO,
            instructions: INSTRUCTIONS,
          })
        case 'notifications/initialized':
          return null
        case 'ping':
          return ok({})
        case 'tools/list':
          return ok({ tools: this.tools })
        case 'resources/list':
          return ok({ resources: [{ uri: 'agent-vault://session', name: 'Current session', mimeType: 'application/json' }] })
        case 'resources/read':
          return ok({ contents: [{ uri: params.uri, mimeType: 'application/json', text: JSON.stringify(this.#status(session, token), null, 2) }] })
        case 'tools/call':
          return ok(await this.#callTool(params?.name, params?.arguments || {}, session, token))
        default:
          return fail(-32601, `unknown method: ${method}`)
      }
    } catch (e) {
      if (e instanceof VaultError) {
        return ok({
          isError: true,
          content: [{ type: 'text', text: JSON.stringify({ code: e.code, detail: e.detail, hint: e.hint, next: e.next }, null, 2) }],
        })
      }
      return fail(-32603, e.message)
    }
  }

  #status(session, token) {
    return {
      daemon: 'agent-vault', version: SERVER_INFO.version,
      locked: this.vault.locked,
      session: session ? { id: session.id, label: session.label, expires_at: session.expires_at } : null,
      // Why there is no session, when there is none. This is the tool an agent
      // reaches for when something stopped working, and "session: null" does
      // not distinguish never-had-one from expired-an-hour-ago.
      session_problem: session ? null : this.#sessionProblem(token),
      credentials_available: session ? this.vault.grantsForSession(session.id).length : 0,
    }
  }

  /**
   * Why the token on this connection does not yield a live session.
   *
   * Resolved from the token that travels WITH the message, never from shared
   * state: the same race that made `handle` take the session and token as
   * parameters would otherwise report one agent's expiry to another.
   */
  #sessionProblem(token) {
    if (!token) return 'no session token was sent with this connection'
    const found = this.vault.sessionByToken(token)
    if (!found) return 'that session token is not recognised; it may belong to a vault that was reset'
    try { this.vault.assertSessionLive(found); return null } catch (e) { return e.detail || e.message }
  }

  /**
   * A refusal the caller can see as a refusal.
   *
   * `isError` is how MCP marks a failed tool call, and a client that does not
   * read it still gets the reason in the text. Returning a plain result would
   * make "you have no session" look like an answer.
   */
  #needsSession(token) {
    return {
      isError: true,
      content: [{
        type: 'text',
        text: JSON.stringify({
          error: 'this tool needs a live session',
          detail: this.#sessionProblem(token),
          next: 'call vault_request_session to ask a human for one, or ask them to run: agent-vault session create --cred <slug>',
        }, null, 2),
      }],
    }
  }

  async #callTool(name, args, session, token) {
    const text = (v) => ({ content: [{ type: 'text', text: typeof v === 'string' ? v : JSON.stringify(v, null, 2) }] })

    switch (name) {
      case 'vault_status':
        return text(this.#status(session, token))

      case 'vault_list_creds': {
        if (!session) return this.#needsSession(token)
        const out = this.vault.grantsForSession(session.id).map((g) => {
          const cred = this.vault.db.credentials[g.credential_id]
          const profile = getProfile(cred.connector_kind)
          return {
            slug: cred.slug,
            kind: cred.connector_kind,
            base_url: `/p/${cred.slug}`,
            allowed: { methods: g.policy?.methods, paths: g.policy?.paths, hosts: g.policy?.hosts },
            budget_remaining: (g.policy?.budget?.limit ?? 0) - g.budget_used,
            usage: cred.fields.map((f) => ({
              field: f.name,
              put_placeholder_at: f.sites.map((s) => sitesMod.describeSite(sitesMod.parseSite(s))),
            })),
            profile_denies: profile.deny_paths.slice(0, 5),
          }
        })
        return text(out)
      }

      case 'vault_request_session': {
        // Asking is not getting. Nothing exists until a human answers, which
        // is why this is the one capability-shaped tool an agent may call.
        if (args.poll_id) {
          const record = this.daemon?.sessionRequests?.get(args.poll_id)
          if (!record) return text({ error: `no session request ${args.poll_id}` })
          if (record.state === 'pending') {
            return text({ state: 'pending', detail: 'a human has not answered yet; poll again or carry on without it' })
          }
          if (record.state === 'denied') return text({ state: 'denied', detail: 'a human declined; do not ask again for the same thing' })
          if (!record.result) {
            // The human's own client collected it when they approved — the
            // daemon cannot write their state file, so whichever client they
            // answered with does, and the bridge reads that file on every
            // request. So the session is already live for this agent; there is
            // nothing to hand over and nothing wrong.
            if (record.state === 'collected') {
              return text({
                state: 'approved',
                detail: 'a human approved this and your session is already active — the bridge found it. Call vault_status to see it, and use the tools normally.',
              })
            }
            return text({ state: record.state, detail: 'the answer is no longer available; ask again' })
          }
          const result = record.result
          record.result = null
          record.state = 'collected'
          this.daemon.sessionRequests.persist()
          this.vault.audit?.write('session_request.collected', { request_id: record.id, via: 'mcp' })
          return text({
            state: 'approved',
            detail: 'a human approved this, possibly narrower than you asked. Use what you were given.',
            ...result,
          })
        }
        if (!this.daemon?.sessionRequests) return text({ error: 'session requests are not available on this daemon' })
        if (!args.cred) return text({ error: 'name the credential you need', known: this.vault.listCredentials().map((c) => c.slug) })
        try {
          const record = this.daemon.sessionRequests.propose({
            proposal: srProposal({ cred: args.cred, methods: args.methods, paths: args.paths, budget: args.budget }),
            reason: args.reason,
          })
          return text({
            state: 'pending',
            request_id: record.id,
            asked_for: record.summary,
            detail: 'a human must approve this. Poll with vault_request_session { poll_id }. They may narrow it.',
          })
        } catch (e) {
          return text({ error: e.message })
        }
      }

      case 'vault_get_placeholder': {
        if (!session) return this.#needsSession(token)
        const cred = this.vault.findCredential(args.cred)
        if (!cred) return text({ error: `no credential ${args.cred}`, known: this.vault.listCredentials().map((c) => c.slug) })
        const grant = this.vault.grantsForSession(session.id).find((g) => g.credential_id === cred.id)
        if (!grant) return text({ error: `this session has no grant for ${args.cred}` })
        const field = cred.fields[0]
        // The grant's ceiling wins over whatever the agent asks for.
        const ceiling = grant.policy?.placeholder_policy?.max_uses
        const asked = args.uses ?? null
        const uses = ceiling == null ? asked : Math.min(asked ?? ceiling, ceiling)
        const { placeholder } = this.vault.issuePlaceholder({ grantId: grant.id, field: field.name, uses })
        this.vault.audit.write('placeholder.issued_via_mcp', { credential_slug: cred.slug, agent_reason_untrusted: args.reason })
        return text({
          placeholder,
          usage: {
            put_it_at: field.sites.map((s) => sitesMod.describeSite(sitesMod.parseSite(s), placeholder)),
            url: `/p/${cred.slug}/<path>`,
            warning: 'A placeholder anywhere other than the site above is refused and audited.',
          },
        })
      }

      case 'vault_approval_status': {
        if (!session) return this.#needsSession(token)
        const status = this.pipeline.approvalStatus(args.approval_id)
        if (!status) return text({ error: `no approval ${args.approval_id}`, detail: 'it may have expired, or already been spent' })
        return text(status)
      }

      case 'vault_http': {
        if (!session) return this.#needsSession(token)
        const cred = this.vault.findCredential(args.cred)
        if (!cred) return text({ error: `no credential ${args.cred}` })
        const grant = this.vault.grantsForSession(session.id).find((g) => g.credential_id === cred.id)
        if (!grant) return text({ error: `this session has no grant for ${args.cred}` })
        const field = cred.fields[0]
        const { placeholder } = this.vault.issuePlaceholder({ grantId: grant.id, field: field.name })

        // The MCP path runs the identical pipeline: same policy, same site
        // check, same scrubber, same audit. Only the framing differs.
        const site = sitesMod.parseSite(field.sites[0])
        const headers = [['host', '127.0.0.1']]
        for (const [k, v] of Object.entries(args.headers || {})) {
          // The daemon sets its own av-* headers below. Letting the caller
          // supply them first meant an agent's value shadowed the real one and
          // the request failed as unauthenticated — confusing, and not
          // something a tool argument should be able to reach.
          if (/^av-/i.test(k) || k.toLowerCase() === 'host') continue
          headers.push([k, v])
        }
        if (site.kind === 'header') {
          headers.push([site.name, site.scheme ? `${site.scheme} ${placeholder}` : placeholder])
        }
        headers.push(['av-session', this.#tokenFor(session)])
        if (args.reason) headers.push(['av-reason', args.reason])
        // The caller's own content-type was already forwarded above, in
        // whatever case they wrote it. Adding a default alongside a
        // `Content-Type` sent two, and a form-encoded body went upstream
        // labelled as JSON as well.
        const callerSetType = Object.keys(args.headers || {}).some((k) => k.toLowerCase() === 'content-type')
        if (args.body && !callerSetType) headers.push(['content-type', 'application/json'])

        const res = await this.pipeline.handle({
          method: args.method, path: `/p/${cred.slug}${args.path}`, query: args.query || '',
          headers, body: args.body ? Buffer.from(args.body) : null,
        })
        return text({
          status: res.status,
          request_id: res.requestId,
          decision: res.headers['av-decision'],
          headers: res.headers,
          body: res.body.toString('utf8').slice(0, 256 * 1024),
        })
      }

      case 'vault_explain_denial': {
        const rows = this.vault.audit.read({ limit: 200 }).filter((r) => r.request_id === args.request_id)
        if (!rows.length) return text({ error: `no record of request ${args.request_id}` })
        const denial = rows.find((r) => r.decision === 'deny') || rows[rows.length - 1]
        return text({
          request_id: args.request_id,
          decision: denial.decision,
          code: denial.reason_code,
          rule: denial.rule,
          detail: denial.detail,
          allowed_here: session ? this.vault.grantsForSession(session.id).map((g) => g.policy) : [],
        })
      }

      default:
        return text({ error: `unknown tool ${name}` })
    }
  }

  /** The MCP process holds the session token it was started with. */
  #tokenFor(session, token) { return token || session?.__token || '' }
}

/** Frame the MCP server onto stdio: newline-delimited JSON-RPC. */
export function serveStdio(server, input = process.stdin, output = process.stdout) {
  let buffer = ''
  input.setEncoding('utf8')
  input.on('data', async (chunk) => {
    buffer += chunk
    let nl
    while ((nl = buffer.indexOf('\n')) !== -1) {
      const line = buffer.slice(0, nl).trim()
      buffer = buffer.slice(nl + 1)
      if (!line) continue
      let message
      try { message = JSON.parse(line) } catch { continue }
      const response = await server.handle(message)
      if (response) output.write(`${JSON.stringify(response)}\n`)
    }
  })
}
