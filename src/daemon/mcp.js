// MCP, implemented once and exposed over two transports.
//
// The tools live here, in the daemon, and both `agent-vault mcp` (stdio) and
// POST /mcp (Streamable HTTP) drive this same handler. One implementation is
// the point: if the transports had separate code, they would drift, and the
// drift would be in policy evaluation and scrubbing rather than in framing.
//
// No tool returns a secret, creates a credential, approves anything, or
// changes a policy.

import { randomUUID } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { getProfile } from '../connectors/profiles.js'
import * as sitesMod from '../core/sites.js'
import * as policyMod from '../core/policy.js'
import { VaultError } from '../core/errors.js'
import { expiryWarning } from '../store/vault.js'
import { SessionRequests, OWNER_FIELDS, templateCreds, templateSummary, grantSpecsOf } from './session-requests.js'

export const PROTOCOL_VERSIONS = ['2025-06-18', '2025-03-26']
export const LATEST_PROTOCOL = PROTOCOL_VERSIONS[0]

// The same version the daemon reports, read from package.json rather than
// written here, so an MCP client is never told a version the code is not.
const SERVER_INFO = {
  name: 'agent-vault',
  version: (() => {
    try {
      return JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf8')).version
    } catch {
      return '0.0.0-unknown'
    }
  })(),
}

// Transport sessions held at once. Each is a few bytes; the bound is what
// matters, not the number.
const MAX_MCP_SESSIONS = 256

const INSTRUCTIONS = [
  'Credentials are placeholders, never real secrets. Never ask the user for a real secret.',
  'Prefer vault_http for API calls; use vault_get_placeholder only for tools that must run natively.',
  'Put a placeholder only where the usage field says. A placeholder anywhere else is refused.',
  'On AV_PH_EXHAUSTED or AV_PH_STALE, call vault_get_placeholder again and retry.',
  'On a denial, call vault_explain_denial with the request_id to learn the rule and the allowed alternatives.',
  'Before a write you are unsure of, call vault_preflight; to learn your limits, call vault_describe_access.',
].join(' ')

// What vault_request_session forwards. Everything else an agent sends is not
// part of what it asked for; `approval` and `infinite` are refused outright.
const REQUEST_ARGS = ['cred', 'methods', 'paths', 'budget', 'uses', 'ttl_minutes', 'routes', 'grant_ttl_minutes', 'template', 'reason']

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

  /**
   * Create an MCP transport session. It is a routing key, never a credential.
   *
   * Bounded, oldest first: `initialize` needs no session token, so nothing
   * else limits how many of these a caller can open, and the map had no size
   * limit and no expiry. An evicted client gets AV_MCP_SESSION_UNKNOWN and
   * initializes again, which is what the protocol expects.
   */
  openSession({ record = true } = {}) {
    while (this.sessions.size >= MAX_MCP_SESSIONS) {
      const oldest = this.sessions.keys().next().value
      if (oldest === undefined) break
      this.sessions.delete(oldest)
    }
    const sid = randomUUID()
    // Whether it was recorded is kept with it, so the close can match.
    this.sessions.set(sid, { created: Date.now(), events: [], nextEventId: 1, recorded: !!record })
    if (record) this.vault.audit?.write('mcp.session_opened', { mcp_session_id: sid })
    return sid
  }

  /**
   * Forget a transport session. Recorded when its opening was, or when the
   * caller closing it has a live session. Always recording it undid the quiet
   * anonymous initialize: closing needs no token either, so initialize and
   * DELETE in a loop wrote a record per cycle while holding no memory at all.
   */
  closeSession(sid, { record = false } = {}) {
    const entry = this.sessions.get(sid)
    if (!entry) return
    this.sessions.delete(sid)
    if (entry.recorded || record) this.vault.audit?.write('mcp.session_closed', { mcp_session_id: sid })
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
            uses: { type: 'number', description: 'optional: n-use placeholders instead of session-lifetime ones' },
            grant_ttl_minutes: { type: 'number', description: 'how long the access itself is needed, if shorter than the session' },
            routes: {
              type: 'array',
              description: 'optional: method-bound routes, each a set of methods allowed only on these paths',
              items: {
                type: 'object',
                properties: { methods: { type: 'array', items: { type: 'string' } }, paths: { type: 'array', items: { type: 'string' } } },
                required: ['methods', 'paths'],
              },
            },
            template: { type: 'string', description: 'a template name the human saved; they see the template, not a policy to read' },
            poll_id: { type: 'string', description: 'an id from an earlier call: check whether it has been answered' },
            poll_secret: { type: 'string', description: 'the poll_secret that earlier call returned; only the asker can poll' },
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
        description: 'Explain why a request this session made was denied and what this session is allowed to do instead. The code and rule are always given; the full sentence is kept for an hour (the last 1000 denials) and is null after that, after the daemon restarts, or for a caller with no session.',
        inputSchema: { type: 'object', properties: { request_id: { type: 'string' } }, required: ['request_id'] },
      },
      {
        name: 'vault_describe_access',
        description: 'What this session may do right now: hosts, methods, paths, approval mode, budgets and limits, lifetimes, and where each placeholder goes.',
        inputSchema: { type: 'object', properties: {} },
      },
      {
        name: 'vault_preflight',
        description: 'Check whether a request would be allowed, held for a human, or refused, without sending it or spending anything. Advisory only.',
        inputSchema: {
          type: 'object',
          properties: {
            cred: { type: 'string', description: 'credential slug' },
            method: { type: 'string' },
            path: { type: 'string', description: 'the upstream path, as for vault_http' },
            query: { type: 'string' },
            headers: { type: 'object' },
            body: { type: 'string' },
          },
          required: ['cred', 'method', 'path'],
        },
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
   * @param {string} [forToken] the session token this message arrived with
   * @param {object|null} [forListener] the network listener it arrived on, or
   *   null for the machine itself (stdio, the built-in gateway). It travels
   *   with the message for the same reason, and every tool asks the vault
   *   whether the session is usable on it.
   */
  async handle(message, forSession, forToken, forListener = null) {
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
    const listener = forListener
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
          return ok({ contents: [{ uri: params.uri, mimeType: 'application/json', text: JSON.stringify(this.#status(session, token, listener), null, 2) }] })
        case 'tools/call':
          return ok(await this.#callTool(params?.name, params?.arguments || {}, session, token, listener))
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

  #status(session, token, listener) {
    return {
      daemon: 'agent-vault', version: SERVER_INFO.version,
      locked: this.vault.locked,
      session: session
        ? { id: session.id, label: session.label, expires_at: session.expires_at ?? null, infinite: session.infinite === true }
        : null,
      // Why there is no session, when there is none. This is the tool an agent
      // reaches for when something stopped working, and "session: null" does
      // not distinguish never-had-one from expired-an-hour-ago.
      session_problem: session ? null : this.#sessionProblem(token, listener, { record: false })?.detail ?? null,
      credentials_available: session ? this.vault.grantsForSession(session.id).length : 0,
      // Shapes a human saved, so an agent can ask by name (F17).
      templates: this.#templates(),
    }
  }

  /** Single-credential templates, as an agent may ask for them. Names and summaries only. */
  #templates() {
    try {
      return (this.vault.listTemplates?.() || [])
        .filter((t) => templateCreds(t.spec).length === 1 && grantSpecsOf(t.spec).length === 1)
        .map((t) => ({ name: t.name, cred: templateCreds(t.spec)[0], summary: templateSummary(t.spec) }))
    } catch { return [] }
  }

  /**
   * A refusal as a tool result: `{ error, code, rule?, hint? }`, the shape
   * every tool error has (0.8), never a JSON-RPC error.
   */
  #refusal(e) {
    const body = { error: e.detail || e.message, code: e.code }
    if (e.rule) body.rule = e.rule
    if (e.hint) body.hint = e.hint
    if (e.retryAfter !== undefined) body.retry_after = e.retryAfter
    return { isError: true, content: [{ type: 'text', text: JSON.stringify(body, null, 2) }] }
  }

  /**
   * The session's grant for a credential, or the refusal to give instead:
   * a grant whose own lifetime ran out (F18) says so, with its own code.
   */
  #grantFor(session, cred) {
    const grant = this.vault.grantsForSession(session.id).find((g) => g.credential_id === cred.id)
    if (grant) return { grant }
    const last = this.vault.findGrant?.(session.id, cred.id)
    if (last?.state === 'expired') {
      return {
        refused: this.#refusal({
          code: 'AV_GRANT_EXPIRED', detail: `this session's grant for ${cred.slug} expired`,
          hint: "This grant's lifetime ran out; the session may still hold others. Ask a human for a new grant.",
        }),
      }
    }
    return { refused: { content: [{ type: 'text', text: JSON.stringify({ error: `this session has no grant for ${cred.slug}` }, null, 2) }] } }
  }

  /**
   * Why the token on this connection does not yield a session usable here,
   * as `{ detail, error }`, or null when it does. `error` is the vault's
   * refusal, when there is one. A C12 refusal is recorded unless `record`
   * is false: asking why is not a use, so vault_status records nothing.
   *
   * Resolved from the token and listener that travel WITH the message, never
   * from shared state: the same race that made `handle` take the session and
   * token as parameters would otherwise report one agent's expiry to another.
   */
  #sessionProblem(token, listener, { record = true } = {}) {
    if (!token) return { detail: 'no session token was sent with this connection' }
    const found = this.vault.sessionByToken(token)
    if (!found) return { detail: 'that session token is not recognised; it may belong to a vault that was reset' }
    try {
      this.vault.assertSessionUsable(found, listener, { record })
      return null
    } catch (e) {
      return { detail: e.detail || e.message, error: e instanceof VaultError ? e : null }
    }
  }

  /**
   * A refusal the caller can see as a refusal.
   *
   * `isError` is how MCP marks a failed tool call, and a client that does not
   * read it still gets the reason in the text. Returning a plain result would
   * make "you have no session" look like an answer. A session this listener
   * may not use (C12) is refused as that, with its code and rule.
   */
  #needsSession(token, listener) {
    const problem = this.#sessionProblem(token, listener)
    if (problem?.error?.code === 'AV_REMOTE_FORBIDDEN') {
      const e = problem.error
      return {
        isError: true,
        content: [{ type: 'text', text: JSON.stringify({ code: e.code, rule: e.rule, detail: e.detail, hint: e.hint }, null, 2) }],
      }
    }
    return {
      isError: true,
      content: [{
        type: 'text',
        text: JSON.stringify({
          error: 'this tool needs a live session',
          detail: problem?.detail ?? null,
          next: 'call vault_request_session to ask a human for one, or ask them to run: agent-vault session create --cred <slug>',
        }, null, 2),
      }],
    }
  }

  async #callTool(name, args, session, token, listener) {
    const text = (v) => ({ content: [{ type: 'text', text: typeof v === 'string' ? v : JSON.stringify(v, null, 2) }] })

    switch (name) {
      case 'vault_status':
        return text(this.#status(session, token, listener))

      case 'vault_list_creds': {
        if (!session) return this.#needsSession(token, listener)
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
            // So an agent can tell the human before a long task (F10), stop
            // trying a stopped credential (F16), and see a grant's own end (F18).
            expiry_warning: expiryWarning(cred),
            quarantined: !!cred.quarantine,
            expires_at: g.expires_at ?? null,
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
          // The id is listed to anyone on the control socket; the secret went
          // only to whoever asked. Without this check another agent could poll
          // the request and collect the session meant for the asker.
          if (!SessionRequests.mayCollect(record, args.poll_secret)) {
            return text({ error: 'poll_secret does not match this request; only the agent that asked can poll it' })
          }
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
        // Refused, not dropped: an agent that sent one must not believe it
        // asked for it. Only the owner sets these.
        const owned = OWNER_FIELDS.filter((f) => Object.hasOwn(args, f))
        if (owned.length) {
          return this.#refusal({
            code: 'AV_POLICY_DENIED', rule: 'owner_only_field', detail: `a session request cannot carry ${owned.join(' or ')}`,
            hint: 'Only the owner can choose the approval mode or an unlimited lifetime. Ask without it and say why in reason.',
          })
        }
        if (!args.cred && !args.template) {
          return text({ error: 'name the credential you need, or a template', known: this.vault.listCredentials().map((c) => c.slug), templates: this.#templates() })
        }
        try {
          // The daemon's one proposer, the same the HTTP route uses. Only the
          // arguments this tool offers are forwarded.
          const asked = Object.fromEntries(REQUEST_ARGS.filter((k) => args[k] !== undefined && args[k] !== null).map((k) => [k, args[k]]))
          const { record, collectSecret } = this.daemon.proposeSessionRequest(asked)
          return text({
            state: 'pending',
            request_id: record.id,
            poll_secret: collectSecret,
            asked_for: record.summary,
            detail: 'a human must approve this. Poll with vault_request_session { poll_id: request_id, poll_secret }. They may narrow it.',
          })
        } catch (e) {
          if (e instanceof VaultError) return this.#refusal(e)
          return text({ error: e.message })
        }
      }

      case 'vault_get_placeholder': {
        if (!session) return this.#needsSession(token, listener)
        const cred = this.vault.findCredential(args.cred)
        if (!cred) return text({ error: `no credential ${args.cred}`, known: this.vault.listCredentials().map((c) => c.slug) })
        const { grant, refused } = this.#grantFor(session, cred)
        if (refused) return refused
        const field = cred.fields[0]
        // The grant's ceiling wins over whatever the agent asks for.
        const ceiling = grant.policy?.placeholder_policy?.max_uses
        const asked = args.uses ?? null
        const uses = ceiling == null ? asked : Math.min(asked ?? ceiling, ceiling)
        let placeholder
        try {
          ({ placeholder } = this.vault.issuePlaceholder({ grantId: grant.id, field: field.name, uses }))
        } catch (e) {
          // An expired grant (F18) or a quarantined credential (F16), with
          // its own code, so the agent knows which.
          if (e instanceof VaultError) return this.#refusal(e)
          throw e
        }
        this.vault.audit.write('placeholder.issued_via_mcp', { credential_slug: cred.slug, agent_reason_untrusted: this.vault.untrustedText(args.reason) })
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
        if (!session) return this.#needsSession(token, listener)
        const status = this.pipeline.approvalStatus(args.approval_id)
        if (!status) return text({ error: `no approval ${args.approval_id}`, detail: 'it may have expired, or already been spent' })
        return text(status)
      }

      case 'vault_http': {
        if (!session) return this.#needsSession(token, listener)
        const cred = this.vault.findCredential(args.cred)
        if (!cred) return text({ error: `no credential ${args.cred}` })
        const { grant, refused } = this.#grantFor(session, cred)
        if (refused) return refused
        const field = cred.fields[0]
        const site = sitesMod.parseSite(field.sites[0])
        // Minted for this one call and burned after it. Each call used to
        // leave its placeholder active, and a used one is never evicted, so
        // the ledger grew by a live row per request.
        let placeholder, row
        try {
          ({ placeholder, row } = this.vault.issuePlaceholder({ grantId: grant.id, field: field.name }))
        } catch (e) {
          if (e instanceof VaultError) return this.#refusal(e)
          throw e
        }

        // The MCP path runs the identical pipeline: same policy, same site
        // check, same scrubber, same audit. Only the framing differs.
        const headers = [['host', '127.0.0.1']]
        for (const [k, v] of Object.entries(args.headers || {})) {
          // The daemon sets its own av-* headers below. Letting the caller
          // supply them first meant an agent's value shadowed the real one and
          // the request failed as unauthenticated — confusing, and not
          // something a tool argument should be able to reach.
          if (/^av-/i.test(k) || k.toLowerCase() === 'host') continue
          headers.push([k, v])
        }
        let query = args.query || ''
        if (site.kind === 'header') {
          headers.push([site.name, site.scheme ? `${site.scheme} ${placeholder}` : placeholder])
        } else if (site.kind === 'query') {
          // The placeholder grammar is URL-safe, so it needs no encoding.
          query = `${query ? `${query}&` : ''}${encodeURIComponent(site.key)}=${placeholder}`
        }
        // The token this call arrived with. `#tokenFor` was called without it,
        // and nothing ever sets `session.__token`, so this header was always
        // empty: every call authenticated by falling back on the placeholder
        // as carrier, which only a header site allows.
        headers.push(['av-session', this.#tokenFor(session, token)])
        if (args.reason) headers.push(['av-reason', args.reason])
        // The caller's own content-type was already forwarded above, in
        // whatever case they wrote it. Adding a default alongside a
        // `Content-Type` sent two, and a form-encoded body went upstream
        // labelled as JSON as well.
        const callerSetType = Object.keys(args.headers || {}).some((k) => k.toLowerCase() === 'content-type')
        if (args.body && !callerSetType) headers.push(['content-type', 'application/json'])

        let res
        let body
        try {
          res = await this.pipeline.handle({
            method: args.method, path: `/p/${cred.slug}${args.path}`, query,
            headers, body: args.body ? Buffer.from(args.body) : null,
            // The listener this call arrived on, so the pipeline's own
            // usability check fires here too, as it does on /p/.
            listener,
          })
          // A streamed (text/event-stream) response has no `body`, only a
          // `stream`, and reading `body` threw after the request had run and
          // been charged — leaving the upstream connection open, and an agent
          // retrying an "internal error" that had in fact succeeded.
          body = res.stream ? await readBounded(res.stream, MAX_TOOL_BODY) : res.body.toString('utf8').slice(0, MAX_TOOL_BODY)
        } finally {
          // A vault locked mid-call cannot record the burn, and the lock
          // already stops the row from being used; the call's own outcome is
          // what the agent needs to see.
          const live = this.vault.db.placeholders[row.id]
          if (live?.state === 'active' && !this.vault.locked) this.vault.burnPlaceholder(row.id, 'spent')
        }
        return text({
          status: res.status,
          request_id: res.requestId,
          decision: res.headers['av-decision'],
          headers: res.headers,
          body,
        })
      }

      case 'vault_explain_denial': {
        // Only the caller's own requests: a request made with no session is
        // explained only to a caller with none.
        const mine = (r) => (r.session_id ?? null) === (session?.id ?? null)
        // That request's records from the whole log, not a recent slice: the
        // code and rule outlive any later traffic, an eviction and a restart.
        const rows = typeof args.request_id === 'string'
          ? this.vault.audit.read({ requestId: args.request_id, limit: 100 }).filter(mine) : []
        if (!rows.length) return text({ error: `no record of request ${args.request_id}` })
        const denial = rows.find((r) => r.decision === 'deny') || rows[rows.length - 1]
        // The record holds the code and the rule (C28). The sentence is kept
        // in memory for a while, and is null after a restart. Never to a
        // caller with no session: every such caller looks the same, so an
        // anonymous denial may have been another agent's.
        const said = session ? this.pipeline.explainDenial(args.request_id, session.id) : null
        return text({
          request_id: args.request_id,
          decision: denial.decision,
          code: denial.reason_code,
          rule: denial.rule,
          detail: said?.detail ?? null,
          ...(said?.hint ? { hint: said.hint } : {}),
          allowed_here: session ? this.vault.grantsForSession(session.id).map((g) => g.policy) : [],
        })
      }

      case 'vault_describe_access': {
        if (!session) return this.#needsSession(token, listener)
        // Usable here, on this listener (C18). A peek: describing records
        // nothing and changes nothing.
        try { this.vault.assertSessionUsable(session, listener, { peek: true }) } catch (e) {
          if (e instanceof VaultError) return this.#refusal(e)
          throw e
        }
        return text(this.#describeAccess(session))
      }

      case 'vault_preflight': {
        if (!session) return this.#needsSession(token, listener)
        // Usability on this listener (C18) is asked by the pipeline, which
        // authenticates the preflight exactly as a real request, as a peek:
        // the listener goes with the call below, as it does for vault_http.
        const shape = (detail) => this.#refusal({ code: 'AV_POLICY_DENIED', rule: 'preflight_shape', detail })
        if (typeof args.cred !== 'string' || !args.cred) return shape('cred is a credential slug')
        if (typeof args.method !== 'string' || !/^[A-Za-z]{1,16}$/.test(args.method)) return shape('method is an HTTP method name')
        if (typeof args.path !== 'string' || !args.path.startsWith('/')) return shape('path is the upstream path, starting with /')
        if (args.query != null && typeof args.query !== 'string') return shape('query is a string')
        if (args.body != null && typeof args.body !== 'string') return shape('body is a string')
        if (args.headers != null && (typeof args.headers !== 'object' || Array.isArray(args.headers))) return shape('headers is an object')
        const cred = this.vault.findCredential(args.cred)
        if (!cred) return this.#refusal({ code: 'AV_NOT_FOUND', detail: `no credential ${args.cred}` })
        const headers = [['host', '127.0.0.1']]
        for (const [k, v] of Object.entries(args.headers || {})) {
          if (/^av-/i.test(k) || k.toLowerCase() === 'host') continue
          headers.push([k, String(v)])
        }
        headers.push(['av-session', this.#tokenFor(session, token)])
        try {
          return text(await this.pipeline.preflight({
            method: args.method.toUpperCase(), path: `/p/${cred.slug}${args.path}`, query: args.query || '',
            headers, body: args.body ? Buffer.from(args.body) : null,
            // The listener this call arrived on, so the pipeline asks the
            // same usability question a real request would.
            listener,
          }, { assumePlaceholder: true }))
        } catch (e) {
          if (e instanceof VaultError) return this.#refusal(e)
          throw e
        }
      }

      default:
        return text({ error: `unknown tool ${name}` })
    }
  }

  /**
   * What a session may do (F20). Policy, limits, lifetimes and where a
   * placeholder goes; never a token, a placeholder, a fingerprint or a size.
   */
  #describeAccess(session) {
    const grants = this.vault.grantsForSession(session.id).map((g) => {
      const cred = this.vault.db.credentials[g.credential_id]
      const profile = getProfile(cred.connector_kind)
      const effective = policyMod.intersect([profile.policyCeiling, session.policy, g.policy])
      const limit = policyMod.budgetLimit(effective.budget)
      const used = Number.isSafeInteger(g.budget_used) ? g.budget_used : 0
      let spend = null
      try {
        const s = this.pipeline.spendFor(g.id)
        if (s) {
          spend = {}
          if (s.limit_tokens != null) spend.tokens = Math.max(0, s.limit_tokens - s.tokens_used - s.reserved_tokens)
          if (s.limit_usd_micros != null) spend.usd_micros = Math.max(0, s.limit_usd_micros - s.usd_micros_used - s.reserved_usd_micros)
        }
      } catch {
        // An unreadable spend state refuses every metered call.
        spend = { tokens: 0, usd_micros: 0 }
      }
      return {
        cred: cred.slug, kind: cred.connector_kind, base_url: `/p/${cred.slug}`,
        put_it_at: cred.fields.filter((f) => g.fields.includes(f.name))
          .flatMap((f) => f.sites.map((s) => sitesMod.describeSite(sitesMod.parseSite(s)))),
        quarantined: !!cred.quarantine,
        expires_at: g.expires_at ?? null,
        effective: policyMod.describeEffective(effective),
        // No limit is null; an unreadable one leaves nothing.
        budget_remaining: limit === Infinity ? null : (limit === null ? 0 : Math.max(0, limit - used)),
        spend_remaining: spend,
      }
    })
    return {
      session: {
        id: session.id, label: session.label, expires_at: session.expires_at ?? null,
        infinite: session.infinite === true, remote: session.remote === true,
      },
      grants,
      templates: this.#templates(),
      next: 'need more? call vault_request_session; it creates nothing until a human approves',
    }
  }

  /** The MCP process holds the session token it was started with. */
  #tokenFor(session, token) { return token || session?.__token || '' }
}

/** How much of a response body a tool result carries. */
const MAX_TOOL_BODY = 256 * 1024

/**
 * Read a streamed response to its end, keeping at most `limit` characters.
 * Read to the end, not to the limit: stopping early leaves the upstream
 * connection open, and the events are already scrubbed one by one.
 */
async function readBounded(stream, limit) {
  let out = ''
  for await (const chunk of stream) {
    if (out.length < limit) out += Buffer.isBuffer(chunk) ? chunk.toString('utf8') : String(chunk)
  }
  return out.slice(0, limit)
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
