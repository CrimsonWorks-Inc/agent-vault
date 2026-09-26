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
import * as sub from '../core/substitute.js'
import * as sitesMod from '../core/sites.js'
import * as policyMod from '../core/policy.js'
import * as canon from '../core/canon.js'
import { Scrubber } from '../core/scrub.js'
import { deny, VaultError } from '../core/errors.js'
import { id } from '../store/ids.js'
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
  }

  /**
   * Handle one proxied request.
   * @param {{method, path, query, headers, body, listener?}} req
   * @returns {Promise<{status, headers, body, requestId}>}
   */
  async handle(req) {
    const requestId = id.request()
    const started = Date.now()
    let consumed = null
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

    try {
      this.#refuseBrowsers(req)
      session = this.#authenticate(req)
      route = this.#route(req, session)
      const result = await this.#proxy({
        req, session, route, requestId,
        onConsume: (r) => { consumed = r },
        onApprovalSpent: (a) => { spentApproval = a },
        markUpstream: () => { upstreamOpened = true },
      })
      this.vault.audit.write('request.allowed', {
        request_id: requestId, session_id: session.id, grant_id: route.grantId,
        credential_slug: route.slug,
        req: {
          host: result.host, method: req.method, path_glob_matched: result.rule, status: result.status,
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
        decision: 'allow',
        peer: { kind: req.listener?.kind || 'loopback', listener_id: req.listener?.id || 'local' },
        duration_ms: Date.now() - started,
      })
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
      if (consumed && !upstreamOpened) this.vault.refundPlaceholder(consumed.id)
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
      err.requestId = requestId
      if (this.vault.audit) {
        this.vault.audit.write(err.auditKind, {
          request_id: requestId, decision: 'deny', reason_code: err.code, rule: err.rule,
          detail: err.detail,
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
      return {
        status: err.http,
        headers: { 'content-type': 'application/problem+json', 'av-decision': 'deny', 'av-request-id': requestId },
        body: Buffer.from(JSON.stringify(err.toProblem(), null, 2)),
        requestId,
        error: err,
      }
    }
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
  #authenticate(req) {
    const explicit = sub.getHeader(req, 'av-session')
    const auth = sub.getHeader(req, 'authorization') || ''
    const bearer = /^bearer\s+(avs1\.\S+)$/i.exec(auth)
    const token = explicit || (bearer ? bearer[1] : null)

    if (token) {
      const session = this.vault.sessionByToken(token.trim())
      if (!session) throw deny('AV_SESSION_REQUIRED', 'session token is not recognised')
      this.vault.assertSessionLive(session)
      this.vault.touchSession(session)
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
      const session = this.vault.db.sessions[carrier.parsed.sid]
      if (!session) throw deny('AV_PH_CROSS_SESSION', 'the placeholder names a session that does not exist')
      this.vault.assertSessionLive(session)
      this.vault.touchSession(session)
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
    return secrets.length ? new Scrubber(secrets.map((x) => ({ ...x, always: true }))) : null
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
  #route(req, session) {
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
      const grant = this.vault.grantsForSession(session.id).find((g) => g.credential_id === cred.id)
      if (!grant) throw deny('AV_NO_GRANT', `this session has no grant for ${slug}`, {
        next: { cli: ['agent-vault cred list --available'], mcp: { tool: 'vault_list_creds' } },
      })
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
          return { mode: 'target', slug: cred.slug, cred, grant: g, grantId: g.id, host, port: credPort, path: upstreamPath, scheme: credScheme, profile }
        }
      }
      throw deny('AV_NO_GRANT', `no grant in this session allows host ${policyMod.hostOnly(rawHost)}`)
    }

    throw deny('AV_NOT_FOUND', `unknown route ${path}`, {
      hint: 'Use /p/<credential>/<path> for a configured credential, or /t/<scheme>/<host>/<path>.',
    })
  }

  async #proxy({ req, session, route, requestId, onConsume, onApprovalSpent, markUpstream }) {
    const { cred, grant, profile } = route
    const effective = policyMod.intersect([profile.policyCeiling, session.policy, grant.policy])
    let approvedRequestHash = null

    // --- locate every placeholder, in every encoding -----------------------
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

    if (!substitutions.length) {
      throw deny('AV_SESSION_REQUIRED', 'no placeholder in this request', {
        rule: 'no_placeholder',
        hint: `Put a placeholder at: ${cred.fields.map((f) => f.sites.map((s) => sitesMod.describeSite(sitesMod.parseSite(s))).join(' | ')).join(' | ')}. Get one with: agent-vault ph next ${cred.slug}`,
        next: { cli: [`agent-vault ph next ${cred.slug}`], mcp: { tool: 'vault_get_placeholder', args: { cred: cred.slug } } },
      })
    }

    // --- policy ------------------------------------------------------------
    const decision = policyMod.evaluateHttp(effective, { method: req.method, host: route.host, path: route.path })

    // --- budget ------------------------------------------------------------
    const budget = effective.budget
    // A limit that is present but not a number can only come from a bug, and
    // the failure mode is silent and total: `used >= NaN` is false forever, so
    // the grant is uncounted while the policy still shows a budget. Refuse
    // rather than proceed on a counter that cannot count.
    const stated = budget && budget.limit !== undefined && budget.limit !== null && budget.limit !== ''
      ? Number(budget.limit) : null
    if (budget && budget.limit !== undefined && budget.limit !== null && budget.limit !== '' && !Number.isFinite(stated)) {
      throw deny('AV_POLICY_DENIED', 'this grant has a budget whose limit is not a number, so no request can be counted against it', {
        rule: 'budget',
        hint: 'Recreate the grant with a numeric budget limit, or with no budget at all.',
      })
    }
    if (stated !== null && grant.budget_used >= stated) {
      throw deny('AV_POLICY_DENIED', `grant budget of ${stated} ${budget.unit || 'requests'} is spent`, {
        rule: 'budget',
        hint: 'A human must widen the grant or start a new session.',
      })
    }

    // --- approval ----------------------------------------------------------
    // The placeholder's TEXT is in the headers and may be in the body, so
    // swapping the id out of the hash is not enough on its own — the value
    // churns wherever it appears. Each occurrence is replaced by what it
    // stands for, exactly as substitution finds it, leaving a hash over what
    // the human was actually shown.
    const canonical = new Map(
      substitutions.map((s) => [s.occ.text, `<av:${s.row.grant_id}:${s.row.field}>`]),
    )
    const stable = (value) => {
      let out = String(value)
      for (const [text, marker] of canonical) out = out.split(text).join(marker)
      return out
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
      }).map(([n, v]) => [n, stable(v)]),
    })
    if (policyMod.needsApproval(effective, { method: decision.method, firstUse: grant.counters.requests === 0 })) {
      const verdict = this.#approval(requestHash, { grant, decision, requestId, reason: sub.getHeader(req, 'av-reason') })
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

    // --- forward -----------------------------------------------------------
    const headers = {}
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
      headers[n] = v
    }
    headers.host = route.port ? `${decision.host}:${route.port}` : decision.host
    headers['accept-encoding'] = 'identity'

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
      res = await this.upstream({ url: upstreamUrl, method: decision.method, headers, body: outgoing.body })
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
      if (!PRE_CONNECT_ERRORS.has(e?.code)) markUpstream()
      throw deny('AV_UPSTREAM_UNREACHABLE', `could not reach ${decision.host}: ${e.message}`, {
        rule: 'upstream',
        refunded: PRE_CONNECT_ERRORS.has(e?.code),
      })
    }

    // --- scrub -------------------------------------------------------------
    const scrubber = new Scrubber([...injected, ...this.vault.allSecrets().filter((s) => !injected.some((i) => i.secret === s.secret))])
    // The path as the audit log may hold it, computed here because this
    // scrubber already exists. Doing it in handle() meant #safeMessage, which
    // calls allSecrets() — decrypting every credential in the vault — on every
    // successful request rather than only on a failing one. More plaintext in
    // memory, more often, for no benefit.
    const auditPath = this.#redactPlaceholders(scrubber.scrub(String(decision.path ?? '').split('?')[0]).text)

    const outHeaders = {}
    for (const [n, v] of Object.entries(res.headers)) {
      const lower = n.toLowerCase()
      if (lower.startsWith('av-')) continue // an upstream must not be able to fake our decisions
      if (lower === 'set-cookie') continue
      // Content-Encoding and Content-Length are dropped because the body that
      // leaves here is decompressed and re-lengthed; forwarding the originals
      // would describe bytes the agent never receives.
      if (HOP_BY_HOP.has(lower) || lower === 'content-encoding' || lower === 'content-length') continue
      outHeaders[lower] = scrubber.scrub(String(v)).text
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
      let source = res.res
      if (contentEncoding && contentEncoding !== 'identity') {
        const gunzip = decompressStream(contentEncoding)
        if (!gunzip) {
          throw deny('AV_UNSCANNABLE', `upstream sent a ${contentEncoding} event stream that could not be decoded, so it could not be scrubbed`, {
            rule: 'content_encoding', hint: 'The response was discarded rather than passed through unread.',
          })
        }
        source = res.res.pipe(gunzip)
      }
      this.vault.audit.write('response.streamed', {
        request_id: requestId, content_type: contentType, content_encoding: contentEncoding || null,
      })
      return {
        status: res.status, headers: outHeaders, host: decision.host, rule: decision.rule, auditPath, redactions: 0,
        stream: scrubEventStream(source, scrubber, () => {
          this.vault.audit?.write('response.stream_cut', {
            request_id: requestId, reason: 'credential_split_across_events',
          })
        }),
      }
    }

    // Everything else is buffered, decompressed and scrubbed whole.
    let raw = res.body ?? (await collect(res.res))
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
    const { text, redactions } = scrubber.scrub(raw.toString('latin1'))
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

    const result = {
      status: res.status, headers: outHeaders, body: Buffer.from(text, 'latin1'),
      host: decision.host, rule: decision.rule, auditPath, redactions,
    }
    // Store the scrubbed response against the approval so a duplicate resend
    // replays it rather than hitting the upstream a second time.
    if (approvedRequestHash) {
      const approval = this.approvals.get(approvedRequestHash)
      if (approval) approval.result = result
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
  #approval(requestHash, { grant, decision, requestId, reason }) {
    const existing = this.approvals.get(requestHash)
    if (existing) {
      if (existing.state === 'granted') {
        existing.state = 'consumed' // exactly-once: a resend cannot fire twice
        return { status: 'granted', approval: existing }
      }
      if (existing.state === 'consumed') {
        // Already executed. Replay the stored response so a retrying SDK gets a
        // coherent answer without a second upstream side effect.
        return existing.result
          ? { status: 'replay', approval: existing }
          : { status: 'pending', approval: existing }
      }
      if (existing.state === 'denied') return { status: 'denied', approval: existing }
      return { status: 'pending', approval: existing }
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
      summary: `${decision.method} ${decision.host}${decision.path}`,
      reason: reason || null,
      state: 'pending',
      created_at: new Date().toISOString(),
    }
    this.approvals.set(requestHash, approval)
    this.vault.audit.write('approval.requested', {
      request_id: requestId, approval_id: approval.id, grant_id: grant.id, summary: approval.summary,
      agent_reason_untrusted: approval.reason,
    })
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

  decideApproval(approvalId, granted) {
    for (const approval of this.approvals.values()) {
      if (approval.id !== approvalId) continue
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

/**
 * Default upstream: Node's http(s) client, redirects never followed. The
 * response stream is handed back rather than buffered here, so the pipeline
 * can decide between streaming and buffering.
 */
function defaultUpstream({ url, method, headers, body }) {
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
 * What neither catches is a secret split across *application* fields, as in
 * `{"delta":"ghp_REAL"}` then `{"delta":"SECRET"}`: reassembling that means
 * knowing the upstream's JSON shape, which a byte proxy does not. For that
 * case the stream is cut rather than continued — the agent may have received
 * a fragment, and it will not receive the rest. It requires a hostile upstream,
 * which already holds the credential; what it buys is teaching the agent a
 * secret it was never given, and that is worth failing closed over.
 */
async function* scrubEventStream(source, scrubber, onLeak) {
  const frame = scrubber.stream()
  let pending = ''
  let assembled = ''

  const dataOf = (event) => event.split('\n')
    .filter((l) => l.startsWith('data:'))
    .map((l) => l.slice(5).replace(/^ /, ''))
    .join('')

  /**
   * The payload so far, as a client would actually put it back together.
   *
   * An LLM token stream is `{"delta":"ghp_SSE"}` then `{"delta":"CRET"}`, and
   * every client concatenates the VALUES. So this pulls out the JSON string
   * literals that are not object keys — a literal followed by `:` is a key —
   * and joins them. That reconstructs exactly what the reader ends up with.
   *
   * It used to strip all punctuation instead, which is wrong in both
   * directions: it glued the key text onto the value (`delta` + `ghp_...`),
   * so an exact secret could only be caught by the loose shape patterns, and
   * those then had to match without a leading boundary — which is what made
   * them fire on ordinary English like `disk-usage_by_repository`.
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

  /** True when the payload so far, however reassembled, contains a secret. */
  const leaked = (text) => {
    if (scrubber.scrub(text).redactions > 0) return true
    // As a JSON client reassembles it: values only, concatenated.
    const values = jsonValues(text)
    if (values && scrubber.scrub(values).redactions > 0) return true
    // And a last, cruder pass for framing that is not JSON at all.
    const bare = text.replace(/[^A-Za-z0-9_\-+/=]/g, '')
    return scrubber.scrub(bare).redactions > 0
  }

  for await (const chunk of source) {
    pending += frame.push(chunk.toString('latin1'))
    let boundary
    while ((boundary = pending.indexOf('\n\n')) !== -1) {
      const event = pending.slice(0, boundary + 2)
      pending = pending.slice(boundary + 2)
      assembled += dataOf(event)
      // Keep only enough to span a split; an LLM response is unbounded.
      if (assembled.length > scrubber.overlap * 4) {
        assembled = assembled.slice(-scrubber.overlap * 4)
      }
      if (leaked(assembled)) {
        onLeak?.()
        yield Buffer.from('event: error\ndata: {"code":"AV_UNSCANNABLE","detail":"the upstream split a credential across events; the stream was cut"}\n\n', 'latin1')
        return
      }
      yield Buffer.from(event, 'latin1')
    }
  }
  const tail = pending + frame.flush()
  if (tail) {
    assembled += dataOf(tail)
    if (leaked(assembled)) {
      onLeak?.()
      yield Buffer.from('event: error\ndata: {"code":"AV_UNSCANNABLE","detail":"the upstream split a credential across events; the stream was cut"}\n\n', 'latin1')
      return
    }
    yield Buffer.from(tail, 'latin1')
  }
}


