// The error registry. Codes and exit codes are frozen for 1.x: adding is
// allowed, changing the meaning of an existing one is not.
//
// Every denial an agent can see carries a code, a rule name, a hint and a
// concrete next step for both the CLI and MCP. An agent that reads
// "placeholder burned; call agent-vault ph next" recovers without a human.

export const EXIT = {
  OK: 0,
  FAILURE: 1,
  USAGE: 2,
  DAEMON_UNREACHABLE: 3,
  LOCKED: 4,
  PRESENCE: 5,
  POLICY_DENIED: 6,
  NOT_FOUND: 7,
  PLACEHOLDER: 8,
  SESSION: 9,
  APPROVAL: 10,
  CONFLICT: 11,
  UPSTREAM: 12,
  NOT_SETUP: 13,
  HEADLESS_LOCKED: 14,
  VERSION_SKEW: 15,
  CLIENT_CERT: 16,
  LISTENER: 17,
  INTERNAL: 70,
}

/** code -> { http, exit, audit, consumes, hint } */
export const CODES = {
  AV_NO_GRANT: { http: 403, exit: EXIT.POLICY_DENIED, audit: 'request.denied', consumes: false,
    hint: 'This session has no grant for that destination.' },
  AV_POLICY_DENIED: { http: 403, exit: EXIT.POLICY_DENIED, audit: 'request.denied', consumes: false,
    hint: 'The grant exists but this method or path is outside it.' },
  AV_BAD_LOCATION: { http: 403, exit: EXIT.POLICY_DENIED, audit: 'placeholder.misplaced', consumes: false,
    hint: 'A placeholder appeared somewhere it is never substituted. Put it only where the usage says.' },
  AV_ENCODED_BODY: { http: 422, exit: EXIT.POLICY_DENIED, audit: 'request.denied', consumes: false,
    hint: 'Request bodies must not be compressed; send identity encoding.' },
  AV_UNSCANNABLE: { http: 502, exit: EXIT.UPSTREAM, audit: 'response.unscannable', consumes: true,
    hint: 'The upstream response could not be decoded for scrubbing, so it was not returned.' },
  AV_BROWSER_ORIGIN: { http: 403, exit: EXIT.POLICY_DENIED, audit: 'request.denied', consumes: false,
    hint: 'Requests carrying Origin or Sec-Fetch-Site are refused; this endpoint is not for browsers.' },
  AV_PH_MALFORMED: { http: 400, exit: EXIT.PLACEHOLDER, audit: 'placeholder.denied', consumes: false,
    hint: 'The placeholder was altered in transit.' },
  AV_PH_EXHAUSTED: { http: 401, exit: EXIT.PLACEHOLDER, audit: 'placeholder.exhausted_reuse', consumes: false,
    hint: 'This placeholder has no uses left. A successor is in the next_placeholder field.' },
  AV_PH_STALE: { http: 401, exit: EXIT.PLACEHOLDER, audit: 'placeholder.stale', consumes: false,
    hint: 'This placeholder is no longer live. Fetch a new one; nothing is wrong.' },
  AV_PH_REPLAY: { http: 403, exit: EXIT.PLACEHOLDER, audit: 'placeholder.replay', consumes: false,
    hint: 'This placeholder was burned or revoked. Reuse is treated as hostile.' },
  AV_PH_CROSS_SESSION: { http: 403, exit: EXIT.PLACEHOLDER, audit: 'placeholder.cross_session', consumes: false,
    hint: 'That placeholder belongs to a different session.' },
  AV_PH_WRONG_CONNECTOR: { http: 403, exit: EXIT.PLACEHOLDER, audit: 'placeholder.cross_grant', consumes: false,
    hint: 'That placeholder is for a different credential than the route it was sent to.' },
  AV_SESSION_EXPIRED: { http: 401, exit: EXIT.SESSION, audit: 'session.ended', consumes: false,
    hint: 'The session expired. A human must start a new one.' },
  AV_SESSION_REVOKED: { http: 401, exit: EXIT.SESSION, audit: 'session.ended', consumes: false,
    hint: 'The session was revoked.' },
  AV_SESSION_REQUIRED: { http: 401, exit: EXIT.SESSION, audit: 'request.denied', consumes: false,
    hint: 'Send the session token in Authorization: Bearer, or a placeholder at a declared header site.' },
  AV_LOCKED: { http: 423, exit: EXIT.LOCKED, audit: 'request.denied', consumes: false,
    hint: 'The vault is locked. A human must unlock it.' },
  AV_REMOTE_FORBIDDEN: { http: 403, exit: EXIT.POLICY_DENIED, audit: 'remote.denied', consumes: false,
    hint: 'That operation is never reachable from a network listener.' },
  AV_PRESENCE_REQUIRED: { http: 401, exit: EXIT.PRESENCE, audit: 'presence.required', consumes: false,
    hint: 'This change needs a human; confirm your passphrase.' },
  AV_PRESENCE_DENIED: { http: 403, exit: EXIT.PRESENCE, audit: 'presence.denied', consumes: false,
    hint: 'The passphrase did not verify.' },
  AV_RATE_LIMITED: { http: 429, exit: EXIT.PRESENCE, audit: 'presence.throttled', consumes: false,
    hint: 'Too many failed attempts. Wait for the backoff to expire and try again.' },
  AV_UPSTREAM_UNREACHABLE: { http: 502, exit: EXIT.UPSTREAM, audit: 'request.upstream_failed', consumes: false,
    hint: 'The upstream could not be reached. If the failure happened before a connection existed, the placeholder use was refunded; the `refunded` field says which.' },
  AV_MCP_PROTOCOL: { http: 400, exit: EXIT.FAILURE, audit: 'mcp.protocol_rejected', consumes: false,
    hint: 'Unsupported or missing MCP-Protocol-Version.' },
  AV_MCP_SESSION_UNKNOWN: { http: 404, exit: EXIT.FAILURE, audit: 'mcp.protocol_rejected', consumes: false,
    hint: 'Unknown Mcp-Session-Id; call initialize again.' },
  AV_NOT_FOUND: { http: 404, exit: EXIT.NOT_FOUND, audit: 'request.denied', consumes: false,
    hint: 'No such object.' },
  AV_INTERNAL: { http: 500, exit: EXIT.INTERNAL, audit: 'request.denied', consumes: false,
    hint: 'Internal error; see the audit log.' },
}

export class VaultError extends Error {
  /**
   * @param {string} code one of CODES
   * @param {string} detail what happened, in the agent's terms
   * @param {object} [extra] { rule, next, requestId, nextPlaceholder }
   */
  constructor(code, detail, extra = {}) {
    const spec = CODES[code] || CODES.AV_INTERNAL
    super(`${code}: ${detail}`)
    this.name = 'VaultError'
    this.code = code
    this.detail = detail
    this.http = spec.http
    this.exit = spec.exit
    this.auditKind = spec.audit
    this.hint = extra.hint || spec.hint
    this.rule = extra.rule
    this.next = extra.next
    this.requestId = extra.requestId
    this.nextPlaceholder = extra.nextPlaceholder
    // Which human factors would satisfy this refusal. A caller that knows the
    // vault has an authenticator but no passphrase can then say so, instead of
    // asking for a passphrase that does not exist.
    this.factors = extra.factors
    // Whether a placeholder use was given back. The hint used to assert that
    // it always was, while the refund was in fact unreachable.
    this.refunded = extra.refunded
  }

  /** RFC 9457 problem+json, the shape every denied HTTP request returns. */
  toProblem() {
    const body = {
      type: `https://agent-vault.dev/errors/${this.code}`,
      code: this.code,
      detail: this.detail,
      hint: this.hint,
    }
    if (this.rule) body.rule = this.rule
    if (this.requestId) body.request_id = this.requestId
    if (this.next) body.next = this.next
    if (this.factors) body.factors = this.factors
    if (this.refunded !== undefined) body.refunded = this.refunded
    if (this.nextPlaceholder) body.next_placeholder = this.nextPlaceholder
    return body
  }
}

/** Shorthand used throughout the pipeline. */
export function deny(code, detail, extra) {
  return new VaultError(code, detail, extra)
}
