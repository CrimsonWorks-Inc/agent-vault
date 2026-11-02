// The WebAuthn flows, ported from src/ui/app.html without changing a byte of
// what goes over the wire (contract U4).
//
// Everything that changes what an agent can do is signed: the page asks the
// UI server for a challenge bound to the exact operation, the platform
// authenticator signs it, and the proof travels with the request. The server
// (GATED in src/ui/server.js) rebuilds the operation from the request it
// receives and compares, and for DAEMON_VERIFIED routes the daemon checks the
// signature again. An automated browser can click the button; it sits at the
// Touch ID dialog and stops there.
//
// Plain ESM with every platform object injected, so node --test can drive it.

// ---- encodings, as app.html wrote them ----------------------------------

export const b64uToBuf = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0))
export const bufToB64u = (b) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
export const bufToB64 = (b) => btoa(String.fromCharCode(...new Uint8Array(b)))
export const b64ToBuf = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0))

/**
 * Request fields that carry a secret, bound by digest rather than in clear.
 * The same list as DIGESTED in src/ui/webauthn.js; a test holds them equal.
 */
export const DIGESTED = ['value', 'prf_secret', 'recovery_passphrase', 'bundle', 'webhook_url']

/** Sorted keys, undefined dropped: canonicalOperation in webauthn.js. */
export function canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value ?? null)
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`
  const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort()
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`
}

/**
 * The operation a signature will authorise, built from the whole request.
 *
 * It used to be a hand-picked few fields, and the ones nobody picked were the
 * dangerous ones. The server rebuilds this from the request it receives and
 * compares, so anything missing here is a field that could be changed after
 * you touched the sensor.
 */
export async function operationFor(op, params = {}, { subtle = globalThis.crypto?.subtle } = {}) {
  const out = { op }
  for (const key of Object.keys(params).sort()) {
    const v = params[key]
    if (v === undefined || key === 'presence') continue
    // The reserved names, refused exactly as webauthn.js refuses them, and
    // before any digest is written: a body naming another op is the swap, and
    // a caller's own `value_sha256` would overwrite the digest of the real
    // value. A body that repeats the route's own op says nothing new.
    if (key === 'op' && v === op) continue
    if (key === 'op' || key.endsWith('_sha256')) throw reservedField(key)
    // A string is its own bytes; anything else its canonical form, which is
    // how the servers digest it too.
    if (DIGESTED.includes(key)) {
      const text = typeof v === 'string' ? v : canonicalJson(v)
      const digest = await subtle.digest('SHA-256', new TextEncoder().encode(text))
      out[`${key}_sha256`] = [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('')
      continue
    }
    out[key] = v
  }
  return out
}

/** webauthn.js's refusal, in the same words, with the same code and rule. */
function reservedField(key) {
  return Object.assign(new Error(`a request cannot carry a field named ${JSON.stringify(key)}`), {
    code: 'AV_POLICY_DENIED', rule: 'reserved_operation_field',
  })
}

/**
 * The gated routes whose operation the server binds from the QUERY string
 * (server.js #operationFor, `url.searchParams.get(name)`), with the op and
 * the fields it reads. A field that is absent from the query is read as
 * null, so it must be signed as null, never left out: "remove every pin for
 * the host" is `spki: null`, and an operation without the key is a different
 * operation, refused with 409.
 */
export const QUERY_BOUND = Object.freeze({
  'DELETE credentials': { op: 'cred.remove', fields: ['slug'] },
  'DELETE sessions': { op: 'session.revoke', fields: ['sid'] },
  'DELETE credentials/scrub': { op: 'cred.scrub_remove', fields: ['slug', 'id'] },
  'DELETE credentials/pins': { op: 'cred.pins_remove', fields: ['slug', 'host', 'spki'] },
  'DELETE templates': { op: 'template.delete', fields: ['name'] },
})

/**
 * One query-bound request, built once so the query sent and the operation
 * signed cannot disagree:
 *
 *   const r = queryBound('DELETE credentials/pins', { slug, host })   // spki left out: every pin
 *   <GatedButton operation={r.operation} label={describeOperation(r.operation)}
 *     send={(proof) => api.del(r.path, r.query, { presence: proof })} />
 *
 * Each field is read the way the server reads it: a string, or null when it
 * is absent, null or empty (lib/api.js `withQuery` leaves those out of the
 * URL, so the server sees no parameter). Numbers become strings, as they do
 * in a URL. A field the route does not bind is refused rather than dropped.
 */
export function queryBound(route, params = {}) {
  const spec = QUERY_BOUND[route]
  if (!spec) throw new Error(`${route} is not a query-bound gated route`)
  const extra = Object.keys(params).filter((k) => !spec.fields.includes(k) && params[k] !== undefined)
  if (extra.length) throw new Error(`${route} does not bind ${extra.join(', ')}`)
  const operation = { op: spec.op }
  const query = {}
  for (const f of spec.fields) {
    const v = params[f]
    const text = v === undefined || v === null || v === '' ? null : String(v)
    operation[f] = text
    if (text !== null) query[f] = text
  }
  const [method, path] = route.split(' ')
  return { method, path, query, operation }
}

/**
 * Words for an operation, for the line the page shows while the platform
 * dialog is open (U7: every gated button names what it is about to sign).
 */
export function describeOperation(operation) {
  const o = operation || {}
  const said = {
    'cred.add': () => `store credential ${o.slug ?? ''}`,
    'cred.remove': () => `remove credential ${o.slug ?? ''}`,
    'cred.rotate': () => `rotate credential ${o.slug ?? ''}`,
    'cred.scrub_add': () => `add a scrub pattern to ${o.slug ?? ''}`,
    'cred.scrub_remove': () => `remove scrub pattern ${o.id ?? ''} from ${o.slug ?? ''}`,
    'cred.pins_remove': () => `remove ${o.spki ? 'a pin' : 'every pin'} for ${o.host ?? ''} on ${o.slug ?? ''}`,
    'cred.expiry_set': () => (o.expires_at ? `set ${o.slug ?? ''} to expire ${String(o.expires_at).slice(0, 10)}` : `clear the expiry on ${o.slug ?? ''}`),
    'cred.release': () => `release ${o.slug ?? ''} from quarantine`,
    'session.create': () => `create session ${o.label ?? ''}`,
    'session.revoke': () => `revoke session ${o.sid ?? ''}`,
    'session.narrow': () => `narrow session ${o.sid ?? ''}`,
    'approval.approve': () => `approve request ${o.id ?? ''}`,
    'approval.deny': () => `deny request ${o.id ?? ''}`,
    'session_request.decide': () => `${o.granted ? 'approve' : 'deny'} session request ${o.id ?? ''}`,
    'pending.decide_many': () => `decide ${Array.isArray(o.decisions) ? o.decisions.length : 0} waiting items`,
    'vault.lock': () => 'lock the vault',
    'touchid.enroll': () => 'turn on Touch ID unlock',
    'touchid.remove': () => 'turn off Touch ID unlock',
    'tripwires.set': () => (o.enabled === true ? 'turn tripwires on' : o.enabled === false ? 'turn tripwires off' : 'save tripwire rules'),
    'template.save': () => `save template ${o.name ?? ''}`,
    'template.delete': () => `delete template ${o.name ?? ''}`,
    'presence.enroll': () => 'replace the confirmation authenticator',
  }[o.op]
  return (said ? said() : String(o.op ?? 'this change')).replace(/\s+$/, '')
}

/**
 * The flows, over an injected `call(method, path, body)` (lib/api.js
 * `request`), `credentials` (navigator.credentials) and `random(n)`.
 */
export function createPresence({
  call,
  credentials = () => globalThis.navigator?.credentials,
  random = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n)),
  subtle = globalThis.crypto?.subtle,
} = {}) {
  let state = { enrolled: false }
  const creds = () => {
    const c = credentials()
    if (!c) throw new Error('This browser has no WebAuthn support, so no change can be confirmed here. The CLI can make every change.')
    return c
  }

  /** GET presence/state; never throws, an unreachable answer is "not enrolled". */
  async function refresh() {
    try { state = await call('GET', 'presence/state') } catch { state = { enrolled: false } }
    return state
  }

  /** Obtain a signature for one specific operation. */
  async function sign(operation) {
    const ch = await call('POST', 'presence/challenge', { operation })
    const assertion = await creds().get({
      publicKey: {
        challenge: b64uToBuf(ch.challenge),
        allowCredentials: ch.allowCredentials.map((c) => ({ id: b64uToBuf(c.id), type: 'public-key' })),
        userVerification: 'required',
        rpId: ch.rpId,
        timeout: 60000,
      },
    })
    return {
      challengeId: ch.challengeId,
      credentialId: bufToB64u(assertion.rawId),
      authenticatorData: bufToB64u(assertion.response.authenticatorData),
      clientDataJSON: bufToB64u(assertion.response.clientDataJSON),
      signature: bufToB64u(assertion.response.signature),
    }
  }

  /** Run a gated action: sign the operation, then send it with the signature. */
  async function gated(operation, send) {
    if (!state.enrolled) {
      throw new Error('No authenticator enrolled. Set one up from the Overview tab first.')
    }
    let proof
    try {
      proof = await sign(operation)
    } catch (e) {
      if (e?.name === 'NotAllowedError') throw new Error('Not confirmed. Nothing was changed.')
      throw e
    }
    return send(proof)
  }

  /**
   * Enrolling is the one change a fingerprint cannot authorise, because the
   * fingerprint being enrolled is the thing in question. When a passphrase
   * exists, the daemon wants it once, here, with the enrolment itself.
   * `askPassphrase(label)` resolves with the text, or null on cancel.
   */
  async function enroll({ askPassphrase }) {
    const ls = await call('GET', 'lockstate').catch(() => ({}))
    let passphrase
    if (ls.has_passphrase) {
      passphrase = await askPassphrase('Vault passphrase, to enrol this device')
      if (passphrase == null) throw new Error('Cancelled. Nothing was enrolled.')
    }
    const opts = await call('POST', 'presence/enroll/begin')
    const cred = await creds().create({
      publicKey: {
        challenge: b64uToBuf(opts.challenge),
        rp: opts.rp,
        user: { id: b64uToBuf(opts.user.id), name: opts.user.name, displayName: opts.user.displayName },
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
        authenticatorSelection: {
          authenticatorAttachment: 'platform',
          userVerification: 'required',
          residentKey: 'preferred',
        },
        timeout: 120000,
        attestation: 'none',
      },
    })
    await call('POST', 'presence/enroll/finish', {
      attestationObject: bufToB64u(cred.response.attestationObject),
      clientDataJSON: bufToB64u(cred.response.clientDataJSON),
      passphrase,
    })
    return refresh()
  }

  /**
   * Replace the confirmation authenticator. The new key is registered first;
   * then the CURRENT key signs the new key's exact public record, and the
   * daemon enrols it only on that signature.
   */
  async function replaceKey() {
    const opts = await call('POST', 'presence/rotate/begin')
    const cred = await creds().create({
      publicKey: {
        challenge: b64uToBuf(opts.challenge),
        rp: opts.rp,
        user: { id: b64uToBuf(opts.user.id), name: opts.user.name, displayName: opts.user.displayName },
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
        authenticatorSelection: { authenticatorAttachment: 'platform', userVerification: 'required', residentKey: 'preferred' },
        excludeCredentials: opts.exclude ? [{ id: b64uToBuf(opts.exclude), type: 'public-key' }] : [],
        timeout: 120000,
        attestation: 'none',
      },
    })
    const { credential } = await call('POST', 'presence/rotate/register', {
      attestationObject: bufToB64u(cred.response.attestationObject),
      clientDataJSON: bufToB64u(cred.response.clientDataJSON),
    })
    await gated(await operationFor('presence.enroll', credential, { subtle }), (proof) =>
      call('POST', 'presence/rotate', { ...credential, presence: proof }))
    return refresh()
  }

  // ---- Touch ID unlock, via the WebAuthn PRF extension ---------------------
  // PRF returns a stable 32-byte secret from the authenticator for our salt,
  // which the daemon uses to unwrap the vault key. Only a real Touch ID can
  // produce it, so it is a cryptographic factor, not just a presence tap.

  async function touchIdUnlock() {
    const p = await call('GET', 'unlock/webauthn-params')
    const salt = b64ToBuf(p.prf_salt)
    let assertion
    try {
      assertion = await creds().get({
        publicKey: {
          challenge: random(32),
          allowCredentials: [{ id: b64uToBuf(p.credential_id), type: 'public-key' }],
          userVerification: 'required', rpId: p.rp_id, timeout: 60000,
          extensions: { prf: { eval: { first: salt } } },
        },
      })
    } catch (e) {
      if (e?.name === 'NotAllowedError') throw new Error('Touch ID was not confirmed.')
      throw e
    }
    const prf = assertion.getClientExtensionResults()?.prf?.results?.first
    if (!prf) throw new Error('This browser did not return a PRF secret. Use your passphrase to unlock.')
    return call('POST', 'unlock/touchid', { prf_secret: bufToB64(prf) })
  }

  async function enableTouchId() {
    const params = await call('GET', 'touchid/enroll-params')
    if (!params.has_passphrase) throw new Error(TOUCHID_NEEDS_PASSPHRASE)
    const salt = b64ToBuf(params.prf_salt)
    const cred = await creds().create({
      publicKey: {
        challenge: random(32),
        rp: { id: params.rp_id, name: 'agent-vault' },
        user: { id: new TextEncoder().encode('agent-vault-unlock'), name: 'vault-unlock', displayName: 'Vault unlock' },
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
        authenticatorSelection: { authenticatorAttachment: 'platform', userVerification: 'required', residentKey: 'preferred' },
        extensions: { prf: { eval: { first: salt } } },
        timeout: 120000, attestation: 'none',
      },
    })
    let prf = cred.getClientExtensionResults()?.prf?.results?.first
    if (!prf) {
      // Some authenticators only evaluate PRF on assertion; follow up with one.
      const asrt = await creds().get({
        publicKey: {
          challenge: random(32),
          allowCredentials: [{ id: cred.rawId, type: 'public-key' }],
          userVerification: 'required', rpId: params.rp_id, timeout: 60000,
          extensions: { prf: { eval: { first: salt } } },
        },
      })
      prf = asrt.getClientExtensionResults()?.prf?.results?.first
    }
    if (!prf) throw new Error('This browser or Mac does not support the WebAuthn PRF extension, so Touch ID unlock is not available here. Your passphrase still works.')
    // Signed over what is sent: the servers compare against the whole request.
    const body = { credential_id: bufToB64u(cred.rawId), prf_secret: bufToB64(prf) }
    return gated(await operationFor('touchid.enroll', body, { subtle }), (proof) =>
      call('POST', 'touchid/enroll', { ...body, presence: proof }))
  }

  function disableTouchId() {
    return gated({ op: 'touchid.remove' }, (proof) => call('POST', 'touchid/remove', { presence: proof }))
  }

  /** Locking is gated like any other change (POST lock is in GATED). */
  function lock() {
    return gated({ op: 'vault.lock' }, (proof) => call('POST', 'lock', { presence: proof }))
  }

  return {
    get state() { return state },
    refresh, sign, gated, enroll, replaceKey, touchIdUnlock, enableTouchId, disableTouchId, lock,
  }
}

/** The daemon refuses Touch ID unlock without a passphrase to fall back on. */
export const TOUCHID_NEEDS_PASSPHRASE = 'Touch ID unlock needs a passphrase to fall back on if the authenticator is lost. Set one, then enable Touch ID unlock again: agent-vault passphrase set'

/** Whether this browser can do WebAuthn at all (app.html's prfSupported). */
export const prfSupported = () => typeof globalThis.PublicKeyCredential !== 'undefined'
