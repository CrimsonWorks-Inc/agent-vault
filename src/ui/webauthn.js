// WebAuthn verification, written against the platform authenticator.
//
// This is the answer to "how do you stop an LLM driving the browser". You
// cannot, inside the browser. Anything the page can observe about its visitor,
// something with control of the browser can forge: navigator.webdriver is a
// boolean it can set, event.isTrusted is true for CDP-injected input, mouse
// movement can be synthesised, and a screenshot reads the DOM better than the
// DOM does.
//
// So the gate is not a test the visitor passes. It is a signature the visitor
// cannot produce. The private key lives in the Secure Enclave, it is bound to
// this origin, and it only signs after the platform verifies a human, by
// fingerprint or by the device password. An automated browser can click the
// button and will simply wait at a dialog that never resolves.
//
// A virtual authenticator, which CDP can install, does not help an attacker:
// it can only mint a NEW credential, and the daemon accepts an assertion only
// from the credential id it enrolled, verified against that stored public key.
//
// Supported algorithm: ES256 (-7), which is what platform authenticators use.
// RS256 is rejected rather than half-supported.

import { createHash, createPublicKey, createVerify, randomBytes, timingSafeEqual } from 'node:crypto'

export const ES256 = -7

// --------------------------------------------------------------------- CBOR

/**
 * Just enough CBOR to read an attestation object and a COSE key. Deliberately
 * small and strict: anything it does not recognise throws rather than guesses.
 */
export function decodeCbor(buf, start = 0) {
  const view = { buf, pos: start }
  const value = readItem(view)
  return { value, end: view.pos }
}

// A hostile attestation can declare a four-billion-item array in five bytes.
// parseAuthData runs on attacker-supplied authenticatorData *before* the
// signature is checked, so a sixty-byte request used to exhaust the heap and
// kill the process. Lengths are bounded by what is actually left in the
// buffer, and nesting by a depth no real COSE key approaches.
const CBOR_MAX_DEPTH = 16

function readItem(v, depth = 0) {
  if (depth > CBOR_MAX_DEPTH) throw new Error('cbor: nested too deeply')
  if (v.pos >= v.buf.length) throw new Error('cbor: truncated')
  const first = v.buf[v.pos++]
  const major = first >> 5
  const minor = first & 0x1f
  const len = readLength(v, minor)

  // Every remaining item costs at least one byte, so a declared count larger
  // than the bytes left cannot be honest.
  const remaining = v.buf.length - v.pos
  if ((major === 2 || major === 3) && len > remaining) throw new Error('cbor: length exceeds the buffer')
  if (major === 4 && len > remaining) throw new Error('cbor: array longer than the buffer')
  if (major === 5 && len * 2 > remaining) throw new Error('cbor: map larger than the buffer')

  switch (major) {
    case 0: return len                                   // unsigned
    case 1: return -1 - len                              // negative
    case 2: { const b = v.buf.subarray(v.pos, v.pos + len); v.pos += len; return b }   // bytes
    case 3: { const s = v.buf.toString('utf8', v.pos, v.pos + len); v.pos += len; return s } // text
    case 4: { const a = []; for (let i = 0; i < len; i++) a.push(readItem(v, depth + 1)); return a }
    case 5: {
      const m = new Map()
      for (let i = 0; i < len; i++) { const k = readItem(v, depth + 1); m.set(k, readItem(v, depth + 1)) }
      return m
    }
    case 7:
      if (minor === 20) return false
      if (minor === 21) return true
      if (minor === 22) return null
      throw new Error(`cbor: unsupported simple value ${minor}`)
    default:
      throw new Error(`cbor: unsupported major type ${major}`)
  }
}

function readLength(v, minor) {
  if (minor < 24) return minor
  if (minor === 24) return v.buf[v.pos++]
  if (minor === 25) { if (v.pos + 2 > v.buf.length) throw new Error('cbor: truncated length'); const n = v.buf.readUInt16BE(v.pos); v.pos += 2; return n }
  if (minor === 26) { if (v.pos + 4 > v.buf.length) throw new Error('cbor: truncated length'); const n = v.buf.readUInt32BE(v.pos); v.pos += 4; return n }
  throw new Error(`cbor: unsupported length encoding ${minor}`)
}

// ------------------------------------------------------------------ authData

/**
 * Parse the authenticator data structure.
 * rpIdHash(32) | flags(1) | signCount(4) | [aaguid(16) credIdLen(2) credId credPubKey]
 */
export function parseAuthData(authData) {
  if (authData.length < 37) throw new Error('authenticator data is too short')
  const rpIdHash = authData.subarray(0, 32)
  const flags = authData[32]
  const signCount = authData.readUInt32BE(33)
  const out = {
    rpIdHash,
    flags,
    signCount,
    userPresent: (flags & 0x01) !== 0,
    userVerified: (flags & 0x04) !== 0,
    attestedCredentialData: (flags & 0x40) !== 0,
  }
  if (out.attestedCredentialData) {
    const credIdLen = authData.readUInt16BE(53)
    out.aaguid = authData.subarray(37, 53)
    out.credentialId = authData.subarray(55, 55 + credIdLen)
    const { value } = decodeCbor(authData, 55 + credIdLen)
    out.coseKey = value
  }
  return out
}

/** Turn a COSE EC2 P-256 key into a Node public key via a SPKI wrapper. */
export function coseToPublicKey(cose) {
  const kty = cose.get(1)
  const alg = cose.get(3)
  if (kty !== 2) throw new Error(`unsupported COSE key type ${kty}; only EC2 is accepted`)
  if (alg !== ES256) throw new Error(`unsupported algorithm ${alg}; only ES256 is accepted`)
  const crv = cose.get(-1)
  if (crv !== 1) throw new Error(`unsupported curve ${crv}; only P-256 is accepted`)
  const x = cose.get(-2)
  const y = cose.get(-3)
  if (!x || !y || x.length !== 32 || y.length !== 32) throw new Error('malformed EC point')

  // Fixed SPKI prefix for id-ecPublicKey over prime256v1, then the uncompressed point.
  const prefix = Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex')
  const der = Buffer.concat([prefix, Buffer.from([0x04]), x, y])
  return createPublicKey({ key: der, format: 'der', type: 'spki' })
}

// ---------------------------------------------------------------- ceremonies

export function newChallenge() {
  return randomBytes(32)
}

export function b64url(buf) {
  return Buffer.from(buf).toString('base64url')
}

function parseClientData(clientDataJSON, { expectedType, expectedChallenge, expectedOrigins }) {
  const data = JSON.parse(Buffer.from(clientDataJSON, 'base64url').toString('utf8'))
  if (data.type !== expectedType) throw new Error(`client data type is ${data.type}, expected ${expectedType}`)

  const got = Buffer.from(data.challenge, 'base64url')
  const want = Buffer.from(expectedChallenge)
  if (got.length !== want.length || !timingSafeEqual(got, want)) {
    throw new Error('challenge does not match; this assertion was made for a different operation')
  }
  if (!expectedOrigins.includes(data.origin)) {
    throw new Error(`origin ${data.origin} is not this server`)
  }
  return data
}

/**
 * Verify a registration. Attestation is not required: the trust here comes from
 * the enrollment moment being human-driven, not from an attestation chain.
 */
export function verifyRegistration({ attestationObject, clientDataJSON, expectedChallenge, expectedOrigins, rpId }) {
  parseClientData(clientDataJSON, { expectedType: 'webauthn.create', expectedChallenge, expectedOrigins })

  const { value: attestation } = decodeCbor(Buffer.from(attestationObject, 'base64url'))
  const authData = parseAuthData(attestation.get('authData'))

  const expectedRpIdHash = createHash('sha256').update(rpId).digest()
  if (!timingSafeEqual(authData.rpIdHash, expectedRpIdHash)) throw new Error('relying party id does not match')
  if (!authData.userPresent) throw new Error('the authenticator did not report user presence')
  if (!authData.userVerified) {
    throw new Error('the authenticator did not verify a human; enrollment requires a fingerprint or device password')
  }
  if (!authData.attestedCredentialData) throw new Error('no credential was attested')

  const publicKey = coseToPublicKey(authData.coseKey)
  return {
    credentialId: b64url(authData.credentialId),
    publicKeySpki: publicKey.export({ format: 'der', type: 'spki' }).toString('base64'),
    signCount: authData.signCount,
    enrolledAt: new Date().toISOString(),
  }
}

/**
 * Verify an assertion against an enrolled credential. This is the check that
 * makes an approval impossible to click through: the signature covers a
 * challenge the daemon derived from the exact operation, and only the enrolled
 * private key can produce it.
 */
export function verifyAssertion({
  credentialId, authenticatorData, clientDataJSON, signature,
  expectedChallenge, expectedOrigins, rpId, enrolled,
}) {
  if (credentialId !== enrolled.credentialId) {
    throw new Error('this assertion is from a credential that was never enrolled')
  }
  parseClientData(clientDataJSON, { expectedType: 'webauthn.get', expectedChallenge, expectedOrigins })

  const authData = Buffer.from(authenticatorData, 'base64url')
  const parsed = parseAuthData(authData)

  const expectedRpIdHash = createHash('sha256').update(rpId).digest()
  if (!timingSafeEqual(parsed.rpIdHash, expectedRpIdHash)) throw new Error('relying party id does not match')
  if (!parsed.userPresent) throw new Error('no user presence')
  if (!parsed.userVerified) throw new Error('the authenticator did not verify a human for this operation')

  const clientDataHash = createHash('sha256').update(Buffer.from(clientDataJSON, 'base64url')).digest()
  const signedBytes = Buffer.concat([authData, clientDataHash])

  const publicKey = createPublicKey({
    key: Buffer.from(enrolled.publicKeySpki, 'base64'), format: 'der', type: 'spki',
  })
  const verifier = createVerify('SHA256')
  verifier.update(signedBytes)
  verifier.end()
  if (!verifier.verify(publicKey, Buffer.from(signature, 'base64url'))) {
    throw new Error('signature does not verify')
  }

  // A counter that goes backwards means the credential was cloned. Platform
  // authenticators commonly report zero, which is not a regression.
  if (parsed.signCount > 0 && enrolled.signCount > 0 && parsed.signCount <= enrolled.signCount) {
    throw new Error('signature counter did not advance; the credential may have been cloned')
  }
  return { signCount: parsed.signCount, userVerified: true }
}

/**
 * The operation a signature authorises, built from the whole request.
 *
 * This used to be a hand-listed subset of each request's fields, and the
 * fields nobody thought to list were the interesting ones: a signature for
 * "session.create on demo, GET, /**" did not bind `approval`, `budget`,
 * `ttl_hours` or `remote`, so a fingerprint given for a read-only eight-hour
 * local session created a remote, auto-approving, billion-request, decade-long
 * one. Both sides derived the same incomplete operation, so the daemon's
 * independent re-verification could not catch it either.
 *
 * Everything in the request is bound now. A credential value is replaced by
 * its digest: the signature must cover which secret is being stored, but the
 * secret itself has no business in a structure that gets canonicalised,
 * compared and logged.
 */
export function operationFor(op, params = {}) {
  const out = { op }
  for (const key of Object.keys(params).sort()) {
    if (key === 'presence') continue          // the proof is not part of what it proves
    const v = params[key]
    if (v === undefined) continue
    if (key === 'value' || key === 'prf_secret') {
      out[`${key}_sha256`] = createHash('sha256').update(String(v)).digest('hex')
      continue
    }
    out[key] = v
  }
  return out
}

/**
 * Stable key order, so the signed operation and the executed one compare
 * exactly. Everything that hashes or compares an operation goes through this;
 * two implementations that disagree about key order or about an absent field
 * would let a signature authorise something subtly different.
 */
export function canonicalOperation(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value ?? null)
  if (Array.isArray(value)) return `[${value.map(canonicalOperation).join(',')}]`
  const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort()
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalOperation(value[k])}`).join(',')}}`
}

/**
 * The challenge is derived from the operation, so a signature for one action
 * cannot authorise another. This mirrors the presence op_hash in the spec.
 */
export function challengeForOperation(nonce, operation) {
  const text = canonicalOperation(operation)
  return createHash('sha256').update(Buffer.concat([nonce, Buffer.from(text, 'utf8')])).digest()
}
