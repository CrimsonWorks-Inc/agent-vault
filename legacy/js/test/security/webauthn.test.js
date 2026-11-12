// The presence gate.
//
// These tests build a synthetic authenticator out of a plain P-256 keypair,
// which is exactly what a virtual authenticator installed over the DevTools
// protocol is: a key the attacker controls. The point of every test here is
// that controlling a key does not help, because the daemon only accepts the
// one credential it enrolled, and only for the operation the signature covers.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPairSync, createHash, sign as cryptoSign, randomBytes } from 'node:crypto'
import * as wa from '../../src/ui/webauthn.js'

const RP_ID = 'localhost'
const ORIGIN = 'http://localhost:7799'

// ------------------------------------------------------------- CBOR encoder
// Only what an attestation object and a COSE key need.

function cborUint(major, n) {
  if (n < 24) return Buffer.from([(major << 5) | n])
  if (n < 256) return Buffer.from([(major << 5) | 24, n])
  if (n < 65536) { const b = Buffer.alloc(3); b[0] = (major << 5) | 25; b.writeUInt16BE(n, 1); return b }
  const b = Buffer.alloc(5); b[0] = (major << 5) | 26; b.writeUInt32BE(n, 1); return b
}
function cbor(value) {
  if (typeof value === 'number') {
    return value >= 0 ? cborUint(0, value) : cborUint(1, -1 - value)
  }
  if (typeof value === 'string') return Buffer.concat([cborUint(3, Buffer.byteLength(value)), Buffer.from(value)])
  if (Buffer.isBuffer(value)) return Buffer.concat([cborUint(2, value.length), value])
  if (value instanceof Map) {
    return Buffer.concat([cborUint(5, value.size), ...[...value].map(([k, v]) => Buffer.concat([cbor(k), cbor(v)]))])
  }
  throw new Error('test cbor: unsupported value')
}

// ------------------------------------------------- a fake platform authenticator

function makeAuthenticator({ credentialId = randomBytes(16) } = {}) {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
  const raw = publicKey.export({ format: 'der', type: 'spki' })
  // The uncompressed point is the last 65 bytes of a P-256 SPKI.
  const point = raw.subarray(raw.length - 65)
  const x = point.subarray(1, 33)
  const y = point.subarray(33, 65)
  const cose = new Map([[1, 2], [3, -7], [-1, 1], [-2, x], [-3, y]])

  const rpIdHash = createHash('sha256').update(RP_ID).digest()

  const authData = (flags, signCount = 0, withCred = false) => {
    const head = Buffer.concat([rpIdHash, Buffer.from([flags]), (() => {
      const c = Buffer.alloc(4); c.writeUInt32BE(signCount); return c
    })()])
    if (!withCred) return head
    const len = Buffer.alloc(2); len.writeUInt16BE(credentialId.length)
    return Buffer.concat([head, Buffer.alloc(16), len, credentialId, cbor(cose)])
  }

  return {
    credentialId,
    /** A registration response, as the browser would return it. */
    register(challenge, { uv = true, origin = ORIGIN } = {}) {
      const clientData = Buffer.from(JSON.stringify({
        type: 'webauthn.create', challenge: Buffer.from(challenge).toString('base64url'), origin,
      }))
      const flags = 0x01 | (uv ? 0x04 : 0) | 0x40
      const attestation = new Map([['fmt', 'none'], ['attStmt', new Map()], ['authData', authData(flags, 0, true)]])
      return {
        attestationObject: cbor(attestation).toString('base64url'),
        clientDataJSON: clientData.toString('base64url'),
      }
    },
    /** An assertion response. */
    assert(challenge, { uv = true, origin = ORIGIN, signCount = 0, type = 'webauthn.get' } = {}) {
      const clientData = Buffer.from(JSON.stringify({
        type, challenge: Buffer.from(challenge).toString('base64url'), origin,
      }))
      const ad = authData(0x01 | (uv ? 0x04 : 0), signCount)
      const signed = Buffer.concat([ad, createHash('sha256').update(clientData).digest()])
      const signature = cryptoSign('sha256', signed, privateKey)
      return {
        credentialId: credentialId.toString('base64url'),
        authenticatorData: ad.toString('base64url'),
        clientDataJSON: clientData.toString('base64url'),
        signature: signature.toString('base64url'),
      }
    },
  }
}

function enrol(auth) {
  const challenge = wa.newChallenge()
  const response = auth.register(challenge)
  return wa.verifyRegistration({
    ...response, expectedChallenge: challenge, expectedOrigins: [ORIGIN], rpId: RP_ID,
  })
}

const verify = (enrolled, assertion, challenge) => wa.verifyAssertion({
  ...assertion, expectedChallenge: challenge, expectedOrigins: [ORIGIN], rpId: RP_ID, enrolled,
})

// ------------------------------------------------------------------- tests

test('a registration produces a credential the daemon can store', () => {
  const enrolled = enrol(makeAuthenticator())
  assert.ok(enrolled.credentialId)
  assert.ok(enrolled.publicKeySpki)
  assert.equal(typeof enrolled.enrolledAt, 'string')
})

test('registration without user verification is refused', () => {
  const auth = makeAuthenticator()
  const challenge = wa.newChallenge()
  assert.throws(
    () => wa.verifyRegistration({
      ...auth.register(challenge, { uv: false }),
      expectedChallenge: challenge, expectedOrigins: [ORIGIN], rpId: RP_ID,
    }),
    /did not verify a human/,
  )
})

test('a valid assertion for the issued challenge verifies', () => {
  const auth = makeAuthenticator()
  const enrolled = enrol(auth)
  const challenge = wa.challengeForOperation(randomBytes(32), { op: 'vault.lock' })
  const result = verify(enrolled, auth.assert(challenge), challenge)
  assert.equal(result.userVerified, true)
})

test('a different authenticator cannot sign for the enrolled credential', () => {
  // This is the virtual-authenticator attack. An agent that installs its own
  // authenticator holds a real key and can produce real signatures; it simply
  // is not the key that was enrolled.
  const enrolled = enrol(makeAuthenticator())
  const attacker = makeAuthenticator()
  const challenge = wa.challengeForOperation(randomBytes(32), { op: 'approval.approve', id: 'ap_1' })
  assert.throws(() => verify(enrolled, attacker.assert(challenge), challenge), /never enrolled/)
})

test('an attacker who copies the enrolled credential id still cannot sign', () => {
  const victim = makeAuthenticator()
  const enrolled = enrol(victim)
  // Same credential id, different key: the id is public, the key is not.
  const attacker = makeAuthenticator({ credentialId: victim.credentialId })
  const challenge = wa.challengeForOperation(randomBytes(32), { op: 'vault.lock' })
  assert.throws(() => verify(enrolled, attacker.assert(challenge), challenge), /signature does not verify/)
})

test('a signature for one operation does not authorise another', () => {
  // The heart of it: approving "read issue 1" must never execute "delete repo".
  const auth = makeAuthenticator()
  const enrolled = enrol(auth)
  const nonce = randomBytes(32)
  const signedFor = wa.challengeForOperation(nonce, { op: 'approval.approve', id: 'ap_harmless' })
  const actuallyRunning = wa.challengeForOperation(nonce, { op: 'approval.approve', id: 'ap_dangerous' })
  const assertion = auth.assert(signedFor)
  assert.throws(() => verify(enrolled, assertion, actuallyRunning), /challenge does not match/)
})

test('the operation challenge changes with every field of the operation', () => {
  const nonce = randomBytes(32)
  const base = wa.challengeForOperation(nonce, { op: 'session.create', cred: 'gh', paths: ['/a'] })
  const differentCred = wa.challengeForOperation(nonce, { op: 'session.create', cred: 'slack', paths: ['/a'] })
  const differentPaths = wa.challengeForOperation(nonce, { op: 'session.create', cred: 'gh', paths: ['/**'] })
  assert.ok(!base.equals(differentCred))
  assert.ok(!base.equals(differentPaths))
})

test('the same operation with a fresh nonce yields a fresh challenge', () => {
  const op = { op: 'vault.lock' }
  assert.ok(!wa.challengeForOperation(randomBytes(32), op).equals(wa.challengeForOperation(randomBytes(32), op)))
})

test('an assertion from another origin is refused', () => {
  const auth = makeAuthenticator()
  const enrolled = enrol(auth)
  const challenge = wa.challengeForOperation(randomBytes(32), { op: 'vault.lock' })
  assert.throws(
    () => verify(enrolled, auth.assert(challenge, { origin: 'https://evil.test' }), challenge),
    /is not this server/,
  )
})

test('a registration response replayed as an assertion is refused', () => {
  const auth = makeAuthenticator()
  const enrolled = enrol(auth)
  const challenge = wa.challengeForOperation(randomBytes(32), { op: 'vault.lock' })
  assert.throws(
    () => verify(enrolled, auth.assert(challenge, { type: 'webauthn.create' }), challenge),
    /type is webauthn.create/,
  )
})

test('an assertion without user verification is refused', () => {
  // A touch alone is not enough: the gate needs the platform to have verified
  // a human, which is what the fingerprint or device password does.
  const auth = makeAuthenticator()
  const enrolled = enrol(auth)
  const challenge = wa.challengeForOperation(randomBytes(32), { op: 'vault.lock' })
  assert.throws(() => verify(enrolled, auth.assert(challenge, { uv: false }), challenge), /did not verify a human/)
})

test('a signature counter that goes backwards is treated as a cloned credential', () => {
  const auth = makeAuthenticator()
  const enrolled = { ...enrol(auth), signCount: 10 }
  const challenge = wa.challengeForOperation(randomBytes(32), { op: 'vault.lock' })
  assert.throws(() => verify(enrolled, auth.assert(challenge, { signCount: 5 }), challenge), /may have been cloned/)
})

test('only ES256 on P-256 is accepted', () => {
  assert.throws(() => wa.coseToPublicKey(new Map([[1, 3], [3, -257]])), /only EC2 is accepted/)
  assert.throws(() => wa.coseToPublicKey(new Map([[1, 2], [3, -257]])), /only ES256 is accepted/)
  assert.throws(() => wa.coseToPublicKey(new Map([[1, 2], [3, -7], [-1, 2]])), /only P-256 is accepted/)
})

test('the CBOR reader rejects what it does not understand rather than guessing', () => {
  assert.throws(() => wa.decodeCbor(Buffer.from([0xff])), /cbor:/)
})

test('an assertion is bounded before anything parses it', () => {
  // A real assertion is tiny: authenticatorData is 37 bytes plus extensions,
  // clientDataJSON a few hundred, the signature about seventy. Nothing bounded
  // any of them, and all three were parsed BEFORE the signature was checked —
  // so an unauthenticated caller on the control socket could hand over
  // megabytes and have the daemon decode all of it on the event loop, per
  // request, before rejecting it.
  //
  // Work done for a caller who has proved nothing should fit in a breath.
  const enrolled = { credentialId: 'c', publicKeySpki: Buffer.alloc(91).toString('base64'), signCount: 0 }
  const huge = 'A'.repeat(4 * 1024 * 1024)
  const small = Buffer.from('{}').toString('base64url')

  for (const field of ['authenticatorData', 'clientDataJSON', 'signature']) {
    const args = {
      credentialId: 'c',
      authenticatorData: small,
      clientDataJSON: small,
      signature: small,
      expectedChallenge: Buffer.alloc(32),
      expectedOrigins: ['http://localhost:1'],
      rpId: 'localhost',
      enrolled,
      [field]: huge,
    }
    // The refusal names the size, which is only possible if it happened on the
    // size check rather than after something parsed four megabytes.
    assert.throws(() => wa.verifyAssertion(args), new RegExp(`${field} is \\d+ characters`),
      `${field} was not bounded`)
  }
})
