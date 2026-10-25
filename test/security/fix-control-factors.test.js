// The factor invariant (fix-control round 4).
//
// The owner's rule: an unlocked vault is never left without a usable human
// factor, and never holds a Touch ID (PRF) unlock wrap without the passphrase
// that recovers it. The re-review found three ways round it, each reproduced
// here against the route or the store that allowed it:
//
//   F1  removing the only passphrase returned the vault to the ungated
//       first-install state, so any caller on the socket could widen access;
//   F2  a presence-key rotation stored whatever it was sent, so a fresh
//       assertion could replace the sole usable key with `{}` or a key that
//       cannot verify anything, and the owner could never get back in;
//   F3  Vault.create made a PRF-only vault, skipping the recovery rule.
//
// The ordinary paths beside them must keep working: changing a passphrase,
// rotating to a real key, creating a vault with a passphrase, and a fresh
// vault with no passphrase staying on its 'none' wrap.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, existsSync, readFileSync, chmodSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { randomBytes, generateKeyPairSync } from 'node:crypto'
import { Vault } from '../../src/store/vault.js'
import { operationFor } from '../../src/ui/webauthn.js'
import { startDaemon, makeAuthenticator, enrol, signed, PASSPHRASE } from './fix-control-helpers.js'

const prf = () => randomBytes(32).toString('base64')
const spki = (type, opts) => generateKeyPairSync(type, opts).publicKey.export({ format: 'der', type: 'spki' }).toString('base64')

/** A daemon whose vault has a presence authenticator and no passphrase. */
async function authenticatorOnly() {
  const d = await startDaemon({ passphrase: PASSPHRASE })
  const human = makeAuthenticator()
  enrol(d.vault, human)
  d.vault.removePassphrase(PASSPHRASE)
  assert.equal(d.vault.hasPassphrase, false)
  return { d, human }
}

/** A widening call made with no proof at all: the agent's request. */
const unsignedSession = (d) => d.control('POST', '/v1/sessions', { cred: 'demo', methods: ['GET'], paths: ['/**'] })

// ------------------------------------------------------------------- F1

test('F1: the only passphrase cannot be removed, and the socket stays gated', async () => {
  const d = await startDaemon({ passphrase: PASSPHRASE })
  try {
    assert.equal((await unsignedSession(d)).status, 401, 'the fixture is gated')
    const disk = readFileSync(join(d.dir, 'vault.json'), 'utf8')

    const res = await d.control('POST', '/v1/passphrase', { action: 'remove', current: PASSPHRASE })
    assert.equal(res.status, 403, JSON.stringify(res.body))
    assert.equal(res.body.code, 'AV_POLICY_DENIED')
    assert.equal(res.body.rule, 'last_factor')
    assert.match(res.body.hint, /presence authenticator/)
    assert.equal(res.body.next, 'agent-vault ui')

    assert.equal(d.vault.hasPassphrase, true)
    assert.equal(readFileSync(join(d.dir, 'vault.json'), 'utf8'), disk, 'a refusal must not write the vault')
    assert.equal((await unsignedSession(d)).status, 401, 'an unsigned widening must still be refused')

    // And across a lock: a bare unlock is still refused.
    await d.control('POST', '/v1/lock', {})
    assert.equal((await d.control('POST', '/v1/unlock', {})).status, 423)
    assert.equal((await d.control('POST', '/v1/unlock', { passphrase: PASSPHRASE })).status, 200)
    assert.equal((await unsignedSession(d)).status, 401)
  } finally { await d.stop() }
})

test('F1: removing Touch ID unlock first does not make the passphrase removable', async () => {
  const d = await startDaemon({ passphrase: PASSPHRASE })
  try {
    d.vault.addWebauthnUnlock('c', prf())
    const first = await d.control('POST', '/v1/passphrase', { action: 'remove', current: PASSPHRASE })
    assert.equal(first.status, 403)
    assert.equal(first.body.rule, 'last_factor', 'Touch ID unlock still depends on the passphrase')
    assert.match(first.body.detail, /remove Touch ID unlock first/)

    d.vault.removeWebauthnUnlock()
    const second = await d.control('POST', '/v1/passphrase', { action: 'remove', current: PASSPHRASE })
    assert.equal(second.status, 403)
    assert.equal(second.body.rule, 'last_factor')
    assert.equal(d.vault.hasPassphrase, true)
    assert.equal((await unsignedSession(d)).status, 401)
  } finally { await d.stop() }
})

test('a wrong passphrase is still a failed proof, not a factor refusal', async () => {
  const d = await startDaemon({ passphrase: PASSPHRASE })
  try {
    const res = await d.control('POST', '/v1/passphrase', { action: 'remove', current: 'not the passphrase' })
    assert.equal(res.body.code, 'AV_LOCKED')
  } finally { await d.stop() }
})

test('control: with a presence authenticator left, the passphrase can be removed', async () => {
  const d = await startDaemon({ passphrase: PASSPHRASE })
  try {
    enrol(d.vault, makeAuthenticator())
    const res = await d.control('POST', '/v1/passphrase', { action: 'remove', current: PASSPHRASE })
    assert.equal(res.status, 200, JSON.stringify(res.body))
    assert.equal(d.vault.hasPassphrase, false)
    assert.equal((await unsignedSession(d)).status, 401, 'the authenticator keeps the socket gated')
  } finally { await d.stop() }
})

test('control: a passphrase changes with the current one', async () => {
  const d = await startDaemon({ passphrase: PASSPHRASE })
  try {
    const res = await d.control('POST', '/v1/passphrase', { action: 'set', passphrase: 'a brand new passphrase', current: PASSPHRASE })
    assert.equal(res.status, 200, JSON.stringify(res.body))
    assert.equal(d.vault.verifyPassphrase('a brand new passphrase'), true)
    assert.equal(d.vault.verifyPassphrase(PASSPHRASE), false)
  } finally { await d.stop() }
})

// ------------------------------------------------------------------- F2

/** Replacements the daemon could never verify a signature from. */
const BROKEN = {
  'an empty record': {},
  'the reviewer\'s broken key': { credentialId: 'broken', publicKeySpki: 'not-a-public-key', signCount: 0 },
  'no public key': { credentialId: randomBytes(16).toString('base64url'), signCount: 0 },
  'a public key that does not parse': { credentialId: randomBytes(16).toString('base64url'), publicKeySpki: Buffer.alloc(91).toString('base64'), signCount: 0 },
  'an Ed25519 key, which ES256 cannot verify': { credentialId: randomBytes(16).toString('base64url'), publicKeySpki: spki('ed25519'), signCount: 0 },
  'a P-384 key': { credentialId: randomBytes(16).toString('base64url'), publicKeySpki: spki('ec', { namedCurve: 'secp384r1' }), signCount: 0 },
  'a credential id too short to be one': { credentialId: 'aGVsbG8', publicKeySpki: spki('ec', { namedCurve: 'prime256v1' }), signCount: 0 },
  'a negative counter': { credentialId: randomBytes(16).toString('base64url'), publicKeySpki: spki('ec', { namedCurve: 'prime256v1' }), signCount: -1 },
  'a counter past 32 bits': { credentialId: randomBytes(16).toString('base64url'), publicKeySpki: spki('ec', { namedCurve: 'prime256v1' }), signCount: 2 ** 40 },
}

test('F2: a rotation to an unusable key is refused, and the sole key keeps working', async () => {
  const { d, human } = await authenticatorOnly()
  try {
    const original = structuredClone(d.vault.db.kv.webauthn)
    for (const [name, body] of Object.entries(BROKEN)) {
      // A real, fresh assertion from the key being replaced: the refusal is
      // about what is being installed, not about who asked.
      const presence = await signed(d.control, human, operationFor('presence.enroll', body))
      const res = await d.control('POST', '/v1/presence', { ...body, presence })
      assert.equal(res.status, 403, `${name}: ${JSON.stringify(res.body)}`)
      assert.equal(res.body.code, 'AV_POLICY_DENIED', name)
      assert.equal(res.body.rule, 'presence_key', name)
      assert.deepEqual(d.vault.db.kv.webauthn, original, `${name}: the old key was replaced`)
      const onDisk = JSON.parse(readFileSync(join(d.dir, 'vault.json'), 'utf8')).kv.webauthn
      assert.deepEqual(onDisk, original, `${name}: the old key was replaced on disk`)
    }

    // The original key still signs for the next change, and a real
    // replacement goes through (the ordinary rotation).
    const next = makeAuthenticator()
    const presence = await signed(d.control, human, operationFor('presence.enroll', next.record))
    const rotated = await d.control('POST', '/v1/presence', { ...next.record, presence })
    assert.equal(rotated.status, 200, JSON.stringify(rotated.body))
    assert.equal(rotated.body.replaced, true)
    assert.equal(d.vault.db.kv.webauthn.credentialId, next.record.credentialId)
  } finally { await d.stop() }
})

test('F2: a rotation stores the credential and nothing else the caller sent', async () => {
  const { d, human } = await authenticatorOnly()
  try {
    const next = makeAuthenticator()
    const body = { ...next.record, attestation: 'x'.repeat(64), extra: { anything: true } }
    const presence = await signed(d.control, human, operationFor('presence.enroll', body))
    const res = await d.control('POST', '/v1/presence', { ...body, presence })
    assert.equal(res.status, 200, JSON.stringify(res.body))
    assert.deepEqual(Object.keys(d.vault.db.kv.webauthn).sort(), ['credentialId', 'enrolledAt', 'publicKeySpki', 'signCount'])

    // And the new key is usable: it signs the next widening.
    const op = operationFor('session.create', { cred: 'demo', methods: ['GET'], paths: ['/**'] })
    const proof = await signed(d.control, next, op)
    const made = await d.control('POST', '/v1/sessions', { cred: 'demo', methods: ['GET'], paths: ['/**'], presence: proof })
    assert.equal(made.status, 200, JSON.stringify(made.body))
  } finally { await d.stop() }
})

test('F2: a first enrolment is held to the same shape', async () => {
  const d = await startDaemon({ passphrase: PASSPHRASE })
  try {
    const res = await d.control('POST', '/v1/presence', { ...BROKEN['the reviewer\'s broken key'], presence: { passphrase: PASSPHRASE } })
    assert.equal(res.status, 403, JSON.stringify(res.body))
    assert.equal(res.body.rule, 'presence_key')
    assert.equal(d.vault.db.kv.webauthn, undefined)
  } finally { await d.stop() }
})

test('a presence key that fails to save leaves the old one in place', () => {
  const dir = mkdtempSync(join(tmpdir(), 'av-fc-atomic-'))
  const v = Vault.create(dir, { factor: 'none' })
  try {
    v.setPassphrase(PASSPHRASE)
    v.setPresenceKey(makeAuthenticator().record)
    const original = structuredClone(v.db.kv.webauthn)
    chmodSync(dir, 0o500) // the write of the temp file fails
    assert.throws(() => v.setPresenceKey(makeAuthenticator().record))
    assert.deepEqual(v.db.kv.webauthn, original)
  } finally {
    chmodSync(dir, 0o700)
    rmSync(dir, { recursive: true, force: true })
  }
})

// ------------------------------------------------------------------- F3

test('F3: the store factory refuses a Touch ID unlock wrap with no passphrase', () => {
  const dir = mkdtempSync(join(tmpdir(), 'av-fc-create-'))
  try {
    const target = join(dir, 'v')
    assert.throws(
      () => Vault.create(target, { factor: 'webauthn-prf', passphrase: prf() }),
      (e) => e.code === 'AV_POLICY_DENIED' && e.rule === 'factor_order' && e.next === 'agent-vault passphrase set',
    )
    assert.equal(existsSync(join(target, 'vault.json')), false, 'no vault was written')
    assert.equal(existsSync(join(target, 'device.key')), false, 'nothing was written at all')
    assert.throws(() => Vault.create(target, { factor: 'webauthn' }), /unknown unlock factor/)
  } finally { rmSync(dir, { recursive: true, force: true }) }
})

test('control: a vault created with a passphrase opens with it and nothing else', () => {
  const dir = mkdtempSync(join(tmpdir(), 'av-fc-create-'))
  try {
    const v = Vault.create(dir, { factor: 'passphrase', passphrase: PASSPHRASE })
    assert.deepEqual(v.db.kv.vmk_wraps.map((w) => w.class), ['passphrase'])
    v.lock()
    assert.throws(() => Vault.open(dir).unlock(null), /AV_LOCKED/)
    assert.equal(Vault.open(dir).unlock(PASSPHRASE), true)
  } finally { rmSync(dir, { recursive: true, force: true }) }
})

test('control: a vault with no passphrase keeps its none wrap', () => {
  const dir = mkdtempSync(join(tmpdir(), 'av-fc-create-'))
  try {
    const v = Vault.create(dir, { factor: 'none' })
    assert.deepEqual(v.db.kv.vmk_wraps.map((w) => w.class), ['none'])
    // Removing Touch ID unlock from a vault that never had it is a no-op, and
    // the invariant does not object to a vault that never had a human factor.
    assert.equal(v.removeWebauthnUnlock(), false)
    assert.equal(v.removePassphrase('anything'), false)
    v.lock()
    assert.equal(Vault.open(dir).unlock(null), true)
  } finally { rmSync(dir, { recursive: true, force: true }) }
})
