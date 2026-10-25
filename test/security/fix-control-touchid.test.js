// Touch ID unlock, enrolled and removed from the web UI.
//
// Neither worked. The page signed `{ op: 'touchid.enroll' }` with no fields,
// the UI server bound the operation to the request body, and the daemon bound
// it to the body plus `action` — three different operations for one tap. The
// UI server then dropped the proof when it forwarded the call, so the daemon
// refused it as having no human behind it. Now all three bind the same thing,
// and the proof travels.

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { operationFor } from '../../src/ui/webauthn.js'
import { startDaemon, startUi, makeAuthenticator, enrol, PASSPHRASE } from './fix-control-helpers.js'

let d, u, auth
before(async () => {
  d = await startDaemon({ passphrase: PASSPHRASE })
  u = await startUi(d)
  auth = makeAuthenticator(u.ui.origin)
  enrol(d.vault, auth)
})
after(async () => { await u?.stop(); await d?.stop() })

const enrolBody = () => ({ credential_id: randomBytes(16).toString('base64url'), prf_secret: randomBytes(32).toString('base64') })

test('enrolling Touch ID unlock from the UI works with one tap', async () => {
  const body = enrolBody()
  const presence = await u.presence(auth, operationFor('touchid.enroll', body))
  const res = await u.api('POST', 'touchid/enroll', { ...body, presence })
  assert.equal(res.status, 200, JSON.stringify(await res.json()))
  assert.ok(d.vault.hasWebauthnUnlock, 'the unlock factor should now exist')
})

test('a tap over one PRF secret cannot enrol another', async () => {
  const signedFor = enrolBody()
  const presence = await u.presence(auth, operationFor('touchid.enroll', signedFor))
  const res = await u.api('POST', 'touchid/enroll', { ...signedFor, prf_secret: randomBytes(32).toString('base64'), presence })
  assert.notEqual(res.status, 200)
})

test('the daemon still refuses an enrol that carries no proof at all', async () => {
  const res = await d.control('POST', '/v1/factors/webauthn', { action: 'enroll', ...enrolBody() })
  assert.equal(res.status, 401)
  assert.equal(res.body.code, 'AV_PRESENCE_REQUIRED')
})

test('removing Touch ID unlock from the UI works with one tap', async () => {
  assert.ok(d.vault.hasWebauthnUnlock)
  const presence = await u.presence(auth, operationFor('touchid.remove', {}))
  const res = await u.api('POST', 'touchid/remove', { presence })
  assert.equal(res.status, 200, JSON.stringify(await res.json()))
  assert.ok(!d.vault.hasWebauthnUnlock, 'the unlock factor should be gone')
})

// Round 2. A vault whose only human factor is the confirmation authenticator
// — a passphrase was set to enrol it, then removed — could rotate that
// authenticator by assertion, but enrolling the Touch ID UNLOCK factor was
// refused after the assertion had been verified: "set a passphrase first".
// The owner's requirement is that such a vault can enrol and remove factors
// with a signature from its authenticator. End to end, through the web UI.

/** A daemon and UI whose vault has an authenticator and no passphrase. */
async function authenticatorOnly() {
  const d = await startDaemon({ passphrase: PASSPHRASE })
  const u = await startUi(d)
  const a = makeAuthenticator(u.ui.origin)
  enrol(d.vault, a)
  d.vault.removePassphrase(PASSPHRASE)
  assert.equal(d.vault.hasPassphrase, false)
  assert.deepEqual(d.vault.db.kv.vmk_wraps.map((w) => w.class), ['none'], 'the fixture is authenticator-only')
  return { d, u, a, stop: async () => { await u.stop(); await d.stop() } }
}

test('an authenticator-only vault enrols Touch ID unlock with one tap, and it unlocks the vault', async () => {
  const t = await authenticatorOnly()
  try {
    const body = enrolBody()
    const presence = await t.u.presence(t.a, operationFor('touchid.enroll', body))
    const res = await t.u.api('POST', 'touchid/enroll', { ...body, presence })
    const out = await res.json()
    assert.equal(res.status, 200, JSON.stringify(out))
    assert.equal(out.recovery, false, 'the answer says there is no recovery factor')
    assert.ok(t.d.vault.hasWebauthnUnlock)
    assert.ok(t.d.vault.audit.read({ limit: 20 }).some((r) => r.kind === 'presence.factor_added' && r.class === 'webauthn-prf' && r.recovery === false))

    // It is a real lock now: nothing opens it but the PRF secret.
    assert.equal((await t.d.control('POST', '/v1/lock', {})).status, 200)
    const bare = await t.d.control('POST', '/v1/unlock', {})
    assert.notEqual(bare.status, 200, 'the vault opened with no factor')
    const wrong = await t.d.control('POST', '/v1/unlock', { prf_secret: randomBytes(32).toString('base64') })
    assert.notEqual(wrong.status, 200)
    const right = await t.d.control('POST', '/v1/unlock', { prf_secret: body.prf_secret })
    assert.equal(right.status, 200, JSON.stringify(right.body))
    assert.equal(t.d.vault.locked, false)

    // And removed the same way, leaving a vault that still opens.
    const off = await t.u.presence(t.a, operationFor('touchid.remove', {}))
    const removed = await t.u.api('POST', 'touchid/remove', { presence: off })
    assert.equal(removed.status, 200, JSON.stringify(await removed.json()))
    assert.ok(!t.d.vault.hasWebauthnUnlock)
    assert.deepEqual(t.d.vault.db.kv.vmk_wraps.map((w) => w.class), ['none'], 'removing the only key-bearing factor must not strand the vault')
  } finally { await t.stop() }
})

test('an authenticator-only vault still refuses an unlock enrolment without the authenticator', async () => {
  const t = await authenticatorOnly()
  try {
    const body = enrolBody()
    const none = await t.d.control('POST', '/v1/factors/webauthn', { action: 'enroll', ...body })
    assert.equal(none.status, 401, JSON.stringify(none.body))
    // There is no passphrase to check, so a passphrase proof proves nothing.
    const phrase = await t.d.control('POST', '/v1/factors/webauthn', { action: 'enroll', ...body, presence: { passphrase: PASSPHRASE } })
    assert.notEqual(phrase.status, 200, JSON.stringify(phrase.body))
    // An open window does not count for a factor change either.
    t.d.daemon.presenceGraceUntil = Date.now() + 60_000
    const windowed = await t.d.control('POST', '/v1/factors/webauthn', { action: 'enroll', ...body })
    t.d.daemon.presenceGraceUntil = 0
    assert.notEqual(windowed.status, 200, JSON.stringify(windowed.body))
    // A tap over a different PRF secret does not enrol this one.
    const presence = await t.u.presence(t.a, operationFor('touchid.enroll', enrolBody()))
    const swapped = await t.u.api('POST', 'touchid/enroll', { ...body, presence })
    assert.notEqual(swapped.status, 200)
    assert.ok(!t.d.vault.hasWebauthnUnlock)
  } finally { await t.stop() }
})

test('a vault with no factor at all still cannot enrol Touch ID unlock', async () => {
  const d = await startDaemon()
  try {
    const res = await d.control('POST', '/v1/factors/webauthn', { action: 'enroll', ...enrolBody() })
    assert.notEqual(res.status, 200, JSON.stringify(res.body))
    assert.equal(res.body.rule, 'factor_required')
    assert.ok(!d.vault.hasWebauthnUnlock)
  } finally { await d.stop() }
})

test('the store still wants a passphrase unless the caller says there is to be no recovery', async () => {
  const t = await authenticatorOnly()
  try {
    const body = enrolBody()
    assert.throws(() => t.d.vault.addWebauthnUnlock(body.credential_id, body.prf_secret), /set a passphrase first/)
    assert.ok(!t.d.vault.hasWebauthnUnlock)
  } finally { await t.stop() }
})

test('with a passphrase, enrolling reports the passphrase as the recovery factor', async () => {
  // The shared vault has a passphrase; enrol and remove again there.
  const body = enrolBody()
  const presence = await u.presence(auth, operationFor('touchid.enroll', body))
  const res = await u.api('POST', 'touchid/enroll', { ...body, presence })
  const out = await res.json()
  assert.equal(res.status, 200, JSON.stringify(out))
  assert.equal(out.recovery, true)
  assert.deepEqual(d.vault.db.kv.vmk_wraps.map((w) => w.class).sort(), ['passphrase', 'webauthn-prf'])
  const off = await u.presence(auth, operationFor('touchid.remove', {}))
  assert.equal((await u.api('POST', 'touchid/remove', { presence: off })).status, 200)
})
