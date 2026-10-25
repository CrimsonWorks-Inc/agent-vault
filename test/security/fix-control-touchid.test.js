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

// Round 3, review finding 5, resolved per the owner's decision (option C).
// A vault whose only human factor is the confirmation authenticator — a
// passphrase was set to enrol it, then removed — is still refused the Touch ID
// UNLOCK factor, because the passphrase is the recovery factor and a vault
// must never be left without one. The refusal is now the one an owner can act
// on: factor_order, naming `agent-vault passphrase set`, given before the tap.
// The owner's Touch ID-only vault is served by the presence key instead, which
// rotates by an assertion from the key being replaced.

const NEXT = 'agent-vault passphrase set'

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

/** The refusal, wherever it comes from: the daemon's problem, or the UI's copy of it. */
function assertPassphraseFirst(status, problem) {
  assert.equal(status, 403, JSON.stringify(problem))
  assert.equal(problem.code, 'AV_POLICY_DENIED')
  assert.equal(problem.rule, 'factor_order')
  assert.match(problem.hint, /agent-vault passphrase set/)
  assert.match(problem.hint, /recovery|fall back/)
  assert.equal(problem.next, NEXT)
}

test('without a passphrase, Touch ID unlock is refused before the tap, and says what to do', async () => {
  const t = await authenticatorOnly()
  try {
    const body = enrolBody()
    // No proof at all: the answer is the way forward, not a request for a tap.
    const bare = await t.d.control('POST', '/v1/factors/webauthn', { action: 'enroll', ...body })
    assertPassphraseFirst(bare.status, bare.body)
    // An open window and a passphrase proof change nothing.
    t.d.daemon.presenceGraceUntil = Date.now() + 60_000
    const windowed = await t.d.control('POST', '/v1/factors/webauthn', { action: 'enroll', ...body, presence: { passphrase: PASSPHRASE } })
    t.d.daemon.presenceGraceUntil = 0
    assertPassphraseFirst(windowed.status, windowed.body)
    // A real tap from the enrolled authenticator, through the web UI, is
    // refused the same way: the owner is not the problem, the missing
    // recovery factor is.
    const presence = await t.u.presence(t.a, operationFor('touchid.enroll', body))
    const res = await t.u.api('POST', 'touchid/enroll', { ...body, presence })
    const out = await res.json()
    assertPassphraseFirst(res.status, out.detail)

    // The store refuses too, if anything calls it directly.
    assert.throws(() => t.d.vault.addWebauthnUnlock(body.credential_id, body.prf_secret),
      (e) => e.rule === 'factor_order' && e.next === NEXT)
    assert.ok(!t.d.vault.hasWebauthnUnlock)
    assert.deepEqual(t.d.vault.db.kv.vmk_wraps.map((w) => w.class), ['none'])
    assert.ok(!t.d.vault.audit.read({ limit: 50 }).some((r) => r.kind === 'presence.factor_added' && r.class === 'webauthn-prf'))
  } finally { await t.stop() }
})

test('once a passphrase is set, the same vault enrols Touch ID unlock with one tap, and both open it', async () => {
  const t = await authenticatorOnly()
  try {
    t.d.vault.setPassphrase(PASSPHRASE)
    const body = enrolBody()
    const presence = await t.u.presence(t.a, operationFor('touchid.enroll', body))
    const res = await t.u.api('POST', 'touchid/enroll', { ...body, presence })
    const out = await res.json()
    assert.equal(res.status, 200, JSON.stringify(out))
    assert.deepEqual(out, { ok: true, enrolled: true }, 'the answer is what it was before option A')
    assert.deepEqual(t.d.vault.db.kv.vmk_wraps.map((w) => w.class).sort(), ['passphrase', 'webauthn-prf'])

    // The fingerprint opens it, and so does the passphrase it fell back on.
    for (const unlock of [{ prf_secret: body.prf_secret }, { passphrase: PASSPHRASE }]) {
      assert.equal((await t.d.control('POST', '/v1/lock', {})).status, 200)
      const opened = await t.d.control('POST', '/v1/unlock', unlock)
      assert.equal(opened.status, 200, JSON.stringify(opened.body))
      assert.equal(t.d.vault.locked, false)
    }
    // And the passphrase cannot now be removed out from under it.
    assert.throws(() => t.d.vault.removePassphrase(PASSPHRASE), /remove Touch ID unlock first/)
  } finally { await t.stop() }
})

test('a vault with no factor at all is refused Touch ID unlock with the same way forward', async () => {
  const d = await startDaemon()
  try {
    const res = await d.control('POST', '/v1/factors/webauthn', { action: 'enroll', ...enrolBody() })
    assertPassphraseFirst(res.status, res.body)
    assert.ok(!d.vault.hasWebauthnUnlock)
  } finally { await d.stop() }
})

test('without a passphrase, the presence authenticator rotates by a tap from itself, through the UI', async () => {
  const t = await authenticatorOnly()
  try {
    const next = makeAuthenticator(t.u.ui.origin)
    // Unproved, or by window, it does not move.
    const unsigned = await t.d.control('POST', '/v1/presence', next.record)
    assert.equal(unsigned.status, 401, JSON.stringify(unsigned.body))
    t.d.daemon.presenceGraceUntil = Date.now() + 60_000
    const windowed = await t.d.control('POST', '/v1/presence', next.record)
    t.d.daemon.presenceGraceUntil = 0
    assert.equal(windowed.status, 401, JSON.stringify(windowed.body))
    assert.equal(t.d.vault.db.kv.webauthn.credentialId, t.a.record.credentialId)

    // Signed by the current key, over a challenge minted through the web UI.
    const presence = await t.u.presence(t.a, operationFor('presence.enroll', next.record))
    const rotated = await t.d.control('POST', '/v1/presence', { ...next.record, presence })
    assert.equal(rotated.status, 200, JSON.stringify(rotated.body))
    assert.equal(rotated.body.replaced, true)
    assert.equal(t.d.vault.db.kv.webauthn.credentialId, next.record.credentialId)

    // The old key no longer signs anything; the new one does.
    const third = makeAuthenticator(t.u.ui.origin)
    const byOld = await t.u.presence(t.a, operationFor('presence.enroll', third.record))
    const refused = await t.d.control('POST', '/v1/presence', { ...third.record, presence: byOld })
    assert.notEqual(refused.status, 200, JSON.stringify(refused.body))
    const byNew = await t.u.presence(next, operationFor('presence.enroll', third.record))
    const again = await t.d.control('POST', '/v1/presence', { ...third.record, presence: byNew })
    assert.equal(again.status, 200, JSON.stringify(again.body))
    assert.equal(t.d.vault.db.kv.webauthn.credentialId, third.record.credentialId)
    assert.equal(t.d.vault.hasPassphrase, false, 'rotating never needed a passphrase')
  } finally { await t.stop() }
})

test('a first presence enrolment without a passphrase is refused with the same way forward', async () => {
  const d = await startDaemon()
  try {
    const res = await d.control('POST', '/v1/presence', makeAuthenticator().record)
    assert.equal(res.status, 403, JSON.stringify(res.body))
    assert.equal(res.body.rule, 'factor_order')
    assert.match(res.body.hint, /agent-vault passphrase set/)
    assert.equal(res.body.next, NEXT)
    assert.equal(d.vault.db.kv.webauthn ?? null, null)
  } finally { await d.stop() }
})
