// Who may change who can prove presence, and where a proof may come from.
//
// - The passphrase window is one daemon-wide timestamp. While a human's
//   ordinary command had it open, any caller on the socket could wrap the
//   master key to a PRF secret of its own or replace the presence
//   authenticator with its own key — permanent possession, from five minutes
//   of someone else's presence. Those routes now need the proof in the request
//   itself: the passphrase, or an assertion from the enrolled authenticator.
// - What the window admitted was not recorded per operation, and locking did
//   not close it.
// - The daemon checked an assertion's origin against origins the CALLER named
//   when minting the challenge, so a page an agent served on any localhost
//   port could collect a valid signature. The daemon now decides which UI
//   origins it trusts.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { operationFor } from '../../src/ui/webauthn.js'
import * as server from '../../src/daemon/server.js'
import { startDaemon, startUi, makeAuthenticator, enrol, signed, PASSPHRASE } from './fix-control-helpers.js'

const DEFAULT_UI_PORT = server.DEFAULT_UI_PORT ?? 7412
const prf = () => randomBytes(32).toString('base64')
const kinds = (d) => d.vault.audit.read({ limit: 300 }).map((r) => r.kind)

test('the shared window cannot enrol an unlock factor or replace the authenticator', async () => {
  const d = await startDaemon({ passphrase: PASSPHRASE })
  try {
    const human = makeAuthenticator()
    enrol(d.vault, human)
    d.daemon.presenceGraceUntil = Date.now() + 60_000 // the human's window, for some other command
    const unlock = await d.control('POST', '/v1/factors/webauthn', { action: 'enroll', credential_id: 'agent', prf_secret: prf() })
    assert.equal(unlock.status, 401, JSON.stringify(unlock.body))
    assert.equal(unlock.body.rule, 'fresh_presence')
    assert.equal(d.vault.hasWebauthnUnlock, false)

    const agent = makeAuthenticator()
    const swap = await d.control('POST', '/v1/presence', agent.record)
    assert.equal(swap.status, 401, JSON.stringify(swap.body))
    assert.equal(d.vault.db.kv.webauthn.credentialId, human.record.credentialId, 'the authenticator was replaced')
  } finally { await d.stop() }
})

test('with the passphrase in the request, the same changes go through', async () => {
  const d = await startDaemon({ passphrase: PASSPHRASE })
  try {
    const human = makeAuthenticator()
    const first = await d.control('POST', '/v1/presence', { ...human.record, presence: { passphrase: PASSPHRASE } })
    assert.equal(first.status, 200, JSON.stringify(first.body))
    assert.equal(d.vault.db.kv.webauthn.presence, undefined, 'the passphrase was stored with the key')
    assert.deepEqual(Object.keys(d.vault.db.kv.webauthn).sort(), Object.keys(human.record).sort())

    const wrong = await d.control('POST', '/v1/factors/webauthn', { action: 'enroll', credential_id: 'c', prf_secret: prf(), presence: { passphrase: 'nope nope nope' } })
    assert.equal(wrong.status, 403, JSON.stringify(wrong.body))
    assert.equal(wrong.body.code, 'AV_PRESENCE_DENIED')
    assert.equal(wrong.body.rule, 'fresh_presence')

    const right = await d.control('POST', '/v1/factors/webauthn', { action: 'enroll', credential_id: 'c', prf_secret: prf(), presence: { passphrase: PASSPHRASE } })
    assert.equal(right.status, 200, JSON.stringify(right.body))
    assert.ok(d.vault.hasWebauthnUnlock)
  } finally { await d.stop() }
})

test('a vault with only an authenticator can still rotate it, by assertion', async () => {
  const d = await startDaemon({ passphrase: PASSPHRASE })
  try {
    const human = makeAuthenticator()
    enrol(d.vault, human)
    d.vault.removePassphrase(PASSPHRASE)
    assert.equal(d.vault.hasPassphrase, false)

    const next = makeAuthenticator()
    const unsigned = await d.control('POST', '/v1/presence', next.record)
    assert.equal(unsigned.status, 401, 'no proof, no rotation')

    const presence = await signed(d.control, human, operationFor('presence.enroll', next.record))
    const rotated = await d.control('POST', '/v1/presence', { ...next.record, presence })
    assert.equal(rotated.status, 200, JSON.stringify(rotated.body))
    assert.equal(d.vault.db.kv.webauthn.credentialId, next.record.credentialId)
    assert.equal(d.vault.db.kv.webauthn.presence, undefined, 'the proof is not stored as part of the key')
  } finally { await d.stop() }
})

test('removing Touch ID unlock by assertion works; by window it does not', async () => {
  const d = await startDaemon({ passphrase: PASSPHRASE })
  try {
    const human = makeAuthenticator()
    enrol(d.vault, human)
    d.vault.addWebauthnUnlock('c', prf())
    d.daemon.presenceGraceUntil = Date.now() + 60_000
    const byWindow = await d.control('POST', '/v1/factors/webauthn', { action: 'remove' })
    assert.equal(byWindow.status, 401)
    d.daemon.presenceGraceUntil = 0
    const presence = await signed(d.control, human, operationFor('touchid.remove', {}))
    const ok = await d.control('POST', '/v1/factors/webauthn', { action: 'remove', presence })
    assert.equal(ok.status, 200, JSON.stringify(ok.body))
    assert.equal(d.vault.hasWebauthnUnlock, false)
  } finally { await d.stop() }
})

test('one window still covers an ordinary multi-step flow, and each step is recorded', async () => {
  const d = await startDaemon({ passphrase: PASSPHRASE })
  try {
    const opened = await d.control('POST', '/v1/presence/window', { passphrase: PASSPHRASE })
    assert.equal(opened.status, 200)
    // What the wizard does after one prompt: add a credential, make a session,
    // issue a placeholder. None of these may ask again.
    const cred = await d.control('POST', '/v1/credentials', { slug: 'second', kind: 'http', host: 'api.other.com', value: 'sk-test-000111222333444' })
    assert.equal(cred.status, 200, JSON.stringify(cred.body))
    const s = await d.control('POST', '/v1/sessions', { cred: 'second' })
    assert.equal(s.status, 200, JSON.stringify(s.body))
    const p = await d.control('POST', '/v1/placeholders', { cred: 'second', sid: s.body.session_id })
    assert.equal(p.status, 200, JSON.stringify(p.body))
    const used = d.vault.audit.read({ limit: 100 }).filter((r) => r.kind === 'presence.window_used').map((r) => r.op)
    assert.deepEqual(used, ['cred add', 'session create', 'placeholder issue'])
  } finally { await d.stop() }
})

test('locking closes the window', async () => {
  const d = await startDaemon({ passphrase: PASSPHRASE })
  try {
    await d.control('POST', '/v1/presence/window', { passphrase: PASSPHRASE })
    await d.control('POST', '/v1/lock')
    d.vault.unlockWith({ passphrase: PASSPHRASE })
    const s = await d.control('POST', '/v1/sessions', { cred: 'demo' })
    assert.equal(s.status, 401, 'the window outlived the lock')
  } finally { await d.stop() }
})

test('the web UI enrolment passes the passphrase through, with no window', async () => {
  const d = await startDaemon({ passphrase: PASSPHRASE })
  const u = await startUi(d)
  try {
    const human = makeAuthenticator(u.ui.origin)
    const begin = await (await u.api('POST', 'presence/enroll/begin')).json()
    const reg = registration(human, begin.challenge, u.ui.origin)
    const res = await u.api('POST', 'presence/enroll/finish', { ...reg, passphrase: PASSPHRASE })
    assert.equal(res.status, 200, JSON.stringify(await res.json()))
    assert.ok(d.vault.db.kv.webauthn)
    assert.equal(d.daemon.presenceGraceUntil, 0, 'no window was opened to do it')
  } finally { await u.stop(); await d.stop() }
})

// ------------------------------------------------------------- UI origins

test('an assertion from a page the caller named is refused', async () => {
  const d = await startDaemon({ passphrase: PASSPHRASE })
  try {
    const human = makeAuthenticator('http://localhost:6666')
    enrol(d.vault, human)
    const op = operationFor('session.create', { cred: 'demo', approval: 'auto', methods: ['GET', 'POST', 'DELETE'] })
    // The caller names its own page as an allowed origin when minting.
    const ch = await d.control('POST', '/v1/presence/challenge', { operation: op, origins: ['http://localhost:6666'] })
    const presence = { challengeId: ch.body.challengeId, ...human.assert(ch.body.challenge, 'http://localhost:6666') }
    const res = await d.control('POST', '/v1/sessions', { cred: 'demo', approval: 'auto', methods: ['GET', 'POST', 'DELETE'], presence })
    assert.equal(res.status, 401, `a page on a port the daemon never trusted got a session: ${JSON.stringify(res.body)}`)
  } finally { await d.stop() }
})

test('an assertion from the default UI origin is accepted', async () => {
  const d = await startDaemon({ passphrase: PASSPHRASE })
  try {
    const origin = `http://localhost:${DEFAULT_UI_PORT}`
    const human = makeAuthenticator(origin)
    enrol(d.vault, human)
    const body = { cred: 'demo', methods: ['GET'] }
    const presence = await signed(d.control, human, operationFor('session.create', body))
    const res = await d.control('POST', '/v1/sessions', { ...body, presence })
    assert.equal(res.status, 200, JSON.stringify(res.body))
    const ui = await d.control('GET', '/v1/ui')
    assert.equal(ui.body.port, DEFAULT_UI_PORT)
    assert.deepEqual(ui.body.origins, [origin])
  } finally { await d.stop() }
})

test('trusting another UI origin needs the owner, and then it works', async () => {
  const d = await startDaemon({ passphrase: PASSPHRASE })
  try {
    const origin = 'http://localhost:9123'
    const human = makeAuthenticator(origin)
    enrol(d.vault, human)
    d.daemon.presenceGraceUntil = Date.now() + 60_000
    const byWindow = await d.control('POST', '/v1/ui/origins', { origin })
    assert.equal(byWindow.status, 401, 'an origin was trusted on the strength of a shared window')
    d.daemon.presenceGraceUntil = 0
    for (const bad of ['http://evil.example:9123', 'https://localhost:9123', 'http://localhost', 'http://localhost:99999', 'http://localhost:9123/x']) {
      const r = await d.control('POST', '/v1/ui/origins', { origin: bad, presence: { passphrase: PASSPHRASE } })
      assert.ok(r.status >= 400, `accepted ${bad}`)
    }
    const added = await d.control('POST', '/v1/ui/origins', { origin, presence: { passphrase: PASSPHRASE } })
    assert.equal(added.status, 200, JSON.stringify(added.body))
    assert.ok(kinds(d).includes('ui.origin_added'))

    const body = { cred: 'demo', methods: ['GET'] }
    const presence = await signed(d.control, human, operationFor('session.create', body))
    const res = await d.control('POST', '/v1/sessions', { ...body, presence })
    assert.equal(res.status, 200, JSON.stringify(res.body))
  } finally { await d.stop() }
})

/** A `none` attestation for the synthetic authenticator, as the page would send. */
function registration(auth, challenge, origin) {
  return auth.register(challenge, origin)
}

test('with no factor enrolled, a fresh-presence change is refused, not waved through', async () => {
  const d = await startDaemon()
  try {
    const res = await d.control('POST', '/v1/ui/origins', { origin: 'http://localhost:9124' })
    assert.equal(res.status, 401, JSON.stringify(res.body))
    assert.equal(res.body.rule, 'factor_required')
    assert.deepEqual(res.body.factors, [])
  } finally { await d.stop() }
})

test('a fresh proof opens no window', async () => {
  const d = await startDaemon({ passphrase: PASSPHRASE })
  try {
    const ok = await d.control('POST', '/v1/ui/origins', { origin: 'http://localhost:9125', presence: { passphrase: PASSPHRASE } })
    assert.equal(ok.status, 200, JSON.stringify(ok.body))
    assert.equal(d.daemon.presenceGraceUntil, 0)
    assert.ok(d.vault.audit.read({ limit: 20 }).some((r) => r.kind === 'presence.verified' && r.fresh === true && r.factor === 'passphrase'))
  } finally { await d.stop() }
})
