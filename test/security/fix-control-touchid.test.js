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
