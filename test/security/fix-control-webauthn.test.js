// The signed operation must name what was signed, and nothing a caller sends
// may rewrite it.
//
// operationFor started from `{ op }` and then copied every request field over
// it, so a field called `op` replaced the route's own name, and a field called
// `prf_secret_sha256` replaced the digest computed from the real secret. A
// signature for "create a narrow session" then authorised "issue a placeholder
// on the existing broad session", and a signature over the human's PRF secret
// installed one the agent chose.

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { operationFor, canonicalOperation } from '../../src/ui/webauthn.js'
import { startDaemon, makeAuthenticator, enrol, signed, PASSPHRASE } from './fix-control-helpers.js'

const sha = (s) => createHash('sha256').update(s).digest('hex')

/** The canonical operation, or the refusal — either way, never the signed one. */
const attempt = (op, params) => {
  try { return canonicalOperation(operationFor(op, params)) } catch (e) { return `refused: ${e.message}` }
}

test('a request field named op cannot replace the route op', () => {
  const fields = { cred: 'demo', methods: ['GET'], paths: ['/only'] }
  const shown = canonicalOperation(operationFor('session.create', fields))
  const executed = attempt('placeholder.issue', { ...fields, op: 'session.create' })
  assert.notEqual(executed, shown)
})

test('a supplied digest cannot replace the one computed from the secret', () => {
  const human = canonicalOperation(operationFor('touchid.enroll', { credential_id: 'c', prf_secret: 'HUMAN' }))
  const swapped = attempt('touchid.enroll', { credential_id: 'c', prf_secret: 'ATTACKER', prf_secret_sha256: sha('HUMAN') })
  assert.notEqual(swapped, human)
  const value = canonicalOperation(operationFor('cred.add', { slug: 's', value: 'HUMAN' }))
  assert.notEqual(attempt('cred.add', { slug: 's', value: 'ATTACKER', value_sha256: sha('HUMAN') }), value)
})

test('an ordinary request still binds every field, and the secret only by digest', () => {
  const op = operationFor('cred.add', { slug: 's', kind: 'http', value: 'v', presence: { x: 1 } })
  assert.deepEqual(op, { op: 'cred.add', slug: 's', kind: 'http', value_sha256: sha('v') })
})

let d, auth
before(async () => {
  d = await startDaemon({ passphrase: PASSPHRASE })
  auth = makeAuthenticator()
  enrol(d.vault, auth)
  // A broad session already exists: the thing the swap borrows.
  d.daemon.presenceGraceUntil = Date.now() + 60_000
  const s = await d.control('POST', '/v1/sessions', { cred: 'demo', methods: ['GET', 'POST', 'DELETE'], paths: ['/**'] })
  assert.equal(s.status, 200, JSON.stringify(s.body))
  d.daemon.presenceGraceUntil = 0
})
after(() => d?.stop())

test('a signature for a narrow session cannot issue a placeholder', async () => {
  const fields = { cred: 'demo', methods: ['GET'], paths: ['/only'] }
  const presence = await signed(d.control, auth, operationFor('session.create', fields))
  const before = d.vault.listPlaceholders().length
  const res = await d.control('POST', '/v1/placeholders', { ...fields, op: 'session.create', presence })
  assert.notEqual(res.status, 200, JSON.stringify(res.body))
  assert.ok(!res.body.placeholder, 'no placeholder may come back')
  assert.equal(d.vault.listPlaceholders().length, before, 'and none may be minted')
})

test('a signature over the real placeholder request still works', async () => {
  const body = { cred: 'demo' }
  const presence = await signed(d.control, auth, operationFor('placeholder.issue', body))
  const res = await d.control('POST', '/v1/placeholders', { ...body, presence })
  assert.equal(res.status, 200, JSON.stringify(res.body))
  assert.ok(res.body.placeholder)
})
