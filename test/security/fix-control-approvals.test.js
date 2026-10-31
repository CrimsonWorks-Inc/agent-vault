// Every answer to a held request needs the human, not only "yes".
//
// Denying was left ungated on the theory that it only narrows. It did not: an
// approval that had already run kept its cached response, and denying it handed
// that response back to whoever asked — including the `av-placeholder-next`
// successor, which works as a carrier on its own. Re-granting one re-armed it.
// So a deny is now held to the same proof as a grant, and the control response
// never carries the cached upstream result.

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { operationFor } from '../../src/ui/webauthn.js'
import { startDaemon, makeAuthenticator, enrol, signed, PASSPHRASE } from './fix-control-helpers.js'

let d, auth, token, placeholder, upstreamHits = 0, n = 0

const gateway = (method, path, body) => fetch(`http://127.0.0.1:${d.daemon.gatewayPort}${path}`, {
  method,
  headers: { 'av-session': token, authorization: `Bearer ${placeholder}` },
  body,
})

/** A held write, waiting for an answer. Each is a distinct request. */
async function held() {
  const path = `/p/demo/things/${++n}`
  const res = await gateway('POST', path, 'x')
  assert.equal(res.status, 202, await res.text())
  held.path = path
  return res.headers.get('av-approval-id')
}

before(async () => {
  d = await startDaemon({ passphrase: PASSPHRASE })
  auth = makeAuthenticator()
  enrol(d.vault, auth)
  d.daemon.pipeline.upstream = async () => {
    upstreamHits++
    return { status: 200, headers: { 'content-type': 'text/plain' }, body: Buffer.from('ok') }
  }
  d.daemon.presenceGraceUntil = Date.now() + 60_000
  const s = await d.control('POST', '/v1/sessions', { cred: 'demo', methods: ['GET', 'POST'], paths: ['/**'], approval: 'on-write', uses: 1 })
  assert.equal(s.status, 200, JSON.stringify(s.body))
  d.daemon.presenceGraceUntil = 0
  token = s.body.token
  placeholder = s.body.placeholder
})
after(() => d?.stop())

test('denying with no human present is refused, and the request stays pending', async () => {
  const id = await held()
  const res = await d.control('POST', '/v1/approvals', { id, granted: false })
  assert.equal(res.status, 401, JSON.stringify(res.body))
  assert.equal(res.body.code, 'AV_PRESENCE_REQUIRED')
  assert.ok(d.daemon.pipeline.pendingApprovals().some((a) => a.id === id))
})

test('a signature for approving cannot be spent on denying', async () => {
  const id = await held()
  const presence = await signed(d.control, auth, operationFor('approval.approve', { id, granted: true }))
  const res = await d.control('POST', '/v1/approvals', { id, granted: false, presence })
  assert.equal(res.status, 401, JSON.stringify(res.body))
})

test('a deny signed for exactly that deny goes through, as the UI sends it', async () => {
  const id = await held()
  const presence = await signed(d.control, auth, operationFor('approval.deny', { id, granted: false }))
  const res = await d.control('POST', '/v1/approvals', { id, granted: false, presence })
  assert.equal(res.status, 200, JSON.stringify(res.body))
  assert.equal(res.body.state, 'denied')
})

test('a deny inside a passphrase window goes through, as the CLI sends it', async () => {
  const id = await held()
  d.daemon.presenceGraceUntil = Date.now() + 60_000
  try {
    const res = await d.control('POST', '/v1/approvals', { id, granted: false })
    assert.equal(res.status, 200, JSON.stringify(res.body))
  } finally { d.daemon.presenceGraceUntil = 0 }
})

test('an approval that already ran never hands its cached response back', async () => {
  const id = await held()
  const presence = await signed(d.control, auth, operationFor('approval.approve', { id, granted: true }))
  const ok = await d.control('POST', '/v1/approvals', { id, granted: true, presence })
  assert.equal(ok.status, 200, JSON.stringify(ok.body))
  const before = upstreamHits
  const ran = await gateway('POST', held.path, 'x')
  assert.equal(ran.status, 200, await ran.text())
  assert.equal(upstreamHits, before + 1)

  // Whatever the state machine decides about a second answer, the control
  // response must not carry the response the agent's request got.
  d.daemon.presenceGraceUntil = Date.now() + 60_000
  try {
    const again = await d.control('POST', '/v1/approvals', { id, granted: false })
    assert.ok(!('result' in again.body), JSON.stringify(again.body))
    assert.ok(!JSON.stringify(again.body).includes('av-placeholder-next'))
  } finally { d.daemon.presenceGraceUntil = 0 }

  const pending = await d.control('GET', '/v1/approvals')
  assert.ok(!JSON.stringify(pending.body).includes('av-placeholder-next'))
})
