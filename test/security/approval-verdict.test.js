// A verdict on a held request is true or false, and nothing else is either.
//
// POST /v1/approvals decided with `input.granted !== false`, so the string
// "false" — or 0, null, "no", or no field at all — approved the request. The
// web UI coerced with `!!body.granted` on its way to the daemon, which turned a
// string "false" into a real `true` before the daemon could look at it. Every
// one of these is refused now, before any presence gate, with nothing decided.

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { operationFor } from '../../src/ui/webauthn.js'
import { decision } from '../../src/pending.js'
import { startDaemon, startUi, makeAuthenticator, enrol, signed, PASSPHRASE } from './fix-control-helpers.js'

const NOT_A_VERDICT = ['false', 0, 1, null, 'true', 'no', undefined]

let d, u, auth, token, placeholder, upstreamHits = 0, n = 0

const gateway = (method, path, body) => fetch(`http://127.0.0.1:${d.daemon.gatewayPort}${path}`, {
  method,
  headers: { 'av-session': token, authorization: `Bearer ${placeholder}` },
  body,
})

/** A held write, waiting for an answer. Each is a distinct request. */
async function held() {
  const res = await gateway('POST', `/p/demo/things/${++n}`, 'x')
  assert.equal(res.status, 202, await res.text())
  return res.headers.get('av-approval-id')
}

const pending = (id) => d.daemon.pipeline.pendingApprovals().some((a) => a.id === id)

/** The body as sent: a missing verdict is a missing field, not `undefined`. */
const withVerdict = (id, granted, rest = {}) => (granted === undefined ? { id, ...rest } : { id, granted, ...rest })

before(async () => {
  d = await startDaemon({ passphrase: PASSPHRASE })
  auth = makeAuthenticator()
  enrol(d.vault, auth)
  u = await startUi(d)
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
after(async () => { await u?.stop(); await d?.stop() })

test('only true or false decides on the approvals route, and anything else decides nothing', async () => {
  const id = await held()
  // With no window, the refusal has to be the verdict's: before the fix these
  // got AV_PRESENCE_REQUIRED, because the gate ran first and read them as yes.
  for (const granted of NOT_A_VERDICT) {
    const r = await d.control('POST', '/v1/approvals', withVerdict(id, granted))
    assert.equal(r.status, 403, `${JSON.stringify(granted)}: ${JSON.stringify(r.body)}`)
    assert.equal(r.body.code, 'AV_POLICY_DENIED')
    assert.equal(r.body.rule, 'bulk_decision')
  }
  // And a window, which lets a real verdict through, does not let these.
  d.daemon.presenceGraceUntil = Date.now() + 60_000
  try {
    for (const granted of NOT_A_VERDICT) {
      const r = await d.control('POST', '/v1/approvals', withVerdict(id, granted))
      assert.equal(r.status, 403, `${JSON.stringify(granted)}: ${JSON.stringify(r.body)}`)
      assert.equal(r.body.rule, 'bulk_decision')
    }
  } finally { d.daemon.presenceGraceUntil = 0 }
  assert.ok(pending(id), 'the request is still waiting')

  // Real true and false still decide, and each still needs the human.
  const yes = await held()
  assert.equal((await d.control('POST', '/v1/approvals', { id: yes, granted: true })).status, 401)
  const approve = await signed(d.control, auth, operationFor('approval.approve', { id: yes, granted: true }))
  const ok = await d.control('POST', '/v1/approvals', { id: yes, granted: true, presence: approve })
  assert.equal(ok.status, 200, JSON.stringify(ok.body))
  assert.equal(ok.body.state, 'granted')

  const no = await held()
  assert.equal((await d.control('POST', '/v1/approvals', { id: no, granted: false })).status, 401)
  const deny = await signed(d.control, auth, operationFor('approval.deny', { id: no, granted: false }))
  const refused = await d.control('POST', '/v1/approvals', { id: no, granted: false, presence: deny })
  assert.equal(refused.status, 200, JSON.stringify(refused.body))
  assert.equal(refused.body.state, 'denied')
})

test('a signature cannot carry a verdict that is not a boolean either', async () => {
  const id = await held()
  for (const granted of NOT_A_VERDICT) {
    const presence = await signed(d.control, auth, operationFor('approval.approve', withVerdict(id, granted)))
    const r = await d.control('POST', '/v1/approvals', withVerdict(id, granted, { presence }))
    assert.equal(r.status, 403, `${JSON.stringify(granted)}: ${JSON.stringify(r.body)}`)
    assert.equal(r.body.rule, 'bulk_decision')
  }
  assert.ok(pending(id), 'the request is still waiting')
  const before = upstreamHits
  assert.equal((await gateway('POST', `/p/demo/things/${n}`, 'x')).status, 202, 'and it was not approved')
  assert.equal(upstreamHits, before)
})

test('the web UI refuses a verdict that is not a boolean, before it spends a signature', async () => {
  const id = await held()
  for (const granted of NOT_A_VERDICT) {
    // A signature for exactly what is sent, so only the verdict can be wrong.
    const presence = await u.presence(auth, operationFor('approval.approve', withVerdict(id, granted)))
    const r = await u.api('POST', 'approvals', withVerdict(id, granted, { presence }))
    const body = await r.json()
    assert.equal(r.status, 403, `${JSON.stringify(granted)}: ${JSON.stringify(body)}`)
    assert.equal(body.detail?.rule, 'bulk_decision')
  }
  assert.ok(pending(id), 'the request is still waiting')

  // A real deny through the page still works.
  const presence = await u.presence(auth, operationFor('approval.deny', { id, granted: false }))
  const r = await u.api('POST', 'approvals', { id, granted: false, presence })
  assert.equal(r.status, 200, JSON.stringify(await r.json()))
  assert.ok(!pending(id))
})

test('the web UI no longer turns a string "false" into an approved session', async () => {
  const asked = await d.control('POST', '/v1/session-requests', { cred: 'demo', methods: ['GET'], reason: 'job' })
  const id = asked.body.id
  const sessions = Object.keys(d.vault.db.sessions || {}).length
  for (const granted of NOT_A_VERDICT) {
    // `!!"false"` is true, so this is the signature the page's proxy used to
    // match — and then forward as a real approval.
    const presence = await u.presence(auth, operationFor('session_request.decide', { id, granted: true }))
    const r = await u.api('POST', 'session-requests/decide', withVerdict(id, granted, { presence }))
    const body = await r.json()
    assert.equal(r.status, 403, `${JSON.stringify(granted)}: ${JSON.stringify(body)}`)
    assert.equal(body.detail?.rule, 'bulk_decision')
  }
  assert.equal(d.daemon.sessionRequests.get(id).state, 'pending', 'nothing was decided')
  assert.equal(Object.keys(d.vault.db.sessions || {}).length, sessions, 'and nothing was created')

  const presence = await u.presence(auth, operationFor('session_request.decide', { id, granted: false }))
  const r = await u.api('POST', 'session-requests/decide', { id, granted: false, presence })
  assert.equal(r.status, 200, JSON.stringify(await r.json()))
  assert.equal(d.daemon.sessionRequests.get(id).state, 'denied')
})

test('the shared decision builder will not coerce a verdict', () => {
  const item = { id: 'ap_x', decide: { path: '/v1/approvals', idField: 'id' } }
  for (const granted of NOT_A_VERDICT) {
    assert.throws(() => decision(item, { granted }), /true or false/, JSON.stringify(granted))
  }
  assert.deepEqual(decision(item, { granted: true }).body, { id: 'ap_x', granted: true })
  assert.deepEqual(decision(item, { granted: false }).body, { id: 'ap_x', granted: false })
})
