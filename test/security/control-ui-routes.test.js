// The UI proxy routes for wave 3 (contract A.6), against a stand-in daemon.
//
// What has to hold, route by route:
//   - every change the page can make is signed over the WHOLE request, with
//     the daemon's own op name (A.2), and refused without that signature;
//   - a route the daemon re-verifies receives the signed body and the proof,
//     so it can check the same signature itself;
//   - the open routes (probe, quarantine, panic) need nothing, and pass on
//     only the fields that mean something, so the page cannot steer a probe
//     or turn "false" into a lock.

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { operationFor, canonicalOperation } from '../../src/ui/webauthn.js'
import { UiServer } from '../../src/ui/server.js'
import { startStub, startUi } from './control-ui-helpers.js'

let d
let u

before(async () => {
  d = await startStub((key) => {
    if (key === 'GET /v1/audit') {
      return [
        { seq: 1, kind: 'session.created' },
        { seq: 2, kind: 'tripwire.fired', rule_id: 'replay' },
        { seq: 3, kind: 'request.denied' },
        { seq: 4, kind: 'tripwire.fired', rule_id: 'deny_paths' },
      ]
    }
    return { ok: true }
  })
  u = await startUi(d)
})
after(async () => { await u.stop(); await d.stop() })

/**
 * Every change the page makes in wave 3. `bind` is what the operation covers
 * when it is not the body (a DELETE binds its query); `verified` says the
 * daemon re-checks the signature, so the proof must reach it.
 */
const CHANGES = [
  { key: 'POST sessions/narrow', op: 'session.narrow', control: '/v1/sessions/narrow', verified: false,
    body: { sid: 's_1', narrow: { methods: ['GET', 'HEAD'] } } },
  { key: 'POST credentials/rotate', op: 'cred.rotate', control: '/v1/credentials/rotate', verified: true,
    body: { slug: 'demo', value: 'ghp_NEWVALUE0011223344556677', mode: 'keep', retire_hours: 24 } },
  { key: 'POST credentials/scrub', op: 'cred.scrub_add', control: '/v1/credentials/scrub', verified: true,
    body: { slug: 'demo', pattern: 'acme_[A-Za-z0-9]{20}', sample: 'token acme_abcdefghijklmnopqrst' } },
  { key: 'DELETE credentials/scrub', path: 'credentials/scrub?slug=demo&id=sp_01', op: 'cred.scrub_remove',
    control: '/v1/credentials/scrub', verified: true, body: {}, bind: { slug: 'demo', id: 'sp_01' } },
  { key: 'POST credentials/expiry', op: 'cred.expiry_set', control: '/v1/credentials/expiry', verified: true,
    body: { slug: 'demo', expires_at: '2027-01-31T00:00:00.000Z' } },
  { key: 'POST credentials/release', op: 'cred.release', control: '/v1/credentials/release', verified: true,
    body: { slug: 'demo' } },
  { key: 'POST tripwires', op: 'tripwires.set', control: '/v1/tripwires', verified: true,
    body: { enabled: false } },
  { key: 'POST templates', op: 'template.save', control: '/v1/templates', verified: true,
    body: { name: 'gh-read', spec: { cred: 'demo', methods: ['GET'], spend_usd: 1.5 } } },
  { key: 'DELETE templates', path: 'templates?name=gh-read', op: 'template.delete', control: '/v1/templates',
    verified: false, body: {}, bind: { name: 'gh-read' } },
]

const methodOf = (c) => c.key.split(' ')[0]
const pathOf = (c) => c.path ?? c.key.split(' ')[1]

test('every wave-3 change is gated, and exactly the daemon-gated ones are re-verified (A.6)', () => {
  for (const c of CHANGES) {
    assert.ok(UiServer.GATED.has(c.key), `${c.key} is not signed`)
    assert.equal(UiServer.DAEMON_VERIFIED.has(c.key), c.verified, `${c.key}: DAEMON_VERIFIED is wrong`)
  }
  // Open by design: each only narrows or reads, and the daemon leaves it open.
  for (const key of ['POST credentials/test', 'POST credentials/quarantine', 'POST panic']) {
    assert.ok(!UiServer.GATED.has(key), `${key} must not wait for a fingerprint`)
    assert.ok(!UiServer.DAEMON_VERIFIED.has(key))
  }
})

test('without a signature, no change reaches the daemon', async () => {
  for (const c of CHANGES) {
    const before = d.callsTo(methodOf(c), c.control).length
    const res = await u.api(methodOf(c), pathOf(c), c.body)
    assert.equal(res.status, 401, `${c.key} went through unsigned`)
    assert.equal(d.callsTo(methodOf(c), c.control).length, before, `${c.key} reached the daemon unsigned`)
  }
})

test('a signature over a different request is refused', async () => {
  for (const c of CHANGES) {
    const bind = c.bind ?? c.body
    // The same op, one field different: the swap a signature must not cover.
    const other = Object.fromEntries(Object.entries(bind).map(([k, v], i) => [k, i === 0 ? `${v}-other` : v]))
    const presence = await u.presence(d.auth, operationFor(c.op, other))
    const before = d.callsTo(methodOf(c), c.control).length
    const res = await u.api(methodOf(c), pathOf(c), { ...c.body, presence })
    assert.equal(res.status, 409, `${c.key} accepted a signature for another request`)
    assert.equal(d.callsTo(methodOf(c), c.control).length, before)
  }
})

test('a signature with another op name is refused, even over the same fields', async () => {
  const c = CHANGES.find((x) => x.key === 'POST credentials/release')
  const presence = await u.presence(d.auth, operationFor('cred.quarantine', c.body))
  const res = await u.api('POST', 'credentials/release', { ...c.body, presence })
  assert.equal(res.status, 409)
})

test('with its own signature, each change reaches its route, carrying what the daemon re-verifies', async () => {
  for (const c of CHANGES) {
    const signed = operationFor(c.op, c.bind ?? c.body)
    const presence = await u.presence(d.auth, signed)
    const res = await u.api(methodOf(c), pathOf(c), { ...c.body, presence })
    assert.equal(res.status, 200, `${c.key}: ${JSON.stringify(await res.json())}`)
    const call = d.callsTo(methodOf(c), c.control).at(-1)
    assert.ok(call, `${c.key} never reached ${c.control}`)
    const bound = c.bind ? call.query : (({ presence: _p, ...rest }) => rest)(call.body || {})
    assert.equal(canonicalOperation(operationFor(c.op, bound)), canonicalOperation(signed),
      `${c.key}: the daemon would bind something other than what was signed`)
    if (c.verified) {
      assert.deepEqual(call.body?.presence, presence, `${c.key}: the proof did not reach the daemon`)
    } else {
      assert.equal(call.body?.presence, undefined, `${c.key}: a proof nothing checks was passed on`)
    }
  }
})

test('a rotation value is bound by digest, never in clear', () => {
  const op = operationFor('cred.rotate', { slug: 'demo', value: 'ghp_NEWVALUE0011223344556677' })
  assert.ok(!JSON.stringify(op).includes('ghp_NEWVALUE'), 'the new value is in the signed operation')
  assert.match(op.value_sha256, /^[0-9a-f]{64}$/)
})

test('the probe takes a credential name and nothing that could steer it', async () => {
  let res = await u.api('POST', 'credentials/test', { slug: 'demo', path: '/admin', method: 'DELETE', body: 'x' })
  assert.equal(res.status, 200)
  assert.deepEqual(d.callsTo('POST', '/v1/credentials/test').at(-1).body, { slug: 'demo' })
  res = await u.api('POST', 'credentials/test', { all: true })
  assert.deepEqual(d.callsTo('POST', '/v1/credentials/test').at(-1).body, { all: true })
  // `all` is a decision: only `true` means all.
  res = await u.api('POST', 'credentials/test', { all: 'true', slug: 'demo' })
  assert.deepEqual(d.callsTo('POST', '/v1/credentials/test').at(-1).body, { slug: 'demo' })
})

test('quarantine needs no fingerprint, and passes on the name and the reason only', async () => {
  const res = await u.api('POST', 'credentials/quarantine', { slug: 'demo', reason: 'odd traffic', by: 'tripwire' })
  assert.equal(res.status, 200)
  assert.deepEqual(d.callsTo('POST', '/v1/credentials/quarantine').at(-1).body, { slug: 'demo', reason: 'odd traffic' })
})

test('panic needs no fingerprint, and only a real true locks', async () => {
  let res = await u.api('POST', 'panic', { lock: true, reason: 'agent went wild' })
  assert.equal(res.status, 200)
  assert.deepEqual(d.callsTo('POST', '/v1/panic').at(-1).body, { lock: true, reason: 'agent went wild' })

  res = await u.api('POST', 'panic', {})
  assert.equal(res.status, 200)
  assert.deepEqual(d.callsTo('POST', '/v1/panic').at(-1).body, { lock: false })

  for (const lock of ['false', 'true', 1, null]) {
    const before = d.callsTo('POST', '/v1/panic').length
    res = await u.api('POST', 'panic', { lock })
    assert.equal(res.status, 400, `lock: ${JSON.stringify(lock)} was read as something`)
    assert.equal(d.callsTo('POST', '/v1/panic').length, before)
  }
})

test('the read routes reach the routes the contract names', async () => {
  const reads = [
    ['sessions/detail?sid=s_1', '/v1/sessions/detail', { sid: 's_1' }],
    ['report/access', '/v1/report/access', { since: '7d' }],
    ['report/access?since=24h', '/v1/report/access', { since: '24h' }],
    ['tripwires', '/v1/tripwires', {}],
    ['templates', '/v1/templates', {}],
    ['templates?name=gh-read', '/v1/templates', { name: 'gh-read' }],
    ['notify', '/v1/notify', {}],
    ['audit/checkpoint', '/v1/audit/checkpoint', {}],
  ]
  for (const [path, control, query] of reads) {
    const res = await u.api('GET', path)
    assert.equal(res.status, 200, path)
    const call = d.callsTo('GET', control).at(-1)
    assert.deepEqual(call.query, query, path)
  }
})

test('the audit view can ask for one kind of record, and gets only that kind', async () => {
  const rows = await (await u.api('GET', 'audit?kind=tripwire.fired&limit=5')).json()
  assert.deepEqual(rows.map((r) => r.seq), [2, 4])
  const all = await (await u.api('GET', 'audit?limit=5')).json()
  assert.equal(all.length, 4, 'with no kind, nothing is filtered')
  const bad = await u.api('GET', 'audit?kind=../../v1/credentials')
  assert.equal(bad.status, 400)
})
