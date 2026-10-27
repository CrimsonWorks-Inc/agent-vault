// R1: a session that approves its own writes is the owner's choice, made with
// a proof for that one operation.
//
// `approval: auto` plus a write method takes the human out of every later
// request on the session, so it is elevated: creating it, or approving a
// request into it, needs a fresh passphrase or authenticator assertion. The
// five-minute window does not count, a vault with no factor refuses it, and an
// agent cannot even ask for it. Read-only auto is not elevated, because
// on-write would never ask for GET or HEAD either; those tests are here too, so
// the gate is shown not to fire on ordinary sessions.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, writeFileSync } from 'node:fs'
import { startDaemon, cli, PASSPHRASE, makeAuthenticator, enrol, signed } from './fix-control-helpers.js'
import { elevationOf, overridesOf, OWNER_FIELDS, SessionRequests } from '../../src/daemon/session-requests.js'
import { parseOverrides } from '../../src/pending.js'
import * as webauthn from '../../src/ui/webauthn.js'

const AUTO_WRITES = { cred: 'demo', methods: ['GET', 'POST'], approval: 'auto' }
const openWindow = (d) => { d.daemon.presenceGraceUntil = Date.now() + 60_000 }
const sessionCount = (d) => Object.keys(d.vault.db.sessions).length
const kinds = (d) => d.vault.audit.read({ limit: 200 }).map((r) => r.kind)

// ------------------------------------------------------------ elevationOf

test('elevationOf names auto with a write method, and nothing ordinary', () => {
  assert.deepEqual(elevationOf(AUTO_WRITES), ['approval_auto_writes'])
  assert.deepEqual(elevationOf({ cred: 'demo', approval: 'auto', methods: ['get', 'patch'] }), ['approval_auto_writes'])
  assert.deepEqual(elevationOf({ grants: [{ cred: 'a' }, { ...AUTO_WRITES, cred: 'b' }] }), ['approval_auto_writes'])
  assert.deepEqual(elevationOf({ cred: 'demo', infinite: true }), ['infinite'])
  assert.deepEqual(elevationOf({ ...AUTO_WRITES, infinite: true }).sort(), ['approval_auto_writes', 'infinite'])
  // Method-bound routes name methods of their own.
  assert.deepEqual(elevationOf({ cred: 'demo', approval: 'auto', routes: [{ methods: ['DELETE'], paths: ['/x'] }] }), ['approval_auto_writes'])

  // Ordinary sessions, which must not be asked for a fresh proof.
  assert.deepEqual(elevationOf({ cred: 'demo' }), [])
  assert.deepEqual(elevationOf({ cred: 'demo', approval: 'auto' }), [], 'the default methods are GET and HEAD')
  assert.deepEqual(elevationOf({ cred: 'demo', approval: 'auto', methods: ['GET', 'HEAD', 'OPTIONS'] }), [])
  assert.deepEqual(elevationOf({ cred: 'demo', approval: 'on-write', methods: ['GET', 'POST', 'DELETE'] }), [])
  assert.deepEqual(elevationOf({ cred: 'demo', approval: 'each', methods: ['POST'] }), [])
  assert.deepEqual(elevationOf({ cred: 'demo', infinite: false }), [])
})

test('elevationOf fails closed on anything it cannot read', () => {
  for (const spec of [null, undefined, [], 'auto', 7]) {
    assert.deepEqual(elevationOf(spec), ['approval_auto_writes'], JSON.stringify(spec))
  }
  assert.deepEqual(elevationOf({ cred: 'demo', approval: 'auto', methods: 'POST' }), ['approval_auto_writes'])
  assert.deepEqual(elevationOf({ cred: 'demo', approval: 'auto', methods: [7] }), ['approval_auto_writes'])
  assert.deepEqual(elevationOf({ cred: 'demo', approval: 'auto', routes: 'GET:/x' }), ['approval_auto_writes'])
  assert.deepEqual(elevationOf({ grants: 'demo' }), ['approval_auto_writes'])
  assert.deepEqual(elevationOf({ grants: [null] }), ['approval_auto_writes'])
  // A getter that throws is unreadable too.
  const hostile = { cred: 'demo', get approval() { throw new Error('no') } }
  assert.deepEqual(elevationOf(hostile), ['approval_auto_writes'])
})

test('elevationOf fails closed on an unreadable list whatever the approval mode', () => {
  // Contract 0.4: a spec it cannot read is elevated. Not only when it says
  // auto: what it would permit is exactly the part that cannot be read.
  for (const spec of [
    { cred: 'demo', methods: 'POST' },
    { cred: 'demo', methods: 7 },
    { cred: 'demo', approval: 'on-write', methods: 'POST' },
    { cred: 'demo', approval: 'each', methods: ['GET', 7] },
    { cred: 'demo', routes: 'POST /x' },
    { cred: 'demo', approval: 'each', routes: [{ methods: 'DELETE', paths: ['/x'] }] },
    { cred: 'demo', routes: [null] },
    { grants: [{ cred: 'a', methods: ['GET'] }, { cred: 'b', methods: 'POST' }] },
    { grants: [{ cred: 'a' }, { cred: 'b', approval: 'first-use', routes: 'GET:/x' }], infinite: false },
  ]) {
    assert.deepEqual(elevationOf(spec), ['approval_auto_writes'], JSON.stringify(spec))
  }
  assert.deepEqual(elevationOf({ cred: 'demo', methods: 'POST', infinite: true }).sort(), ['approval_auto_writes', 'infinite'])

  // Readable lists are read as before: absent or null is the default, and a
  // mode other than auto asks before writes, so none of these is elevated.
  assert.deepEqual(elevationOf({ cred: 'demo', methods: null, routes: null }), [])
  assert.deepEqual(elevationOf({ cred: 'demo', approval: 'each', methods: ['POST'], routes: [{ methods: ['DELETE'], paths: ['/x'] }] }), [])
  assert.deepEqual(elevationOf({ grants: [{ cred: 'a', methods: ['GET'] }, { cred: 'b', approval: 'on-write', methods: ['POST'] }] }), [])
  assert.deepEqual(elevationOf({ cred: 'demo', approval: 'auto', routes: [{ methods: ['GET'], paths: ['/x'] }] }), [])
  // An unknown mode is not auto here either; #planSession refuses it (below).
  assert.deepEqual(elevationOf({ cred: 'demo', approval: 'yolo', methods: ['POST'] }), [])
})

test('owner fields are read by one parser, and the CLI parse feeds it', () => {
  assert.deepEqual(OWNER_FIELDS, ['approval', 'infinite'])
  assert.deepEqual(overridesOf({ methods: ['GET'], approval: 'auto', infinite: true, junk: 1 }), {
    methods: ['GET'], approval: 'auto', infinite: true,
  })
  assert.deepEqual(parseOverrides({ approval: 'auto', infinite: true }), { approval: 'auto', infinite: true })
  assert.deepEqual(parseOverrides({ infinite: 'true' }), { infinite: true })
  assert.deepEqual(parseOverrides({ infinite: 'yes', approval: '' }), {}, 'anything else is dropped, never guessed')
})

// ------------------------------------------------------- creating directly

test('auto with writes is refused inside an open window without a fresh proof', async () => {
  const d = await startDaemon({ passphrase: PASSPHRASE })
  try {
    openWindow(d)
    const before = sessionCount(d)
    const r = await d.control('POST', '/v1/sessions', AUTO_WRITES)
    assert.equal(r.status, 401, JSON.stringify(r.body))
    assert.equal(r.body.code, 'AV_PRESENCE_REQUIRED')
    assert.equal(r.body.rule, 'fresh_presence')
    assert.deepEqual(r.body.factors, ['passphrase'])
    assert.equal(sessionCount(d), before, 'nothing was created')
  } finally { await d.stop() }
})

test('auto with writes is created with the passphrase in the request, and audited as fresh', async () => {
  const d = await startDaemon({ passphrase: PASSPHRASE })
  try {
    const r = await d.control('POST', '/v1/sessions', { ...AUTO_WRITES, presence: { passphrase: PASSPHRASE } })
    assert.equal(r.status, 200, JSON.stringify(r.body))
    const grant = d.vault.db.grants[r.body.grant_id]
    assert.equal(grant.policy.approval, 'auto')
    assert.deepEqual(grant.policy.methods, ['GET', 'POST'])
    const proof = d.vault.audit.read({ limit: 50 }).find((x) => x.kind === 'presence.verified' && x.fresh === true)
    assert.ok(proof, 'the fresh proof is in the log')
    assert.equal(proof.op, 'session create')
    assert.equal(proof.factor, 'passphrase')
    assert.equal(d.daemon.presenceGraceUntil, 0, 'a fresh proof opens no window')
    // And the listing says what it is.
    const listed = (await d.control('GET', '/v1/sessions')).body.find((s) => s.id === r.body.session_id)
    assert.deepEqual(listed.elevated, ['approval_auto_writes'])
    assert.deepEqual(listed.creds, [{ slug: 'demo', grant_id: r.body.grant_id, approval: 'auto', methods: ['GET', 'POST'] }])
    assert.equal(listed.infinite, false)
  } finally { await d.stop() }
})

test('a wrong passphrase for an elevated session is refused, and counted', async () => {
  const d = await startDaemon({ passphrase: PASSPHRASE })
  try {
    const r = await d.control('POST', '/v1/sessions', { ...AUTO_WRITES, presence: { passphrase: 'not it at all' } })
    assert.equal(r.status, 403)
    assert.equal(r.body.code, 'AV_PRESENCE_DENIED')
    assert.equal(r.body.rule, 'fresh_presence')
    assert.equal(d.daemon.passphraseFailures, 1)
  } finally { await d.stop() }
})

test('read-only auto is not elevated: the window is enough, and nobody is asked again', async () => {
  const d = await startDaemon({ passphrase: PASSPHRASE })
  try {
    openWindow(d)
    const r = await d.control('POST', '/v1/sessions', { cred: 'demo', approval: 'auto', methods: ['GET', 'HEAD'] })
    assert.equal(r.status, 200, JSON.stringify(r.body))
    assert.ok(kinds(d).includes('presence.window_used'))
    const listed = (await d.control('GET', '/v1/sessions')).body.find((s) => s.id === r.body.session_id)
    assert.deepEqual(listed.elevated, [])
    // Without the window it is gated as widening, not as fresh.
    d.daemon.presenceGraceUntil = 0
    const shut = await d.control('POST', '/v1/sessions', { cred: 'demo', approval: 'auto' })
    assert.equal(shut.status, 401)
    assert.equal(shut.body.rule, 'human_presence')
  } finally { await d.stop() }
})

test('a vault with no factor refuses auto with writes, and still makes ordinary sessions', async () => {
  const d = await startDaemon()
  try {
    const r = await d.control('POST', '/v1/sessions', AUTO_WRITES)
    assert.equal(r.status, 401)
    assert.equal(r.body.code, 'AV_PRESENCE_REQUIRED')
    assert.equal(r.body.rule, 'factor_required')
    assert.deepEqual(r.body.factors, [])
    assert.match(r.body.hint, /agent-vault passphrase set/)
    // Read-only auto and ordinary on-write sessions are unaffected (Q1).
    assert.equal((await d.control('POST', '/v1/sessions', { cred: 'demo', approval: 'auto' })).status, 200)
    assert.equal((await d.control('POST', '/v1/sessions', { cred: 'demo', methods: ['GET', 'POST'] })).status, 200)
  } finally { await d.stop() }
})

test('an authenticator assertion over the exact body creates an elevated session', async () => {
  const d = await startDaemon({ passphrase: PASSPHRASE })
  const auth = makeAuthenticator()
  enrol(d.vault, auth)
  try {
    const presence = await signed(d.control, auth, webauthn.operationFor('session.create', AUTO_WRITES))
    const r = await d.control('POST', '/v1/sessions', { ...AUTO_WRITES, presence })
    assert.equal(r.status, 200, JSON.stringify(r.body))
    const proof = d.vault.audit.read({ limit: 50 }).find((x) => x.kind === 'presence.verified' && x.fresh === true)
    assert.equal(proof.factor, 'webauthn-platform')
    // A signature for a GET-only session cannot be spent on one that writes.
    const narrow = { cred: 'demo', methods: ['GET'], approval: 'auto' }
    const other = await signed(d.control, auth, webauthn.operationFor('session.create', narrow))
    const swapped = await d.control('POST', '/v1/sessions', { ...AUTO_WRITES, presence: other })
    assert.equal(swapped.status, 401)
    assert.equal(swapped.body.rule, 'fresh_presence')
  } finally { await d.stop() }
})

test('an unknown approval mode is refused, never read as auto', async () => {
  const d = await startDaemon()
  try {
    for (const approval of ['each-time', 'AUTO', '', 0]) {
      const r = await d.control('POST', '/v1/sessions', { cred: 'demo', approval })
      assert.equal(r.status, 403, `${JSON.stringify(approval)}: ${JSON.stringify(r.body)}`)
      assert.equal(r.body.code, 'AV_POLICY_DENIED')
      assert.equal(r.body.rule, 'approval')
      assert.equal(r.body.hint, 'approval is one of: each, on-write, first-use, auto')
    }
    for (const approval of ['each', 'on-write', 'first-use', 'auto']) {
      assert.equal((await d.control('POST', '/v1/sessions', { cred: 'demo', approval })).status, 200, approval)
    }
  } finally { await d.stop() }
})

test('malformed limits are refused before anything is created', async () => {
  const d = await startDaemon()
  try {
    const before = sessionCount(d)
    for (const body of [
      { cred: 'demo', methods: 'POST' }, { cred: 'demo', methods: [1] }, { cred: 'demo', paths: '/x' },
      { cred: 'demo', budget: 'lots' }, { cred: 'demo', budget: -1 }, { cred: 'demo', uses: 0 },
      { cred: 'demo', label: 'x'.repeat(81) },
    ]) {
      const r = await d.control('POST', '/v1/sessions', body)
      assert.equal(r.status, 403, JSON.stringify(body))
      assert.equal(r.body.rule, 'policy_invalid', JSON.stringify(r.body))
    }
    assert.equal(sessionCount(d), before)
    // The ordinary shapes of the same fields still work.
    const ok = await d.control('POST', '/v1/sessions', { cred: 'demo', methods: ['GET'], paths: ['/a/**'], budget: 1, uses: 2, label: 'fine' })
    assert.equal(ok.status, 200, JSON.stringify(ok.body))
    // A budget of 0 is well-formed, so it is not policy_invalid here. The
    // store then issues nothing on a spent grant, and the session is torn down.
    const zero = await d.control('POST', '/v1/sessions', { cred: 'demo', budget: 0 })
    assert.equal(zero.status, 403, JSON.stringify(zero.body))
    assert.equal(zero.body.rule, 'budget', JSON.stringify(zero.body))
    assert.ok(Object.values(d.vault.db.sessions).every((s) => s.id === ok.body.session_id || s.state === 'revoked'), 'no live session for budget 0')
  } finally { await d.stop() }
})

// ------------------------------------------------------- agents cannot ask

test('a session request that names an owner field is refused, not trimmed', async () => {
  const d = await startDaemon()
  try {
    for (const extra of [{ approval: 'auto' }, { infinite: true }, { approval: null }, { infinite: false }]) {
      const r = await d.control('POST', '/v1/session-requests', { cred: 'demo', methods: ['POST'], reason: 'x', ...extra })
      assert.equal(r.status, 403, JSON.stringify(extra))
      assert.equal(r.body.rule, 'owner_only_field')
      assert.match(r.body.hint, /Only the owner can choose/)
    }
    assert.equal(d.daemon.sessionRequests.pending().length, 0, 'nothing was opened')
    const ok = await d.control('POST', '/v1/session-requests', { cred: 'demo', methods: ['POST'], reason: 'x' })
    assert.equal(ok.status, 200)
    assert.ok(!('approval' in ok.body.proposal))
  } finally { await d.stop() }
})

test('the request store refuses an owner field from any caller', () => {
  const sr = new SessionRequests(null)
  assert.throws(() => sr.propose({ proposal: { cred: 'demo', approval: 'auto' }, reason: 'x' }), { code: 'AV_OWNER_ONLY' })
  assert.throws(() => sr.propose({ proposal: { cred: 'demo', infinite: true }, reason: 'x' }), { code: 'AV_OWNER_ONLY' })
  assert.ok(sr.propose({ proposal: { cred: 'demo' }, reason: 'x' }).record)
})

test('MCP cannot carry an owner field into a request', async () => {
  const d = await startDaemon({ passphrase: PASSPHRASE })
  try {
    const r = await d.daemon.mcp.handle({
      jsonrpc: '2.0', id: 1, method: 'tools/call',
      params: { name: 'vault_request_session', arguments: { cred: 'demo', reason: 'x', methods: ['POST'], approval: 'auto', infinite: true } },
    }, null, '')
    const answer = JSON.parse(r.result.content[0].text)
    const record = d.daemon.sessionRequests.get(answer.request_id)
    assert.ok(record, JSON.stringify(answer))
    for (const f of OWNER_FIELDS) assert.ok(!(f in record.proposal), `${f} reached the proposal`)
    // Approved as asked, it is an ordinary session: the window is enough.
    openWindow(d)
    const decided = await d.control('POST', '/v1/session-requests/decide', { id: record.id, granted: true })
    assert.equal(decided.status, 200, JSON.stringify(decided.body))
    const grant = d.vault.db.grants[decided.body.session.grant_id]
    assert.equal(grant.policy.approval, 'on-write')
    assert.notEqual(d.vault.db.sessions[decided.body.session.session_id].infinite, true)
  } finally { await d.stop() }
})

test('the gateway has no route that creates a session', async () => {
  const d = await startDaemon({ passphrase: PASSPHRASE })
  try {
    const before = sessionCount(d)
    for (const path of ['/v1/sessions', '/v1/session-requests/decide', '/v1/pending/decide-many', '/v1/placeholders/batch']) {
      const res = await fetch(`http://127.0.0.1:${d.daemon.gatewayPort}${path}`, {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ ...AUTO_WRITES, infinite: true, presence: { passphrase: PASSPHRASE } }),
      })
      assert.ok([401, 404].includes(res.status), `${path} answered ${res.status}`)
    }
    assert.equal(sessionCount(d), before)
  } finally { await d.stop() }
})

// ------------------------------------------------------- the owner approves

async function requestFor(d, body = { methods: ['GET', 'POST'] }) {
  const r = await d.control('POST', '/v1/session-requests', { cred: 'demo', reason: 'job', ...body })
  assert.equal(r.status, 200, JSON.stringify(r.body))
  return r.body.id
}

test('approving a request into auto with writes needs a fresh proof, not the window', async () => {
  const d = await startDaemon({ passphrase: PASSPHRASE })
  try {
    const id = await requestFor(d)
    openWindow(d)
    const overrides = { approval: 'auto', methods: ['POST'] }
    const refused = await d.control('POST', '/v1/session-requests/decide', { id, granted: true, overrides })
    assert.equal(refused.status, 401, JSON.stringify(refused.body))
    assert.equal(refused.body.rule, 'fresh_presence')
    assert.equal(d.daemon.sessionRequests.get(id).state, 'pending', 'still waiting')

    const ok = await d.control('POST', '/v1/session-requests/decide', {
      id, granted: true, overrides, presence: { passphrase: PASSPHRASE },
    })
    assert.equal(ok.status, 200, JSON.stringify(ok.body))
    assert.equal(d.vault.db.grants[ok.body.session.grant_id].policy.approval, 'auto')
    assert.ok(ok.body.session.token, 'the deciding client gets the session it made')
    const approved = d.vault.audit.read({ limit: 50 }).find((x) => x.kind === 'session_request.approved')
    assert.equal(approved.granted.approval, 'auto')
  } finally { await d.stop() }
})

test('a request approved without owner options stays ordinary, inside the window', async () => {
  const d = await startDaemon({ passphrase: PASSPHRASE })
  try {
    const id = await requestFor(d)
    openWindow(d)
    const ok = await d.control('POST', '/v1/session-requests/decide', { id, granted: true, overrides: { approval: 'each' } })
    assert.equal(ok.status, 200, JSON.stringify(ok.body))
    assert.equal(d.vault.db.grants[ok.body.session.grant_id].policy.approval, 'each')
    // A denial with elevated overrides creates nothing, so it is not elevated.
    const id2 = await requestFor(d)
    const no = await d.control('POST', '/v1/session-requests/decide', { id: id2, granted: false, overrides: { approval: 'auto' } })
    assert.equal(no.status, 200, JSON.stringify(no.body))
  } finally { await d.stop() }
})

test('a verdict that is not true or false is refused on the single decide route', async () => {
  const d = await startDaemon({ passphrase: PASSPHRASE })
  try {
    const id = await requestFor(d, { methods: ['GET'] })
    const before = sessionCount(d)
    // Refused before the gate, so with no window it is the verdict that is
    // wrong, not the presence. `"false"` is truthy and used to approve.
    for (const granted of ['false', 0, 1, null, undefined, 'true']) {
      const r = await d.control('POST', '/v1/session-requests/decide', { id, granted })
      assert.equal(r.status, 403, `${JSON.stringify(granted)}: ${JSON.stringify(r.body)}`)
      assert.equal(r.body.rule, 'bulk_decision')
    }
    openWindow(d)
    for (const granted of ['false', 0, 1, null]) {
      const r = await d.control('POST', '/v1/session-requests/decide', { id, granted })
      assert.equal(r.status, 403, `${JSON.stringify(granted)}: ${JSON.stringify(r.body)}`)
      assert.equal(r.body.rule, 'bulk_decision')
    }
    assert.equal(d.daemon.sessionRequests.get(id).state, 'pending', 'nothing was decided')
    assert.equal(sessionCount(d), before, 'and nothing was created')

    // A real verdict still works, both ways.
    const ok = await d.control('POST', '/v1/session-requests/decide', { id, granted: true })
    assert.equal(ok.status, 200, JSON.stringify(ok.body))
    assert.equal(sessionCount(d), before + 1)
    const id2 = await requestFor(d, { methods: ['GET'] })
    const no = await d.control('POST', '/v1/session-requests/decide', { id: id2, granted: false })
    assert.equal(no.status, 200, JSON.stringify(no.body))
    assert.equal(d.daemon.sessionRequests.get(id2).state, 'denied')
  } finally { await d.stop() }
})

test('an override with an unknown mode is refused when it is settled', async () => {
  const d = await startDaemon({ passphrase: PASSPHRASE })
  try {
    const id = await requestFor(d, { methods: ['GET'] })
    openWindow(d)
    const r = await d.control('POST', '/v1/session-requests/decide', { id, granted: true, overrides: { approval: 'yolo' } })
    assert.equal(r.status, 403, JSON.stringify(r.body))
    assert.equal(r.body.rule, 'approval')
    assert.equal(d.daemon.sessionRequests.get(id).state, 'pending')
  } finally { await d.stop() }
})

test('a bulk decision with one elevated item needs a fresh proof for the whole list', async () => {
  const d = await startDaemon({ passphrase: PASSPHRASE })
  try {
    const plain = await requestFor(d, { methods: ['GET'] })
    const wide = await requestFor(d)
    const decisions = [
      { id: plain, kind: 'session', granted: true },
      { id: wide, kind: 'session', granted: true, overrides: { approval: 'auto' } },
    ]
    openWindow(d)
    const refused = await d.control('POST', '/v1/pending/decide-many', { decisions })
    assert.equal(refused.status, 401, JSON.stringify(refused.body))
    assert.equal(refused.body.rule, 'fresh_presence')
    assert.equal(d.daemon.sessionRequests.get(plain).state, 'pending', 'not even the ordinary item ran')

    const ok = await d.control('POST', '/v1/pending/decide-many', { decisions, presence: { passphrase: PASSPHRASE } })
    assert.equal(ok.status, 200, JSON.stringify(ok.body))
    assert.deepEqual(ok.body.decided.map((r) => r.outcome), ['decided', 'decided'])

    // Without an elevated item the window still decides a list.
    const a = await requestFor(d, { methods: ['GET'] })
    const b = await requestFor(d, { methods: ['GET'] })
    openWindow(d)
    const plainList = await d.control('POST', '/v1/pending/decide-many', {
      decisions: [{ id: a, kind: 'session', granted: true }, { id: b, kind: 'session', granted: false, overrides: { approval: 'auto' } }],
    })
    assert.equal(plainList.status, 200, JSON.stringify(plainList.body))
  } finally { await d.stop() }
})

// ---------------------------------------------------------------- the CLI

test('the CLI refuses a mode it does not know before it calls anything', async () => {
  const d = await startDaemon({ socketName: 'control.sock' })
  try {
    const r = await cli(d.dir, ['session', 'create', '--cred', 'demo', '--approval', 'each-time'])
    assert.equal(r.code, 2, r.stderr)
    assert.match(r.stderr, /--approval is one of: each, on-write, first-use, auto/)
    for (const bad of [['--ttl', 'abc'], ['--ttl', '0'], ['--budget', 'x'], ['--uses', '0']]) {
      const b = await cli(d.dir, ['session', 'create', '--cred', 'demo', ...bad])
      assert.equal(b.code, 2, `${bad.join(' ')}: ${b.stderr}`)
    }
    assert.equal(Object.keys(d.vault.db.sessions).length, 0)
  } finally { await d.stop() }
})

test('the CLI says what to do when auto with writes cannot be proved', async () => {
  const none = await startDaemon({ socketName: 'control.sock' })
  try {
    const r = await cli(none.dir, ['session', 'create', '--cred', 'demo', '--methods', 'GET,POST', '--approval', 'auto'])
    assert.equal(r.code, 5, r.stderr)
    assert.match(r.stderr, /next: agent-vault passphrase set/)
    // Read-only auto needs nothing on the same vault, and says nothing about writes.
    const ro = await cli(none.dir, ['session', 'create', '--cred', 'demo', '--approval', 'auto'])
    assert.equal(ro.code, 0, ro.stderr)
    assert.doesNotMatch(ro.stdout, /writes go through without asking you/)
  } finally { await none.stop() }
  const pass = await startDaemon({ passphrase: PASSPHRASE, socketName: 'control.sock' })
  try {
    const r = await cli(pass.dir, ['session', 'create', '--cred', 'demo', '--methods', 'GET,POST', '--approval', 'auto'])
    assert.equal(r.code, 5, r.stderr)
    assert.match(r.stderr, /no terminal to ask on/)
    // A passphrase-only vault is not sent to a UI that cannot confirm anything.
    assert.doesNotMatch(r.stderr, /next:/)
  } finally { await pass.stop() }
  // With an authenticator as well, the UI is a way through, and is named.
  const both = await startDaemon({ passphrase: PASSPHRASE, socketName: 'control.sock' })
  enrol(both.vault, makeAuthenticator())
  try {
    const r = await cli(both.dir, ['session', 'create', '--cred', 'demo', '--methods', 'GET,POST', '--approval', 'auto'])
    assert.equal(r.code, 5, r.stderr)
    assert.match(r.stderr, /no terminal to ask on/)
    assert.match(r.stderr, /next: agent-vault ui {3}\(confirm it there with your authenticator\)/)
  } finally { await both.stop() }
})

test('the CLI exits with the refusal code’s own exit status', async () => {
  const d = await startDaemon({ socketName: 'control.sock' })
  try {
    const missing = await cli(d.dir, ['session', 'create', '--cred', 'nope'])
    assert.equal(missing.code, 7, missing.stderr)
    // A refusal by policy is 6, which is what AV_POLICY_DENIED registers.
    const file = `${d.dir}/grants.json`
    writeFileSync(file, JSON.stringify([{ cred: 'demo', approval: 'sometimes' }]))
    const refused = await cli(d.dir, ['session', 'create', '--grants-file', file])
    assert.equal(refused.code, 6, refused.stderr)
    assert.match(refused.stderr, /approval/)
  } finally { await d.stop() }
})

test('approvals offers the owner options, and approve validates them', async () => {
  const d = await startDaemon({ socketName: 'control.sock' })
  try {
    const id = await requestFor(d, { methods: ['GET'] })
    const listing = await cli(d.dir, ['approvals'])
    assert.match(listing.stdout, new RegExp(`approve ${id} .*\\[--ttl_minutes \\.\\.\\.\\] \\[--approval MODE\\] \\[--infinite\\]`))
    const bad = await cli(d.dir, ['approve', id, '--approval', 'sometimes'])
    assert.equal(bad.code, 2, bad.stderr)
    const ok = await cli(d.dir, ['approve', id, '--approval', 'each'])
    assert.equal(ok.code, 0, ok.stderr)
    const sid = JSON.parse(readFileSync(`${d.dir}/cli-state.json`, 'utf8')).session_id
    const grant = Object.values(d.vault.db.grants).find((g) => g.session_id === sid)
    assert.equal(grant.policy.approval, 'each')
  } finally { await d.stop() }
})

test('the help text documents how to start an auto-approving session', async () => {
  const r = await cli('/nonexistent', ['help'])
  assert.match(r.stdout, /\[--budget N\] \[--uses N\] \[--approval each\|on-write\|first-use\|auto\]/)
  assert.match(r.stdout, /\[--ttl HOURS \| --infinite\] \[--label TEXT\] \[--grants-file F\]/)
  assert.match(r.stdout, /--approval auto with writes, and --infinite,\n\s+ask for your passphrase every time/)
})
