// Containment on the control API (F16): panic and tripwires. Panic is open
// because it only takes capability away; it revokes every session, infinite
// ones too, denies everything waiting (session requests through the wired
// onPanic hook, C1), and can lock. Turning tripwires on is open for exactly
// `{ enabled: true }`; anything else changes what a human chose (C20).

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { startApi, PASSPHRASE } from './control-api-helpers.js'

test('panic is open, revokes every session including infinite ones, and denies everything waiting (C1)', async () => {
  const a = await startApi({ passphrase: PASSPHRASE })
  try {
    const finite = a.session()
    const forever = a.session({ infinite: true })
    const waiting = a.session({ policy: { approval: 'each' } })
    const held = await a.gateway('/p/demo/x', { headers: { authorization: `Bearer ${waiting.placeholder}` } })
    assert.equal(held.status, 202)
    const asked = await a.control('POST', '/v1/session-requests', { cred: 'demo', reason: 'later' })
    assert.equal(asked.status, 200)

    const r = await a.control('POST', '/v1/panic', { reason: 'agent went rogue' })
    assert.equal(r.status, 200, JSON.stringify(r.body))
    assert.deepEqual(r.body, { revoked_sessions: 3, denied_approvals: 1, denied_session_requests: 1, locked: false })
    for (const s of [finite, forever, waiting]) assert.equal(a.vault.db.sessions[s.session.id].state, 'revoked')
    assert.equal(a.daemon.sessionRequests.get(asked.body.id).state, 'denied')
    assert.ok(a.audit('session_request.denied').some((x) => x.request_id === asked.body.id && x.reason === 'panic'))
    const triggered = a.audit('panic.triggered').at(-1)
    assert.equal(triggered.denied_session_requests, 1)
    assert.equal(triggered.reason_untrusted, 'agent went rogue')
    const after = await a.gateway('/p/demo/x', { headers: { authorization: `Bearer ${forever.placeholder}` } })
    assert.notEqual(after.status, 200)
  } finally { await a.stop() }
})

test('panic with lock locks the vault and closes the passphrase window; panicking a locked vault revokes nothing', async () => {
  const a = await startApi({ passphrase: PASSPHRASE })
  try {
    a.session()
    a.openWindow()
    const r = await a.control('POST', '/v1/panic', { lock: true })
    assert.equal(r.status, 200, JSON.stringify(r.body))
    assert.equal(r.body.locked, true)
    assert.equal(a.vault.locked, true)
    assert.equal(a.daemon.presenceGraceUntil, 0, 'the window survived the lock')
    const again = await a.control('POST', '/v1/panic', {})
    assert.equal(again.status, 423, JSON.stringify(again.body))
    assert.equal(again.body.code, 'AV_LOCKED')
    assert.equal(again.body.locked, true)
    assert.equal(again.body.already, true)
  } finally { await a.stop() }
})

test('panic reads its inputs strictly', async () => {
  const a = await startApi()
  try {
    const s = a.session()
    for (const body of [{ lock: 'true' }, { lock: 1 }, { reason: 5 }, { reason: 'x'.repeat(201) }]) {
      const r = await a.control('POST', '/v1/panic', body)
      assert.equal(r.status, 403, JSON.stringify(body))
      assert.equal(r.body.rule, 'policy_invalid')
    }
    assert.equal(a.vault.db.sessions[s.session.id].state, 'active', 'a refused panic revoked something')
    assert.equal(a.vault.locked, false)
  } finally { await a.stop() }
})

test('tripwires: on is open, everything else needs a human (C20)', async () => {
  const a = await startApi({ passphrase: PASSPHRASE })
  try {
    const shown = await a.control('GET', '/v1/tripwires')
    assert.equal(shown.body.enabled, false)
    assert.equal(shown.body.rules_saved, false)
    assert.deepEqual(shown.body.rules, shown.body.defaults, 'rules never saved are shown as the defaults in force')
    assert.ok(shown.body.defaults.some((r) => r.id === 'replay'))
    for (const body of [
      { enabled: false }, { enabled: 'true' }, { enabled: 1 }, { enabled: true, extra: 1 },
      { enabled: true, rules: 'defaults' }, { rules: [] }, {},
    ]) {
      const r = await a.control('POST', '/v1/tripwires', body)
      assert.equal(r.status, 401, `${JSON.stringify(body)}: ${JSON.stringify(r.body)}`)
      assert.equal(r.body.code, 'AV_PRESENCE_REQUIRED')
    }
    assert.equal(a.vault.getSettings().tripwires, undefined, 'a refused change was stored')
    const on = await a.control('POST', '/v1/tripwires', { enabled: true })
    assert.equal(on.status, 200, JSON.stringify(on.body))
    assert.equal(on.body.enabled, true)
    assert.ok(on.body.rules.some((r) => r.id === 'replay'), 'rules that were never set are the defaults')
    // Off needs the owner.
    const off = await a.control('POST', '/v1/tripwires', { enabled: false })
    assert.equal(off.status, 401)
    a.openWindow()
    const custom = [{ id: 'mine', codes: ['AV_BAD_LOCATION'], threshold: 2, window_s: 60, action: 'revoke_session' }]
    const set = await a.control('POST', '/v1/tripwires', { rules: custom })
    assert.deepEqual(set.body, { enabled: true, rules: custom })
    const bad = await a.control('POST', '/v1/tripwires', { rules: [{ id: 'X Y', threshold: 0 }] })
    assert.equal(bad.body.rule, 'tripwire_rule')
    assert.equal((await a.control('POST', '/v1/tripwires', { enabled: 'no' })).body.rule, 'tripwire_rule')
    assert.equal((await a.control('POST', '/v1/tripwires', { enabled: false })).body.enabled, false)
  } finally { await a.stop() }
})

test('a tripwire turned on through the route revokes a replaying session before its answer returns', async () => {
  const a = await startApi()
  try {
    assert.equal((await a.control('POST', '/v1/tripwires', { enabled: true })).status, 200)
    // Writes are held; reads are not.
    const s = a.session({ policy: { approval: 'on-write' } })
    const held = await a.gateway('/p/demo/x', { method: 'POST', headers: { authorization: `Bearer ${s.placeholder}` } })
    assert.equal(held.status, 202)
    // A placeholder whose row was spent, used again: a replay.
    const second = a.vault.issuePlaceholder({ grantId: s.grant.id, field: 'token' })
    a.vault.burnPlaceholder(second.row.id, 'spent')
    const replayed = await a.gateway('/p/demo/y', { headers: { authorization: `Bearer ${second.placeholder}` } })
    assert.equal(replayed.json?.code, 'AV_PH_REPLAY', replayed.text)
    assert.ok(a.audit('tripwire.fired').length >= 1, JSON.stringify(a.audit().slice(-5)))
    assert.equal(a.vault.db.sessions[s.session.id].state, 'revoked')
    assert.equal(a.daemon.pipeline.pendingApprovals().length, 0, 'its held request is still waiting')
  } finally { await a.stop() }
})

test('with tripwires off, the same replay revokes nothing', async () => {
  const a = await startApi()
  try {
    const s = a.session()
    const second = a.vault.issuePlaceholder({ grantId: s.grant.id, field: 'token' })
    a.vault.burnPlaceholder(second.row.id, 'spent')
    const r = await a.gateway('/p/demo/y', { headers: { authorization: `Bearer ${second.placeholder}` } })
    assert.equal(r.json?.code, 'AV_PH_REPLAY', r.text)
    assert.equal(a.audit('tripwire.fired').length, 0)
    assert.equal(a.vault.db.sessions[s.session.id].state, 'active')
  } finally { await a.stop() }
})
