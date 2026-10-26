// F19, store side: session activity and the access review report. Both are
// pure readings of the audit log, driven here by real pipeline traffic, so the
// record shapes they read are the ones the gateway actually writes.

import { test, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { summarizeSession, accessReport } from '../../src/store/activity.js'
import { setup, cleanup, SECRET } from './gateway-helpers.js'

afterEach(cleanup)

const rowsOf = (s) => s.vault.audit.read({ limit: 100000 })

/**
 * Traffic for one session: three reads of one path, one of another, a write
 * that is held for approval (then granted), and one request outside the grant.
 */
async function traffic(s) {
  const send = (over) => s.pipeline.handle(s.request({ ...over, headers: [...s.request().headers, ['x-key', s.ph()]] }))
  for (let i = 0; i < 3; i++) await send({ path: '/p/a/repos/one' })
  await send({ path: '/p/a/repos/two' })
  const held = await send({ path: '/p/a/repos/one', method: 'POST' })
  await send({ path: '/p/a/admin/x' })
  const approval = [...s.pipeline.approvals.values()][0]
  s.pipeline.decideApproval(approval.id, true)
  return { held }
}

function fixture() {
  return setup({ approval: 'on-write', methods: ['GET', 'POST', 'DELETE'], paths: ['/repos/**'] })
}

test('a normal session reports complete activity with the right counts', async () => {
  const s = fixture()
  await traffic(s)
  const rows = rowsOf(s)
  // The fixture checks itself: the traffic it claims is in the log. The
  // held POST is written as request.allowed too (status 202, no path).
  assert.equal(rows.filter((r) => r.kind === 'request.allowed' && r.req.status === 200).length, 4)
  assert.equal(rows.filter((r) => r.kind === 'request.allowed' && r.req.status === 202 && r.req.method === 'POST').length, 1)
  assert.equal(rows.filter((r) => r.kind === 'approval.requested').length, 1)

  const a = summarizeSession(rows, { session: s.session, grants: [s.grant] })
  assert.equal(a.complete, true)
  assert.equal(a.note, null)
  assert.deepEqual(a.requests, { allowed: 4, denied: 1, held: 1 })
  assert.deepEqual(a.approvals, { requested: 1, granted: 1, denied: 0, replayed: 0 })
  assert.equal(a.paths[0].path, '/repos/one')
  assert.equal(a.paths[0].method, 'GET')
  assert.equal(a.paths[0].count, 3)
  // The held POST is not a path that was used.
  assert.deepEqual(a.paths.map((p) => `${p.method} ${p.path} ${p.count}`).sort(), ['GET /p/a/admin/x 1', 'GET /repos/one 3', 'GET /repos/two 1'])
  assert.equal(a.denials.length, 1)
  assert.equal(a.denials[0].code, 'AV_POLICY_DENIED')
  assert.equal(a.denials[0].count, 1)
  assert.deepEqual(Object.keys(a.denials[0]).sort(), ['code', 'count', 'rule'])
  assert.ok(a.from_seq < a.to_seq && a.first_at <= a.last_at)
  assert.deepEqual(a.tripwires, [])
})

test('the activity carries no placeholder, no query, no secret and no detail text', async () => {
  const s = fixture()
  const ph = s.ph()
  await s.pipeline.handle(s.request({ path: `/p/a/repos/${ph}`, query: `token=${SECRET}`, headers: [...s.request().headers, ['x-key', s.ph()]] }))
  await s.pipeline.handle(s.request({ path: `/p/a/admin/${ph}`, query: `token=${SECRET}`, headers: [...s.request().headers, ['x-key', s.ph()]] }))
  const rows = rowsOf(s)
  const a = summarizeSession(rows, { session: s.session, grants: [s.grant] })
  assert.equal(a.requests.allowed + a.requests.denied, 2)
  const text = JSON.stringify(a)
  for (const bad of [ph, SECRET, 'token=']) assert.ok(!text.includes(bad), `${bad} reached the activity`)
  assert.ok(!/"detail"/.test(text))
  for (const d of rows.filter((r) => r.decision === 'deny' && typeof r.detail === 'string' && r.detail.length > 12)) {
    assert.ok(!text.includes(d.detail), 'a denial detail was copied')
  }

  // Whatever wrote the row, a placeholder or a query in a path is not repeated.
  const synthetic = [{ seq: 1, ts: '2026-01-01T00:00:00.000Z', kind: 'request.allowed', session_id: s.session.id, req: { method: 'get', path: `/x/${ph}/y?q=${SECRET}` } }]
  const b = summarizeSession(synthetic, { session: s.session, grants: [] })
  assert.deepEqual(b.paths.map((p) => [p.method, p.path]), [['GET', '/x/[[av:placeholder]]/y']])
})

test('a log that starts after the session, or was cut back, is reported incomplete', async () => {
  const s = fixture()
  await traffic(s)
  const rows = rowsOf(s)
  const created = rows.find((r) => r.kind === 'session.created' && r.session_id === s.session.id)
  const after = rows.filter((r) => r.seq > created.seq)
  const late = summarizeSession(after, { session: s.session, grants: [s.grant] })
  assert.equal(late.complete, false)
  assert.match(late.note, /starts after this session/)
  // Missing records are not zero: what is there is still counted.
  assert.equal(late.requests.allowed, 4)

  for (const kind of ['audit.truncation_detected', 'audit.anchor_missing']) {
    const cut = summarizeSession([...rows, { seq: 9999, ts: new Date().toISOString(), kind }], { session: s.session, grants: [s.grant] })
    assert.equal(cut.complete, false, kind)
    assert.match(cut.note, /cut back|anchor/)
  }
})

test("another session's rows are not this session's activity", async () => {
  const s = fixture()
  await traffic(s)
  const other = s.vault.createSession({ label: 'other' })
  const otherGrant = s.vault.createGrant({ sessionId: other.session.id, credentialId: s.cred.id, fields: ['key'], policy: s.grant.policy })
  const a = summarizeSession(rowsOf(s), { session: other.session, grants: [otherGrant, s.grant] })
  assert.deepEqual(a.requests, { allowed: 0, denied: 0, held: 0 })
  assert.deepEqual(a.approvals, { requested: 0, granted: 0, denied: 0, replayed: 0 })
  assert.deepEqual(a.paths, [])
  assert.equal(a.complete, true)
})

test('a tripwire that fired on the session is listed', async () => {
  const s = fixture()
  const rows = [...rowsOf(s), { seq: 500, ts: '2026-10-26T00:00:00.000Z', kind: 'tripwire.fired', session_id: s.session.id, rule_id: 'replay', detail: 'nope' }]
  assert.deepEqual(summarizeSession(rows, { session: s.session, grants: [s.grant] }).tripwires, [{ rule_id: 'replay', at: '2026-10-26T00:00:00.000Z' }])
})

test('the access report counts use per credential and per session, and names granted methods never used', async () => {
  const s = fixture()
  await traffic(s)
  s.vault.setCredentialExpiry('a', new Date(Date.now() + 2 * 86_400_000).toISOString())
  const since = new Date(Date.now() - 3_600_000).toISOString()
  const r = accessReport(rowsOf(s), {
    sessions: s.vault.db.sessions, grants: s.vault.db.grants, credentials: s.vault.listCredentials(), since,
  })
  assert.equal(r.complete, true)
  assert.equal(r.since, since)
  assert.deepEqual(r.credentials, [{
    slug: 'a', sessions_active: 1, sessions_total: 1, requests: 4, denials: 1,
    // The last request that ran, not the hold after it.
    last_used_at: rowsOf(s).filter((x) => x.kind === 'request.allowed' && x.req.status === 200).at(-1).ts,
    expires_at: s.vault.findCredential('a').expires_at, expiry_warning: 'soon', health_status: null, quarantined: false,
  }])
  assert.deepEqual(r.sessions, [{
    id: s.session.id, label: 'gw', state: 'active', creds: ['a'], requests: 4, denials: 1,
    last_seen_at: s.session.last_seen_at, elevated: [], unused_methods: ['DELETE', 'POST'],
  }])
  assert.ok(!JSON.stringify(r).includes(SECRET))
})

test('the report window, an expired session and a missing creation record are all honest', async () => {
  const s = fixture()
  await traffic(s)
  const rows = rowsOf(s)
  const future = accessReport(rows, { sessions: s.vault.db.sessions, grants: s.vault.db.grants, credentials: s.vault.db.credentials, since: new Date(Date.now() + 60_000).toISOString() })
  assert.equal(future.credentials[0].requests, 0)
  assert.equal(future.sessions.length, 1, 'an active session is reviewed whatever the window')

  s.session.expires_at = new Date(Date.now() - 1000).toISOString()
  const expired = accessReport(rows, { sessions: s.vault.db.sessions, grants: s.vault.db.grants, credentials: s.vault.db.credentials, since: new Date(Date.now() - 3_600_000).toISOString() })
  assert.equal(expired.sessions[0].state, 'expired')
  assert.equal(expired.credentials[0].sessions_active, 0)

  const withoutCreation = rows.filter((x) => x.kind !== 'session.created')
  assert.equal(accessReport(withoutCreation, { sessions: s.vault.db.sessions, grants: s.vault.db.grants, credentials: s.vault.db.credentials, since: new Date(Date.now() - 3_600_000).toISOString() }).complete, false)

  for (const since of ['7d', 'garbage', '', null, 42]) {
    assert.throws(() => accessReport(rows, { sessions: {}, grants: {}, credentials: {}, since }), (e) => e.code === 'AV_POLICY_DENIED' && e.rule === 'report_since')
  }
})

test('a row the gateway marks as held is a hold, whatever else it says', async () => {
  const s = fixture()
  const created = rowsOf(s).find((r) => r.kind === 'session.created')
  const rows = [created, {
    seq: 900, ts: new Date().toISOString(), kind: 'request.allowed', decision: 'held', session_id: s.session.id,
    request_id: 'req_x', grant_id: s.grant.id, req: { method: 'DELETE', path: '/repos/one', status: 202 },
  }]
  const a = summarizeSession(rows, { session: s.session, grants: [s.grant] })
  assert.equal(a.requests.allowed, 0)
  assert.deepEqual(a.paths, [])
  const r = accessReport(rows, { sessions: s.vault.db.sessions, grants: s.vault.db.grants, credentials: s.vault.db.credentials, since: new Date(0).toISOString() })
  assert.ok(r.sessions[0].unused_methods.includes('DELETE'))
})
