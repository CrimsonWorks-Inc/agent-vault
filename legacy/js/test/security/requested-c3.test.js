// C3: what elevated a session is written into its session.created record.
//
// The daemon decides the elevation (elevationOf, over the same body it gated)
// and the store records it. Every path that creates a session — the owner's
// own create, a single approval and a bulk decision — must hand it over, and
// each session records its own elevation, not the strictest one in its batch.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { startDaemon, PASSPHRASE } from './fix-control-helpers.js'

const presence = { passphrase: PASSPHRASE }

/** The session.created record for one session. */
function createdRecord(d, sid) {
  const recs = d.vault.audit.read({ limit: 100000, kind: 'session.created' })
    .filter((r) => r.kind === 'session.created' && r.session_id === sid)
  assert.equal(recs.length, 1, `one session.created record for ${sid}`)
  return recs[0]
}

async function requestFor(d, body) {
  const r = await d.control('POST', '/v1/session-requests', { cred: 'demo', reason: 'job', ...body })
  assert.equal(r.status, 200, JSON.stringify(r.body))
  return r.body.id
}

test('a session the owner creates records its elevation, [] when ordinary', async () => {
  const d = await startDaemon({ passphrase: PASSPHRASE, socketName: 'control.sock' })
  try {
    const cases = [
      [{ cred: 'demo', methods: ['GET'] }, [], false],
      [{ cred: 'demo', methods: ['GET', 'POST'], approval: 'auto' }, ['approval_auto_writes'], false],
      [{ cred: 'demo', methods: ['GET'], infinite: true }, ['infinite'], true],
      [{ cred: 'demo', methods: ['POST'], approval: 'auto', infinite: true }, ['infinite', 'approval_auto_writes'], true],
    ]
    for (const [body, elevated, infinite] of cases) {
      // An ordinary create takes the window; an elevated one, the passphrase.
      d.daemon.presenceGraceUntil = Date.now() + 60_000
      const r = await d.control('POST', '/v1/sessions', { ...body, presence })
      assert.equal(r.status, 200, JSON.stringify(r.body))
      const rec = createdRecord(d, r.body.session_id)
      assert.deepEqual(rec.elevated, elevated, JSON.stringify(body))
      assert.equal(rec.infinite, infinite)
      if (infinite) assert.equal(rec.expires_at, null)
      else assert.ok(Date.parse(rec.expires_at) > Date.now(), rec.expires_at)
    }
  } finally { await d.stop() }
})

test('an approved request records the elevation of what the owner approved', async () => {
  const d = await startDaemon({ passphrase: PASSPHRASE, socketName: 'control.sock' })
  try {
    const cases = [
      [{ methods: ['GET'] }, undefined, []],
      // The agent asked for an ordinary session; the owner's edit is what elevates it.
      [{ methods: ['GET', 'POST'] }, { approval: 'auto' }, ['approval_auto_writes']],
      [{ methods: ['GET'] }, { infinite: true }, ['infinite']],
    ]
    for (const [body, overrides, elevated] of cases) {
      const id = await requestFor(d, body)
      d.daemon.presenceGraceUntil = Date.now() + 60_000
      const r = await d.control('POST', '/v1/session-requests/decide', { id, granted: true, overrides, presence })
      assert.equal(r.status, 200, JSON.stringify(r.body))
      assert.deepEqual(createdRecord(d, r.body.session.session_id).elevated, elevated, JSON.stringify({ body, overrides }))
    }
  } finally { await d.stop() }
})

test('a bulk decision records each session\'s own elevation, not the batch\'s', async () => {
  const d = await startDaemon({ passphrase: PASSPHRASE, socketName: 'control.sock' })
  try {
    const plain = await requestFor(d, { methods: ['GET'] })
    const wide = await requestFor(d, { methods: ['GET', 'POST'] })
    const forever = await requestFor(d, { methods: ['GET'] })
    const r = await d.control('POST', '/v1/pending/decide-many', {
      decisions: [
        { id: plain, kind: 'session', granted: true },
        { id: wide, kind: 'session', granted: true, overrides: { approval: 'auto' } },
        { id: forever, kind: 'session', granted: true, overrides: { infinite: true } },
      ],
      presence,
    })
    assert.equal(r.status, 200, JSON.stringify(r.body))
    assert.deepEqual(r.body.decided.map((x) => x.outcome), ['decided', 'decided', 'decided'])
    // With several granted, each asker collects its own; the record holds the session id.
    const sidOf = (id) => d.daemon.sessionRequests.get(id).result.session_id
    assert.deepEqual(createdRecord(d, sidOf(plain)).elevated, [])
    assert.deepEqual(createdRecord(d, sidOf(wide)).elevated, ['approval_auto_writes'])
    assert.deepEqual(createdRecord(d, sidOf(forever)).elevated, ['infinite'])
  } finally { await d.stop() }
})

test('an elevation the store does not know is refused, and nothing is written', async () => {
  const d = await startDaemon({ passphrase: PASSPHRASE, socketName: 'control.sock' })
  try {
    // Stands in for a daemon that computes a name the store has never heard of.
    const original = d.vault.createSession.bind(d.vault)
    d.vault.createSession = (opts) => original({ ...opts, elevated: [...opts.elevated, 'root'] })
    const counts = () => ['sessions', 'grants', 'placeholders'].map((k) => Object.keys(d.vault.db[k]).length)
    const before = counts()
    const disk = readFileSync(join(d.dir, 'vault.json'), 'utf8')
    d.daemon.presenceGraceUntil = Date.now() + 60_000
    const seq = d.vault.audit.seq
    for (const body of [{ cred: 'demo', methods: ['GET'] }, { cred: 'demo', methods: ['POST'], approval: 'auto', presence }]) {
      const r = await d.control('POST', '/v1/sessions', body)
      assert.equal(r.status, 403, JSON.stringify(r.body))
      assert.equal(r.body.rule, 'elevation_invalid')
    }
    assert.deepEqual(counts(), before)
    assert.equal(readFileSync(join(d.dir, 'vault.json'), 'utf8'), disk, 'a refusal changed the vault on disk')
    // The gate logs who it let through; the refusal itself adds nothing.
    const written = d.vault.audit.read({ limit: 100000 }).filter((r) => r.seq > seq).map((r) => r.kind)
    assert.deepEqual(written, ['presence.window_used', 'presence.verified'])
  } finally { await d.stop() }
})
