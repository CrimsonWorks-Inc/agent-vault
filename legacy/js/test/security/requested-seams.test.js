// Where the daemon's session paths meet store slice A's own refusals.
//
// The store refuses a grant on a quarantined credential (AV_QUARANTINED, rule
// 'quarantine') and a grant on an ended session. The daemon meets the same
// refusal first, with the same code and rule, so no session is made only to
// be torn down again, and a direct create asks for no passphrase first.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { startDaemon, PASSPHRASE } from './fix-control-helpers.js'

const presence = { passphrase: PASSPHRASE }

function assertQuarantined(r) {
  assert.equal(r.status, 403, JSON.stringify(r.body))
  assert.equal(r.body.code, 'AV_QUARANTINED')
  assert.equal(r.body.rule, 'quarantine')
}

const sessionCount = (d) => Object.keys(d.vault.db.sessions).length
const createdCount = (d) => d.vault.audit.read({ limit: 100000, kind: 'session.created' })
  .filter((r) => r.kind === 'session.created').length

test('a session for a quarantined credential is refused before the gate asks for anything', async () => {
  const d = await startDaemon({ passphrase: PASSPHRASE, socketName: 'control.sock' })
  try {
    d.vault.setQuarantine('demo')
    // No window and no proof: refused as quarantined, not as needing a human.
    for (const body of [{ cred: 'demo' }, { cred: 'demo', infinite: true }, { grants: [{ cred: 'demo', approval: 'auto', methods: ['POST'] }] }]) {
      assertQuarantined(await d.control('POST', '/v1/sessions', body))
    }
    assertQuarantined(await d.control('POST', '/v1/sessions', { cred: 'demo', infinite: true, presence }))
    assert.equal(sessionCount(d), 0)
    assert.equal(createdCount(d), 0, 'no session was made and torn down again')
  } finally { await d.stop() }
})

test('approving a request for a quarantined credential is refused and leaves it pending', async () => {
  const d = await startDaemon({ passphrase: PASSPHRASE, socketName: 'control.sock' })
  try {
    const ask = async () => (await d.control('POST', '/v1/session-requests', { cred: 'demo', reason: 'job' })).body.id
    const one = await ask()
    const two = await ask()
    d.vault.setQuarantine('demo')
    // A decision is gated before the approved proposal is planned, as every
    // other refusal of an approval is; what matters is that nothing is made.
    d.daemon.presenceGraceUntil = Date.now() + 60_000
    assertQuarantined(await d.control('POST', '/v1/session-requests/decide', { id: one, granted: true }))
    assert.equal(d.daemon.sessionRequests.get(one).state, 'pending')

    const many = await d.control('POST', '/v1/pending/decide-many', { decisions: [{ id: two, kind: 'session', granted: true }] })
    assert.equal(many.status, 200, JSON.stringify(many.body))
    assert.equal(many.body.decided[0].outcome, 'skipped')
    assert.match(many.body.decided[0].reason, /quarantined/)
    assert.equal(d.daemon.sessionRequests.get(two).state, 'pending')
    assert.equal(sessionCount(d), 0)
  } finally { await d.stop() }
})

test('a placeholder batch for a quarantined credential is refused whole, with the store\'s rule', async () => {
  const d = await startDaemon({ passphrase: PASSPHRASE, socketName: 'control.sock' })
  try {
    d.daemon.presenceGraceUntil = Date.now() + 60_000
    const s = await d.control('POST', '/v1/sessions', { cred: 'demo' })
    assert.equal(s.status, 200, JSON.stringify(s.body))
    const rows = () => Object.keys(d.vault.db.placeholders).length
    const before = rows()
    d.vault.setQuarantine('demo')
    d.daemon.presenceGraceUntil = Date.now() + 60_000
    assertQuarantined(await d.control('POST', '/v1/placeholders/batch', { sid: s.body.session_id, items: [{ cred: 'demo' }] }))
    assert.equal(rows(), before)
  } finally { await d.stop() }
})

test('a placeholder batch on a grant that has ended is refused by the store\'s grant check', async () => {
  const d = await startDaemon({ passphrase: PASSPHRASE, socketName: 'control.sock' })
  try {
    d.daemon.presenceGraceUntil = Date.now() + 60_000
    const s = await d.control('POST', '/v1/sessions', { cred: 'demo' })
    assert.equal(s.status, 200, JSON.stringify(s.body))
    d.vault.db.grants[s.body.grant_id].expires_at = new Date(Date.now() - 1000).toISOString()
    const before = Object.keys(d.vault.db.placeholders).length
    const r = await d.control('POST', '/v1/placeholders/batch', { sid: s.body.session_id, items: [{ cred: 'demo' }] })
    assert.equal(r.status >= 400, true, JSON.stringify(r.body))
    assert.match(r.body.code, /^AV_GRANT_/)
    assert.equal(Object.keys(d.vault.db.placeholders).length, before)
  } finally { await d.stop() }
})
