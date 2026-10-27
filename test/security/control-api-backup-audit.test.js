// Backup and audit routes (F8, F9). Exporting is FRESH: the bundle is every
// secret under a passphrase whoever runs it chooses, so a window someone
// opened for something else is not enough, and a vault with no factor
// refuses. Inspecting is open but charged like a passphrase attempt, and a
// right answer must not clear the count. Restoring is gated. The audit
// export, checkpoint and witness check are open reads, refused while locked.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { startApi, PASSPHRASE, SECRET } from './control-api-helpers.js'

const RECOVERY = 'a recovery passphrase, not the vault one'

async function exported(a) {
  const r = await a.control('POST', '/v1/backup/export', { recovery_passphrase: RECOVERY, presence: { passphrase: PASSPHRASE } })
  assert.equal(r.status, 200, JSON.stringify(r.body))
  return r.body
}

test('export needs a fresh proof: the window is refused, the passphrase works, and the bundle holds no secret', async () => {
  const a = await startApi({ passphrase: PASSPHRASE })
  try {
    a.openWindow()
    const windowed = await a.control('POST', '/v1/backup/export', { recovery_passphrase: RECOVERY })
    assert.equal(windowed.status, 401, JSON.stringify(windowed.body))
    assert.equal(windowed.body.rule, 'fresh_presence')
    const wrong = await a.control('POST', '/v1/backup/export', { recovery_passphrase: RECOVERY, presence: { passphrase: 'not it' } })
    assert.equal(wrong.body.code, 'AV_PRESENCE_DENIED')
    a.closeWindow()
    const body = await exported(a)
    assert.equal(body.summary.credentials, 1)
    assert.match(body.bundle_sha256, /^[0-9a-f]{64}$/)
    const text = JSON.stringify(body)
    assert.ok(!text.includes(SECRET), 'the secret is in the bundle in clear')
    assert.ok(!text.includes(Buffer.from(SECRET).toString('base64')), 'the secret is in the bundle as base64')
    assert.ok(!text.includes(RECOVERY))
    const short = await a.control('POST', '/v1/backup/export', { recovery_passphrase: 'short', presence: { passphrase: PASSPHRASE } })
    assert.equal(short.body.rule, 'recovery_passphrase')
    assert.ok(a.audit('presence.verified').some((r) => r.op === 'backup export' && r.fresh === true))
  } finally { await a.stop() }
})

test('export is refused on a vault with no human factor, and while locked', async () => {
  const a = await startApi()
  try {
    const r = await a.control('POST', '/v1/backup/export', { recovery_passphrase: RECOVERY })
    assert.equal(r.status, 401)
    assert.equal(r.body.rule, 'factor_required')
    a.vault.lock()
    assert.equal((await a.control('POST', '/v1/backup/export', { recovery_passphrase: RECOVERY })).body.code, 'AV_LOCKED')
    a.vault.unlockWith({})
  } finally { await a.stop() }
})

test('inspect is open, but a wrong recovery passphrase is counted, and a right one does not clear the count', async () => {
  const a = await startApi({ passphrase: PASSPHRASE })
  try {
    const { bundle } = await exported(a)
    const ok = await a.control('POST', '/v1/backup/inspect', { bundle, recovery_passphrase: RECOVERY })
    assert.equal(ok.status, 200, JSON.stringify(ok.body))
    assert.deepEqual(ok.body.credentials.map((c) => c.slug), ['demo'])
    assert.ok(a.audit('backup.inspected').length === 1)
    a.daemon.passphraseFailures = 0
    const wrong = await a.control('POST', '/v1/backup/inspect', { bundle, recovery_passphrase: 'not the recovery passphrase' })
    assert.equal(wrong.body.rule, 'backup_auth')
    assert.equal(a.daemon.passphraseFailures, 1, 'a wrong recovery passphrase was not counted')
    // An agent that made a bundle itself must not be able to reset the
    // throttle on the vault passphrase it is guessing.
    a.daemon.passphraseFailures = 3
    assert.equal((await a.control('POST', '/v1/backup/inspect', { bundle, recovery_passphrase: RECOVERY })).status, 200)
    assert.equal(a.daemon.passphraseFailures, 3, 'a right recovery passphrase cleared the count')
    // Past the free attempts, it waits.
    a.daemon.passphraseFailures = 99
    a.daemon.passphraseLockedUntil = Date.now() + 10_000
    const throttled = await a.control('POST', '/v1/backup/inspect', { bundle, recovery_passphrase: RECOVERY })
    assert.equal(throttled.body.code, 'AV_RATE_LIMITED')
    a.daemon.passphraseFailures = 0
    a.daemon.passphraseLockedUntil = 0
    const notBundle = await a.control('POST', '/v1/backup/inspect', { bundle: { format: 'other' }, recovery_passphrase: RECOVERY })
    assert.equal(notBundle.body.rule, 'backup_format')
  } finally { await a.stop() }
})

test('restore needs a human, and gives back credentials but never a session', async () => {
  const a = await startApi({ passphrase: PASSPHRASE })
  const b = await startApi({ passphrase: PASSPHRASE })
  try {
    const s = a.session()
    const { bundle } = await exported(a)
    const refused = await b.control('POST', '/v1/backup/restore', { bundle, recovery_passphrase: RECOVERY })
    assert.equal(refused.status, 401)
    assert.equal(refused.body.code, 'AV_PRESENCE_REQUIRED')
    b.openWindow()
    b.daemon.passphraseFailures = 0
    const wrong = await b.control('POST', '/v1/backup/restore', { bundle, recovery_passphrase: 'not the recovery passphrase' })
    assert.equal(wrong.body.rule, 'backup_auth')
    assert.equal(b.daemon.passphraseFailures, 1)
    b.daemon.passphraseFailures = 0
    const r = await b.control('POST', '/v1/backup/restore', { bundle, recovery_passphrase: RECOVERY, on_conflict: 'rename' })
    assert.equal(r.status, 200, JSON.stringify(r.body))
    assert.deepEqual(r.body.renamed, [{ from: 'demo', to: 'demo-restored' }])
    assert.ok(b.vault.findCredential('demo-restored'))
    // The other vault's session means nothing here.
    const res = await b.gateway('/p/demo-restored/x', { headers: { authorization: `Bearer ${s.token}` } })
    assert.notEqual(res.status, 200)
    const fail = await b.control('POST', '/v1/backup/restore', { bundle, recovery_passphrase: RECOVERY, on_conflict: 'fail' })
    assert.equal(fail.body.rule, 'backup_conflict')
  } finally { await a.stop(); await b.stop() }
})

test('audit export, checkpoint and witness check are open reads, refused while locked (F9)', async () => {
  const a = await startApi()
  try {
    a.session()
    const page = await a.control('GET', '/v1/audit/export?since_seq=0&limit=3')
    assert.equal(page.status, 200, JSON.stringify(page.body))
    assert.equal(page.body.rows.length, 3)
    assert.equal(page.body.next_seq, page.body.rows[2].seq)
    const rest = await a.control('GET', `/v1/audit/export?since_seq=${page.body.next_seq}`)
    assert.ok(rest.body.rows.every((r) => r.seq > page.body.next_seq))
    for (const q of ['since_seq=x', 'since_seq=-1', 'since_seq=1.5', 'limit=', 'limit=1e3', 'since_seq=%201']) {
      const r = await a.control('GET', `/v1/audit/export?${q}`)
      assert.equal(r.status, 403, q)
      assert.equal(r.body.rule, 'audit_range', q)
    }
    const cp = await a.control('GET', '/v1/audit/checkpoint')
    assert.equal(cp.status, 200)
    assert.match(cp.body.mac, /^[0-9a-f]{64}$/)
    const ok = await a.control('POST', '/v1/audit/verify-witness', { checkpoints: [cp.body] })
    assert.equal(ok.body.ok, true, JSON.stringify(ok.body))
    const forged = await a.control('POST', '/v1/audit/verify-witness', { checkpoints: [{ ...cp.body, seq: cp.body.seq - 1 }] })
    assert.equal(forged.body.ok, false)
    assert.deepEqual(forged.body.forged, [0])
    assert.equal((await a.control('POST', '/v1/audit/verify-witness', { checkpoints: 'all' })).body.rule, 'audit_range')
    a.vault.lock()
    for (const [m, p, b] of [['GET', '/v1/audit/export'], ['GET', '/v1/audit/checkpoint'], ['POST', '/v1/audit/verify-witness', { checkpoints: [] }]]) {
      assert.equal((await a.control(m, p, b)).body.code, 'AV_LOCKED', p)
    }
    a.vault.unlockWith({})
  } finally { await a.stop() }
})
