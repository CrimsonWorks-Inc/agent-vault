// The six findings of the round-1 review of the wave-2 store, each with the
// case that reproduced it, the ordinary use it must not refuse, and the
// record that a refusal changed nothing.
//
//   1. restoreBackup stored a credential and then threw on its scrub pattern.
//   2. touchSession revived a session that had already ended.
//   3. A quarantine did not stop a placeholder issued before it.
//   4. A budget of 0 issued a thousand uses, and consume never re-read the grant.
//   5. (test/core/passphrase.test.js) every vault writer is classified.
//   6. A forked grant dropped the lifetime of the grant it copied.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdirSync, readFileSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import * as crypt from '../../src/store/crypto.js'
import { exportBackup, restoreBackup, BACKUP_FORMAT, BACKUP_VERSION, BACKUP_KDF } from '../../src/store/backup.js'
import { fresh, at, code, codeAsync, SECRET, POLICY, HOUR } from './store-helpers.js'

const RECOVERY = 'correct horse battery staple'
const KDF = { ...BACKUP_KDF, keylen: 32, maxmem: 256 * 1024 * 1024 }
const aad = (b) => `${b.format}|${b.version}|${b.created_at}`

async function sealedBundle(plain) {
  const salt = crypt.randomKey().subarray(0, 16)
  const head = { format: BACKUP_FORMAT, version: BACKUP_VERSION, created_at: new Date().toISOString() }
  const key = await crypt.scryptAsync(RECOVERY, salt, KDF)
  const sealed = crypt.seal(key, JSON.stringify(plain), aad(head))
  return { ...head, kdf: { ...BACKUP_KDF, salt: salt.toString('base64') }, cipher: 'chacha20-poly1305', nonce: sealed.nonce, ct: sealed.ct }
}

const entry = (slug, value, scrub = []) => ({
  slug, kind: 'http', connector: { host: 'api.example.com', scheme: 'https' }, created_at: new Date().toISOString(),
  fields: [{ name: 'token', value, sites: ['header:authorization:Bearer'] }],
  scrub_patterns: scrub.map((source) => ({ source })), pins: {}, expires_at: '2031-01-01',
})
const FIRST = 'ghp_RESTOREFIRST0011223344556677889900'
const SECOND = 'ghp_RESTORESECOND011223344556677889900'
const THIRD = 'ghp_RESTORETHIRD0011223344556677889900'
const TEMPLATES = [{ name: 'restored-a', spec: { cred: 'first', methods: ['GET'] } }, { name: 'restored-b', spec: { cred: 'third' } }]

/** Everything a restore could change: memory, the file's bytes, and the log. */
function state(v) {
  return { mem: JSON.stringify(v.vault.db), disk: readFileSync(join(v.dir, 'vault.json')), seq: v.vault.audit.seq }
}

/** Refused with `expected`, the vault byte for byte as it was, and one `backup.refused` in the log. */
async function refusedWhole(v, bundle, expected) {
  const before = state(v)
  assert.deepEqual(await codeAsync(() => restoreBackup(v.vault, bundle, { recoveryPassphrase: RECOVERY })), expected)
  const after = state(v)
  assert.equal(after.mem, before.mem, 'a refused restore changed the vault in memory')
  assert.ok(after.disk.equals(before.disk), 'a refused restore changed vault.json')
  const added = v.vault.audit.read({ limit: 100000 }).filter((r) => r.seq > before.seq)
  assert.deepEqual(added.map((r) => [r.kind, r.reason]), [['backup.refused', expected.rule]], 'the log holds anything but one refusal')
}

// ------------------------------------------------------------ 1. restore

test('a restore that fails at the first, a middle or the last item leaves the vault exactly as it was', async () => {
  const v = fresh('av-r2-restore-')
  try {
    // First item: the first credential's own pattern is too short.
    await refusedWhole(v, await sealedBundle({
      credentials: [entry('first', FIRST, ['ab']), entry('second', SECOND), entry('third', THIRD)], templates: TEMPLATES,
    }), { code: 'AV_POLICY_DENIED', rule: 'scrub_pattern' })
    // A middle item: a placeholder hidden in the second credential's pattern.
    const { session } = v.vault.createSession({ label: 'ph' })
    const grant = v.vault.createGrant({ sessionId: session.id, credentialId: v.cred.id, fields: ['token'], policy: POLICY })
    const { placeholder } = v.vault.issuePlaceholder({ grantId: grant.id })
    await refusedWhole(v, await sealedBundle({
      credentials: [entry('first', FIRST, ['acme_[a-z]{8}']), entry('second', SECOND, [placeholder]), entry('third', THIRD)], templates: TEMPLATES,
    }), { code: 'AV_POLICY_DENIED', rule: 'scrub_pattern' })
    // The last credential: a pattern over 256 characters, after two good ones.
    await refusedWhole(v, await sealedBundle({
      credentials: [entry('first', FIRST), entry('second', SECOND), entry('third', THIRD, ['x'.repeat(257)])], templates: TEMPLATES,
    }), { code: 'AV_POLICY_DENIED', rule: 'scrub_pattern' })
    // The last credential carries the first one's value in a pattern.
    await refusedWhole(v, await sealedBundle({
      credentials: [entry('first', FIRST), entry('second', SECOND), entry('third', THIRD, [`id=${FIRST}`])], templates: TEMPLATES,
    }), { code: 'AV_POLICY_DENIED', rule: 'scrub_pattern' })
  } finally { v.done() }
})

test('a restore whose last template does not fit writes none of the credentials before it', async () => {
  const v = fresh('av-r2-restore-tpl-')
  try {
    for (let i = 0; i < 63; i++) v.vault.saveTemplate(`t${i}`, { cred: 'demo' })
    await refusedWhole(v, await sealedBundle({
      credentials: [entry('first', FIRST), entry('second', SECOND)], templates: TEMPLATES,
    }), { code: 'AV_POLICY_DENIED', rule: 'template_size' })
  } finally { v.done() }
})

test('a restore whose one write fails is undone in memory and leaves the file as it was', async () => {
  const v = fresh('av-r2-restore-persist-')
  try {
    const bundle = await sealedBundle({ credentials: [entry('first', FIRST, ['acme_[a-z]{8}']), entry('second', SECOND)], templates: TEMPLATES })
    // The temp file is a directory, so the write fails before the rename.
    const tmp = join(v.dir, 'vault.json.tmp')
    mkdirSync(tmp)
    await refusedWhole(v, bundle, { code: 'AV_INTERNAL', rule: 'backup_persist' })
    assert.equal(v.vault.findCredential('first'), null)
    assert.equal(v.vault.getTemplate('restored-a'), null)
    // The control: once the write can happen, the same bundle restores whole.
    rmSync(tmp, { recursive: true })
    const out = await restoreBackup(v.vault, bundle, { recoveryPassphrase: RECOVERY })
    assert.deepEqual([out.restored, out.templates.restored], [['first', 'second'], ['restored-a', 'restored-b']])
    assert.equal(v.vault.revealField(v.vault.findCredential('second').id, 'token'), SECOND)
    assert.deepEqual(v.vault.findCredential('first').scrub_patterns.map((p) => p.source), ['acme_[a-z]{8}'])
  } finally { v.done() }
})

test('an ordinary restore stores everything in one write and records each item', async () => {
  const v = fresh('av-r2-restore-ok-')
  try {
    const before = v.vault.audit.seq
    const out = await restoreBackup(v.vault, await sealedBundle({
      credentials: [entry('first', FIRST, ['acme_[a-z]{8}']), entry('second', SECOND), entry('third', THIRD)], templates: TEMPLATES,
    }), { recoveryPassphrase: RECOVERY })
    assert.deepEqual(out.restored, ['first', 'second', 'third'])
    const onDisk = JSON.parse(readFileSync(join(v.dir, 'vault.json'), 'utf8'))
    assert.deepEqual(Object.values(onDisk.credentials).map((c) => c.slug).sort(), ['demo', 'first', 'other', 'second', 'third'])
    assert.equal(v.vault.findCredential('third').expires_at, '2031-01-01T00:00:00.000Z')
    const kinds = v.vault.audit.read({ limit: 100000 }).filter((r) => r.seq > before).map((r) => r.kind)
    assert.deepEqual(kinds, [
      'cred.added', 'cred.expiry_set', 'cred.scrub_pattern_added', 'cred.added', 'cred.expiry_set', 'cred.added', 'cred.expiry_set',
      'template.saved', 'template.saved', 'backup.restored',
    ])
  } finally { v.done() }
})

// ------------------------------------------------------- 2. touchSession

test('touching a session that has ended does not bring it back, in whatever order it is called', () => {
  const v = fresh('av-r2-touch-')
  try {
    // A default session: 8 hours, idle extension of 2 hours up to a 24-hour ceiling.
    const t0 = Date.parse('2032-06-01T00:00:00.000Z')
    const idle = at(t0, () => v.vault.createSession({ label: 'idle' }).session)
    const was = idle.expires_at
    // Nine hours in, untouched since: touched before anything asserts it.
    assert.equal(at(t0 + 9 * HOUR, () => v.vault.touchSession(idle)), false)
    assert.equal(idle.expires_at, was, 'an idle-expired session was extended')
    assert.equal(at(t0 + 9 * HOUR, () => code(() => v.vault.assertSessionLive(idle))).code, 'AV_SESSION_EXPIRED')
    // Marked ended, and touched again: still ended, even if its date were later moved.
    assert.equal(at(t0 + 9 * HOUR, () => v.vault.touchSession(idle)), false)
    idle.expires_at = new Date(t0 + 10 * HOUR).toISOString()
    assert.equal(at(t0 + 9 * HOUR, () => code(() => v.vault.assertSessionLive(idle))).code, 'AV_SESSION_EXPIRED')

    const revoked = at(t0, () => v.vault.createSession({ label: 'revoked' }).session)
    v.vault.revokeSession(revoked.id)
    const revokedEnds = revoked.expires_at
    assert.equal(at(t0 + HOUR, () => v.vault.touchSession(revoked)), false)
    assert.equal(revoked.expires_at, revokedEnds)
  } finally { v.done() }
})

test('a touch never moves an end earlier, nor past the ceiling, and does extend a live session', () => {
  const v = fresh('av-r2-touch-ok-')
  try {
    const t0 = Date.parse('2032-06-01T00:00:00.000Z')
    const s = at(t0, () => v.vault.createSession({ label: 'busy' }).session)
    // One hour in, now + 2h is earlier than the 8-hour end: unchanged.
    assert.equal(at(t0 + HOUR, () => v.vault.touchSession(s)), true)
    assert.equal(Date.parse(s.expires_at), t0 + 8 * HOUR)
    // Seven hours in, it moves out by the idle timeout.
    at(t0 + 7 * HOUR, () => v.vault.touchSession(s))
    assert.equal(Date.parse(s.expires_at), t0 + 9 * HOUR)
    // Kept busy, it stops at the ceiling.
    for (let t = 8.5; t <= 23.5; t += 1.5) at(t0 + t * HOUR, () => v.vault.touchSession(s))
    assert.equal(s.expires_at, s.max_expires_at)
    // A ceiling that cannot be read extends nothing.
    const odd = at(t0, () => v.vault.createSession({ label: 'odd' }).session)
    odd.max_expires_at = 'garbage'
    at(t0 + 7 * HOUR, () => v.vault.touchSession(odd))
    assert.equal(Date.parse(odd.expires_at), t0 + 8 * HOUR)
  } finally { v.done() }
})

// ---------------------------------------------------------- 3. quarantine

test('a quarantine stops a placeholder issued before it, at consume and at reveal, until it is released', () => {
  const v = fresh('av-r2-quarantine-')
  try {
    const { session } = v.vault.createSession({ label: 'q' })
    const grant = v.vault.createGrant({ sessionId: session.id, credentialId: v.cred.id, fields: ['token'], policy: POLICY })
    const { row } = v.vault.issuePlaceholder({ grantId: grant.id, uses: 3 })
    v.vault.setQuarantine('demo', { by: 'control', reason: 'review' })
    assert.deepEqual(code(() => v.vault.consumePlaceholder(row.id)), { code: 'AV_QUARANTINED', rule: 'quarantine' })
    assert.deepEqual(code(() => v.vault.revealField(v.cred.id, 'token')), { code: 'AV_QUARANTINED', rule: 'quarantine' })
    // Paused, not spent and not killed.
    assert.deepEqual([row.uses, row.state, grant.budget_used], [0, 'active', 0])
    // Still scrubbed: the value stays in the scrubber's set while it is quarantined.
    assert.ok(v.vault.allSecrets().some((s) => s.secret === SECRET))

    // The other credential is untouched by it.
    const g2 = v.vault.createGrant({ sessionId: session.id, credentialId: v.other.id, fields: ['token'], policy: POLICY })
    v.vault.consumePlaceholder(v.vault.issuePlaceholder({ grantId: g2.id }).row.id)

    v.vault.clearQuarantine('demo')
    assert.equal(v.vault.consumePlaceholder(row.id).uses, 1)
    assert.equal(v.vault.revealField(v.cred.id, 'token'), SECRET)
  } finally { v.done() }
})

test('a quarantined credential can still be rotated and backed up', async () => {
  const v = fresh('av-r2-quarantine-ok-')
  try {
    v.vault.setQuarantine('demo', { by: 'control' })
    const { bundle } = await exportBackup(v.vault, { recoveryPassphrase: RECOVERY })
    assert.ok(bundle.ct)
    const NEW = 'ghp_ROTATEDQUARANTINE0011223344556677'
    v.vault.rotateCredential('demo', { value: NEW })
    v.vault.clearQuarantine('demo')
    assert.equal(v.vault.revealField(v.cred.id, 'token'), NEW)
  } finally { v.done() }
})

// -------------------------------------------------------------- 4. budget

const budgeted = (v, limit, extra = {}) => {
  const { session } = v.vault.createSession({ label: `budget ${String(limit)}` })
  return v.vault.createGrant({
    sessionId: session.id, credentialId: v.cred.id, fields: ['token'],
    policy: { ...POLICY, budget: { unit: 'requests', limit }, ...extra },
  })
}

test('a budget of 0 issues nothing, and consume re-reads the budget and ceiling as they are now', () => {
  const v = fresh('av-r2-budget-')
  try {
    // 0 is no uses. It used to be read as "no budget" and issue 1000.
    for (const zero of [0, '0']) {
      const g = budgeted(v, zero)
      const rows = Object.keys(v.vault.db.placeholders).length
      assert.deepEqual(code(() => v.vault.issuePlaceholder({ grantId: g.id })), { code: 'AV_POLICY_DENIED', rule: 'budget' })
      assert.equal(Object.keys(v.vault.db.placeholders).length, rows)
    }

    // Spent elsewhere (redirect hops) after the placeholder was issued.
    const g3 = budgeted(v, 3)
    const { row } = v.vault.issuePlaceholder({ grantId: g3.id })
    assert.equal(row.max_uses, 3)
    for (let i = 0; i < 3; i++) assert.equal(v.vault.chargeGrant(g3.id, 1), true)
    assert.deepEqual(code(() => v.vault.consumePlaceholder(row.id)), { code: 'AV_POLICY_DENIED', rule: 'budget' })
    assert.deepEqual([row.uses, g3.budget_used], [0, 3])

    // A placeholder ceiling narrowed after issue.
    const g100 = budgeted(v, 100)
    const wide = v.vault.issuePlaceholder({ grantId: g100.id }).row
    assert.equal(wide.max_uses, 100)
    v.vault.consumePlaceholder(wide.id)
    v.vault.narrowGrant(g100.id, { placeholder_policy: { max_uses: 1 } })
    assert.equal(code(() => v.vault.consumePlaceholder(wide.id)).code, 'AV_PH_EXHAUSTED')
    assert.equal(g100.budget_used, 1)

    // A budget that cannot be read is refused at use.
    const lots = budgeted(v, 'lots')
    const lotsRow = v.vault.issuePlaceholder({ grantId: lots.id }).row
    assert.deepEqual(code(() => v.vault.consumePlaceholder(lotsRow.id)), { code: 'AV_POLICY_DENIED', rule: 'budget' })
    assert.equal(lotsRow.uses, 0)
  } finally { v.done() }
})

test('an ordinary budget spends to its limit, and a layer that names no limit is not refused', () => {
  const v = fresh('av-r2-budget-ok-')
  try {
    const g = budgeted(v, '2')
    const { row } = v.vault.issuePlaceholder({ grantId: g.id })
    v.vault.consumePlaceholder(row.id)
    v.vault.consumePlaceholder(row.id)
    assert.equal(g.budget_used, 2)
    // The row's own limit was the budget, so it is the row that says so.
    assert.equal(code(() => v.vault.consumePlaceholder(row.id)).code, 'AV_PH_EXHAUSTED')

    // The session's layer carries the limit; the grant's names only the unit.
    const open = budgeted(v, undefined)
    const r = v.vault.issuePlaceholder({ grantId: open.id }).row
    for (let i = 0; i < 5; i++) v.vault.consumePlaceholder(r.id)
    assert.equal(open.budget_used, 5)
    // No budget at all is unlimited here, as before.
    const { session } = v.vault.createSession({ label: 'none' })
    const none = v.vault.createGrant({ sessionId: session.id, credentialId: v.cred.id, fields: ['token'], policy: { hosts: ['api.example.com'] } })
    assert.equal(v.vault.issuePlaceholder({ grantId: none.id }).row.max_uses, 1000)
  } finally { v.done() }
})

// ---------------------------------------------------------------- 6. fork

test('a forked grant ends no later than the grant it copies, or its own session', () => {
  const v = fresh('av-r2-fork-')
  try {
    const t0 = Date.parse('2032-06-01T00:00:00.000Z')
    at(t0, () => {
      const { session } = v.vault.createSession({ label: 'parent', ttlMs: 2 * HOUR })
      const short = v.vault.createGrant({ sessionId: session.id, credentialId: v.cred.id, fields: ['token'], policy: POLICY, ttlMs: 30 * 60_000 })
      const whole = v.vault.createGrant({ sessionId: session.id, credentialId: v.other.id, fields: ['token'], policy: POLICY })
      const child = v.vault.forkSession(session.id, { label: 'child' }).session
      const grants = Object.values(v.vault.db.grants).filter((g) => g.session_id === child.id)
      const of = (cred) => grants.find((g) => g.credential_id === cred.id)
      assert.equal(of(v.cred).expires_at, short.expires_at, 'the child grant outlives the one it copies')
      // A grant with no lifetime of its own still lives as long as its session.
      assert.equal(whole.expires_at, null)
      assert.equal(of(v.other).expires_at, null)

      // A child with a shorter life of its own: the shorter of the two.
      const brief = v.vault.forkSession(session.id, { label: 'brief', ttlMs: 10 * 60_000 }).session
      const briefGrant = Object.values(v.vault.db.grants).find((g) => g.session_id === brief.id && g.credential_id === v.cred.id)
      assert.equal(briefGrant.expires_at, new Date(t0 + 10 * 60_000).toISOString())
    })
    // A parent grant that has ended is not copied.
    at(t0 + 45 * 60_000, () => {
      const parent = Object.values(v.vault.db.sessions).find((s) => s.label === 'parent')
      const late = v.vault.forkSession(parent.id, { label: 'late' }).session
      const copied = Object.values(v.vault.db.grants).filter((g) => g.session_id === late.id).map((g) => g.credential_id)
      assert.deepEqual(copied, [v.other.id])
    })
  } finally { v.done() }
})
