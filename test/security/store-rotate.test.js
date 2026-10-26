// F7, store side: credential rotation with a versioned cutover. The new value
// is what gets substituted from the moment it is stored; the old one is kept
// sealed only so it is still scrubbed for the retire window, then dropped.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { Vault } from '../../src/store/vault.js'
import { fresh, at, code, records, onDisk, auditText, refusedCleanly, SECRET, OTHER_SECRET, POLICY, HOUR, DAY } from './store-helpers.js'

const NEW = 'ghp_ROTATEDNEW00112233445566778899aabbcc'

function liveGrant(v, cred = v.cred) {
  const { session } = v.vault.createSession({})
  const grant = v.vault.createGrant({ sessionId: session.id, credentialId: cred.id, fields: ['token'], policy: POLICY })
  return { session, grant }
}

const secretsFor = (v, slug) => v.vault.allSecrets().filter((s) => s.label === slug)

test('keep mode: the new value is substituted at once, and placeholders already handed out keep working', () => {
  const v = fresh()
  try {
    const { grant } = liveGrant(v)
    const { row } = v.vault.issuePlaceholder({ grantId: grant.id })
    const before = v.vault.listCredentials().find((c) => c.slug === 'demo').fields[0]
    const { credential, rotated } = v.vault.rotateCredential('demo', { value: NEW })

    assert.equal(v.vault.revealField(v.cred.id, 'token'), NEW)
    v.vault.consumePlaceholder(row.id)
    assert.equal(grant.state, 'active')
    assert.equal(rotated.field, 'token')
    assert.equal(rotated.version, 2)
    assert.equal(rotated.mode, 'keep')
    assert.equal(rotated.revoked_grants, 0)
    assert.equal(rotated.previous_fp8, before.fp8)
    assert.notEqual(rotated.fp8, before.fp8)
    // Keyed, like every fingerprint: never a bare hash of the secret.
    assert.notEqual(rotated.fp8, createHash('sha256').update(NEW).digest('hex').slice(0, 8))
    assert.equal(credential.fields[0].version, 2)
    assert.ok(Date.parse(credential.fields[0].rotated_at))
    assert.ok(Math.abs(Date.parse(rotated.retire_until) - (Date.now() + DAY)) < 2000)

    // And it survives a restart: sealed with the AAD the next read expects.
    const again = Vault.open(v.dir)
    again.unlock()
    assert.equal(again.revealField(v.cred.id, 'token'), NEW)
  } finally { v.done() }
})

test('the rotation is audited with fingerprints and counts, never a value', () => {
  const v = fresh()
  try {
    const { rotated } = v.vault.rotateCredential('demo', { value: NEW, retireMs: HOUR })
    const [rec] = records(v, 'cred.rotated')
    for (const k of ['field', 'version', 'previous_fp8', 'fp8', 'mode', 'revoked_grants', 'retire_until']) assert.equal(rec[k], rotated[k], k)
    assert.equal(rec.credential_slug, 'demo')
    const log = auditText(v)
    for (const s of [SECRET, NEW, Buffer.from(NEW).toString('base64')]) assert.ok(!log.includes(s), 'a value reached the audit log')
    const disk = JSON.stringify(onDisk(v))
    for (const s of [SECRET, NEW]) assert.ok(!disk.includes(s), 'a value reached vault.json unsealed')
  } finally { v.done() }
})

test('the old value is still scrubbed within the retire window, and not after it', () => {
  const v = fresh()
  try {
    v.vault.rotateCredential('demo', { value: NEW, retireMs: HOUR })
    const now = secretsFor(v, 'demo')
    assert.deepEqual(now.map((s) => [s.secret, !!s.retired]), [[NEW, false], [SECRET, true]])
    const later = at(Date.now() + 2 * HOUR, () => secretsFor(v, 'demo'))
    assert.deepEqual(later.map((s) => s.secret), [NEW])
    // Reading never drops anything; the next rotation does.
    assert.equal(v.vault.findCredential('demo').fields[0].retired.length, 1)
    at(Date.now() + 2 * HOUR, () => v.vault.rotateCredential('demo', { value: 'ghp_THIRD00112233445566778899aabbccdd' }))
    assert.deepEqual(v.vault.findCredential('demo').fields[0].retired.map((r) => r.key_version), [2])
    // Retired values never substitute.
    assert.equal(v.vault.revealField(v.cred.id, 'token'), 'ghp_THIRD00112233445566778899aabbccdd')
  } finally { v.done() }
})

test('a zero retire window keeps nothing of the old value', () => {
  const v = fresh()
  try {
    v.vault.rotateCredential('demo', { value: NEW, retireMs: 0 })
    assert.deepEqual(v.vault.findCredential('demo').fields[0].retired, [])
    assert.deepEqual(secretsFor(v, 'demo').map((s) => s.secret), [NEW])
  } finally { v.done() }
})

test('a retired value still counts as a stored value for scrub patterns', () => {
  const v = fresh()
  try {
    v.vault.rotateCredential('demo', { value: NEW })
    refusedCleanly(v, () => v.vault.addScrubPattern('other', `x${SECRET}`), { code: 'AV_POLICY_DENIED', rule: 'scrub_pattern' })
  } finally { v.done() }
})

test('revoke mode revokes the credential\'s grants and kills their placeholders, and nobody else\'s', () => {
  const v = fresh()
  try {
    const a = liveGrant(v)
    const b = liveGrant(v)
    const mine = v.vault.issuePlaceholder({ grantId: a.grant.id }).row
    const theirs = liveGrant(v, v.other)
    const otherRow = v.vault.issuePlaceholder({ grantId: theirs.grant.id }).row
    const { rotated } = v.vault.rotateCredential('demo', { value: NEW, mode: 'revoke' })
    assert.equal(rotated.revoked_grants, 2)
    assert.equal(a.grant.state, 'revoked')
    assert.equal(b.grant.state, 'revoked')
    assert.equal(code(() => v.vault.consumePlaceholder(mine.id)).code, 'AV_PH_REPLAY')
    assert.deepEqual(records(v, 'grant.revoked').map((r) => r.reason), ['credential_rotated', 'credential_rotated'])
    assert.equal(theirs.grant.state, 'active')
    v.vault.consumePlaceholder(otherRow.id)
  } finally { v.done() }
})

test('the expiry is cleared by default and set when given', () => {
  const v = fresh()
  try {
    v.vault.setCredentialExpiry('demo', '2030-01-01')
    v.vault.rotateCredential('demo', { value: NEW })
    assert.equal(v.vault.findCredential('demo').expires_at, null)
    v.vault.rotateCredential('demo', { value: `${NEW}x`, expiresAt: '2031-02-03' })
    assert.equal(v.vault.findCredential('demo').expires_at, '2031-02-03T00:00:00.000Z')
    v.vault.rotateCredential('demo', { value: `${NEW}y`, expiresAt: null })
    assert.equal(v.vault.findCredential('demo').expires_at, null)
  } finally { v.done() }
})

test('a bad rotation is refused before anything changes, revoke mode included', () => {
  const v = fresh()
  try {
    liveGrant(v)
    v.vault.issuePlaceholder({ grantId: liveGrant(v).grant.id })
    const bad = [
      [{ value: SECRET }, { code: 'AV_POLICY_DENIED', rule: 'rotate_same_value' }],
      [{ value: NEW, mode: 'nuke' }, { code: 'AV_POLICY_DENIED', rule: 'rotate_mode' }],
      [{ value: NEW, mode: 'revoke', retireMs: -1 }, { code: 'AV_POLICY_DENIED', rule: 'retire_window' }],
      [{ value: NEW, mode: 'revoke', retireMs: 7 * DAY + 1 }, { code: 'AV_POLICY_DENIED', rule: 'retire_window' }],
      [{ value: NEW, retireMs: 1.5 }, { code: 'AV_POLICY_DENIED', rule: 'retire_window' }],
      [{ value: NEW, retireMs: NaN }, { code: 'AV_POLICY_DENIED', rule: 'retire_window' }],
      [{ value: NEW, retireMs: '100' }, { code: 'AV_POLICY_DENIED', rule: 'retire_window' }],
      // Gemini's version checked this after revoking the grants.
      [{ value: NEW, mode: 'revoke', expiresAt: 'garbage' }, { code: 'AV_POLICY_DENIED', rule: 'expires_at' }],
      [{ value: '' }, { code: 'AV_POLICY_DENIED', rule: undefined }],
      [{ value: 42 }, { code: 'AV_POLICY_DENIED', rule: undefined }],
      [{ value: NEW, field: 'nope' }, { code: 'AV_NOT_FOUND', rule: undefined }],
    ]
    for (const [opts, expected] of bad) refusedCleanly(v, () => v.vault.rotateCredential('demo', opts), expected)
    refusedCleanly(v, () => v.vault.rotateCredential('nope', { value: NEW }), { code: 'AV_NOT_FOUND', rule: undefined })
    // The edges of the window are fine.
    v.vault.rotateCredential('demo', { value: NEW, retireMs: 7 * DAY })
    v.vault.rotateCredential('other', { value: `${OTHER_SECRET}2`, retireMs: 0 })
    v.vault.lock()
    assert.equal(code(() => v.vault.rotateCredential('demo', { value: 'x-new-value' })).code, 'AV_LOCKED')
  } finally { v.done() }
})
