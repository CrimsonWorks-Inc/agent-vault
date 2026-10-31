// F4, store side: scrub-pattern CRUD on the credential record. The grammar
// is the gateway's (compileScrubPattern); the store keeps the bounds, and keeps
// a secret or a placeholder out of a pattern everyone who lists credentials sees.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { fresh, code, records, onDisk, auditText, refusedCleanly, SECRET, OTHER_SECRET, POLICY } from './store-helpers.js'

const PATTERN = 'acme_[A-Za-z0-9]{20,40}'

test('a scrub pattern is added, listed, persisted and audited by digest only', () => {
  const v = fresh()
  try {
    const p = v.vault.addScrubPattern('demo', PATTERN)
    assert.match(p.id, /^sp_[0-9A-Z]{26}$/)
    assert.equal(p.source, PATTERN)
    assert.ok(Date.parse(p.added_at))
    assert.deepEqual(v.vault.listCredentials().find((c) => c.slug === 'demo').scrub_patterns, [p])
    assert.deepEqual(v.vault.listCredentials().find((c) => c.slug === 'other').scrub_patterns, [])
    assert.deepEqual(onDisk(v).credentials[v.cred.id].scrub_patterns, [p])

    const [rec] = records(v, 'cred.scrub_pattern_added')
    assert.deepEqual(
      [rec.credential_slug, rec.pattern_id, rec.pattern_sha256, rec.length],
      ['demo', p.id, createHash('sha256').update(PATTERN).digest('hex'), PATTERN.length],
    )
    assert.ok(!auditText(v).includes(PATTERN), 'the pattern source reached the audit log')

    // The listed copy is a copy.
    v.vault.listCredentials()[0].scrub_patterns.length = 0
    assert.equal(v.vault.findCredential('demo').scrub_patterns.length, 1)
  } finally { v.done() }
})

test('removing a pattern removes that one, once', () => {
  const v = fresh()
  try {
    const a = v.vault.addScrubPattern('demo', PATTERN)
    const b = v.vault.addScrubPattern('demo', 'xoxb-[0-9]{10,13}')
    assert.equal(v.vault.removeScrubPattern('demo', a.id), true)
    assert.equal(v.vault.removeScrubPattern('demo', a.id), false)
    assert.equal(v.vault.removeScrubPattern('demo', 'sp_nope'), false)
    assert.deepEqual(v.vault.findCredential('demo').scrub_patterns.map((p) => p.id), [b.id])
    assert.deepEqual(records(v, 'cred.scrub_pattern_removed').map((r) => [r.credential_slug, r.pattern_id]), [['demo', a.id]])
  } finally { v.done() }
})

test('a pattern that is too short, too long or not text is refused', () => {
  const v = fresh()
  try {
    for (const source of ['ab', '', 'x'.repeat(257), 42, null, undefined, ['abc']]) {
      refusedCleanly(v, () => v.vault.addScrubPattern('demo', source), { code: 'AV_POLICY_DENIED', rule: 'scrub_pattern' })
    }
    // The bounds themselves are allowed.
    v.vault.addScrubPattern('demo', 'abc')
    v.vault.addScrubPattern('demo', 'y'.repeat(256))
  } finally { v.done() }
})

test('a pattern that contains a stored credential value or a placeholder is refused', () => {
  const v = fresh()
  try {
    for (const source of [SECRET, `prefix${SECRET}`, `${OTHER_SECRET}|abc`]) {
      refusedCleanly(v, () => v.vault.addScrubPattern('demo', source), { code: 'AV_POLICY_DENIED', rule: 'scrub_pattern' })
    }
    const { session } = v.vault.createSession({})
    const grant = v.vault.createGrant({ sessionId: session.id, credentialId: v.cred.id, fields: ['token'], policy: POLICY })
    const { placeholder } = v.vault.issuePlaceholder({ grantId: grant.id })
    refusedCleanly(v, () => v.vault.addScrubPattern('demo', `Bearer ${placeholder}`), { code: 'AV_POLICY_DENIED', rule: 'scrub_pattern' })
    // The C5 grammar refuses a placeholder's dots as well, with the same rule;
    // this says the placeholder check itself is the one that answered first.
    assert.throws(() => v.vault.addScrubPattern('demo', `Bearer ${placeholder}`), /it contains a placeholder/)
    // A prefix of the secret's shape is the ordinary case, and is fine.
    v.vault.addScrubPattern('demo', 'ghp_[A-Za-z0-9]{36}')
  } finally { v.done() }
})

test('at most 16 patterns per credential and 64 in the vault', () => {
  const v = fresh()
  try {
    for (let i = 0; i < 16; i++) v.vault.addScrubPattern('demo', `aaa${i}`)
    refusedCleanly(v, () => v.vault.addScrubPattern('demo', 'aaa-one-more'), { code: 'AV_POLICY_DENIED', rule: 'scrub_pattern' })
    for (const slug of ['c3', 'c4', 'c5']) {
      v.vault.addCredential({ slug, kind: 'http', connector: { host: `${slug}.example` }, fields: { token: `tok_${slug}_0011223344556677` } })
      for (let i = 0; i < 16; i++) v.vault.addScrubPattern(slug, `bbb${slug}${i}`)
    }
    refusedCleanly(v, () => v.vault.addScrubPattern('other', 'ccc-sixty-five'), { code: 'AV_POLICY_DENIED', rule: 'scrub_pattern' })
    // Removing one makes room again.
    v.vault.removeScrubPattern('c5', v.vault.findCredential('c5').scrub_patterns[0].id)
    v.vault.addScrubPattern('other', 'ccc-sixty-four')
  } finally { v.done() }
})

test('scrub-pattern writes need the credential to exist and the vault to be unlocked', () => {
  const v = fresh()
  try {
    refusedCleanly(v, () => v.vault.addScrubPattern('nope', PATTERN), { code: 'AV_NOT_FOUND', rule: undefined })
    refusedCleanly(v, () => v.vault.removeScrubPattern('nope', 'sp_x'), { code: 'AV_NOT_FOUND', rule: undefined })
    const p = v.vault.addScrubPattern('demo', PATTERN)
    v.vault.lock()
    assert.equal(code(() => v.vault.addScrubPattern('demo', 'abcdef')).code, 'AV_LOCKED')
    assert.equal(code(() => v.vault.removeScrubPattern('demo', p.id)).code, 'AV_LOCKED')
    assert.equal(v.vault.db.credentials[v.cred.id].scrub_patterns.length, 1)
  } finally { v.done() }
})
