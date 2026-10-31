// F11, store side: per-credential SPKI pins. A pin list is stored under the
// host the connectors read it by (urlHostOf), so the gateway and the probe
// find it under the URL host they connect to. Only hosts the credential can
// reach may be pinned, only well-formed pins are kept, and the log holds a
// count, never a pin. A backup carries pins and a restore puts them back with
// the same rules, or refuses; a quarantine still survives it (C13).

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Vault } from '../../src/store/vault.js'
import * as crypt from '../../src/store/crypto.js'
import { exportBackup, inspectBackup, restoreBackup, BACKUP_FORMAT, BACKUP_VERSION, BACKUP_KDF } from '../../src/store/backup.js'
import { pinsFor } from '../../src/connectors/pinning.js'
import { fresh, code, records, onDisk, auditText, refusedCleanly, refusedCleanlyAsync, SECRET } from './store-helpers.js'

const PIN_A = `sha256/${'A'.repeat(43)}=`
const PIN_B = `sha256/${'B'.repeat(43)}=`
const PIN_C = `sha256/${'C'.repeat(43)}=`
const RECOVERY = 'correct horse battery staple'
const KDF = { ...BACKUP_KDF, keylen: 32, maxmem: 256 * 1024 * 1024 }

async function sealedBundle(plain) {
  const salt = crypt.randomKey().subarray(0, 16)
  const head = { format: BACKUP_FORMAT, version: BACKUP_VERSION, created_at: new Date().toISOString() }
  const key = await crypt.scryptAsync(RECOVERY, salt, KDF)
  const sealed = crypt.seal(key, JSON.stringify(plain), `${head.format}|${head.version}|${head.created_at}`)
  return { ...head, kdf: { ...BACKUP_KDF, salt: salt.toString('base64') }, cipher: 'chacha20-poly1305', nonce: sealed.nonce, ct: sealed.ct }
}

function target() {
  const dir = mkdtempSync(join(tmpdir(), 'av-store-pins-restore-'))
  const vault = Vault.create(dir, { factor: 'none' })
  return { dir, vault, done: () => rmSync(dir, { recursive: true, force: true }) }
}

test('pins are stored under the canonical host, counted publicly, persisted, and logged as a count', () => {
  const v = fresh()
  try {
    const out = v.vault.setPins('demo', ' API.Example.com. ', [PIN_A, PIN_B, PIN_A])
    assert.deepEqual(out, { slug: 'demo', host: 'api.example.com', pins: 2 })
    const cred = v.vault.findCredential('demo')
    assert.deepEqual(cred.pins, { 'api.example.com': [PIN_A, PIN_B] })
    assert.deepEqual(onDisk(v).credentials[cred.id].pins, { 'api.example.com': [PIN_A, PIN_B] })
    // The gateway's and the probe's lookup finds them by the URL host.
    assert.deepEqual(pinsFor(cred, 'api.example.com'), [PIN_A, PIN_B])
    // The public view has the count, never a pin.
    const pub = v.vault.listCredentials().find((c) => c.slug === 'demo')
    assert.deepEqual(pub.pins, { 'api.example.com': 2 })
    assert.ok(!JSON.stringify(v.vault.listCredentials()).includes(PIN_A))
    assert.deepEqual(records(v, 'cred.pins_set').map(({ credential_slug, host, pins }) => ({ credential_slug, host, pins })), [{ credential_slug: 'demo', host: 'api.example.com', pins: 2 }])
    assert.ok(!auditText(v).includes('A'.repeat(43)), 'a pin reached the audit log')
    // Another spelling of the same host replaces the list; it is one entry.
    v.vault.setPins('demo', 'api.example.com', [PIN_C])
    assert.deepEqual(v.vault.findCredential('demo').pins, { 'api.example.com': [PIN_C] })
    // An unpinned credential shows no hosts.
    assert.deepEqual(v.vault.listCredentials().find((c) => c.slug === 'other').pins, {})
  } finally { v.done() }
})

test('a malformed pin list, or a host the credential cannot reach, is refused and changes nothing', () => {
  const v = fresh()
  try {
    v.vault.setPins('demo', 'api.example.com', [PIN_A])
    for (const pins of [undefined, null, 'x', PIN_A, {}, [], [PIN_A, PIN_B, PIN_C, `sha256/${'D'.repeat(43)}=`, `sha256/${'E'.repeat(43)}=`], ['sha256/short='], [`sha1/${'A'.repeat(27)}=`], [` ${PIN_A}`], [PIN_A, 42]]) {
      refusedCleanly(v, () => v.vault.setPins('demo', 'api.example.com', pins), { code: 'AV_POLICY_DENIED', rule: 'pin_format' })
    }
    for (const host of ['api.other.example', 'evil.example', '', 'api.example.com.evil.test', 42, null]) {
      refusedCleanly(v, () => v.vault.setPins('demo', host, [PIN_B]), { code: 'AV_POLICY_DENIED', rule: 'pin_host' })
    }
    refusedCleanly(v, () => v.vault.setPins('nope', 'api.example.com', [PIN_B]), { code: 'AV_NOT_FOUND', rule: undefined })
    // At most four hosts: a fifth is refused, a replacement of a pinned one is not.
    const cred = v.vault.findCredential('demo')
    cred.pins = { 'a.test': [PIN_A], 'b.test': [PIN_A], 'c.test': [PIN_A], 'd.test': [PIN_A] }
    v.vault.save()
    refusedCleanly(v, () => v.vault.setPins('demo', 'api.example.com', [PIN_B]), { code: 'AV_POLICY_DENIED', rule: 'pin_host' })
    cred.pins = { 'a.test': [PIN_A], 'b.test': [PIN_A], 'c.test': [PIN_A], 'api.example.com': [PIN_A] }
    v.vault.save()
    assert.equal(v.vault.setPins('demo', 'api.example.com', [PIN_B]).pins, 1)
  } finally { v.done() }
})

test('a host the profile reaches can be pinned on a profile credential', () => {
  const v = fresh()
  try {
    v.vault.addCredential({ slug: 'gh', kind: 'github', fields: { token: 'ghp_PINSTORE0000111122223333444455556666' } })
    assert.equal(v.vault.setPins('gh', 'uploads.github.com', [PIN_A]).host, 'uploads.github.com')
    refusedCleanly(v, () => v.vault.setPins('gh', 'api.example.com', [PIN_A]), { code: 'AV_POLICY_DENIED', rule: 'pin_host' })
  } finally { v.done() }
})

test('clearPins removes one pin or all of a host, records a count, and does nothing when nothing matches', () => {
  const v = fresh()
  try {
    v.vault.setPins('demo', 'api.example.com', [PIN_A, PIN_B])
    assert.equal(v.vault.clearPins('demo', 'API.EXAMPLE.COM', PIN_A), 1)
    assert.deepEqual(v.vault.findCredential('demo').pins, { 'api.example.com': [PIN_B] })
    // Nothing to remove: nothing written, nothing recorded.
    refusedCleanly(v, () => assert.equal(v.vault.clearPins('demo', 'api.example.com', PIN_C), 1), { code: 'none' })
    refusedCleanly(v, () => assert.equal(v.vault.clearPins('demo', 'other.example', null), 0), { code: 'none' })
    refusedCleanly(v, () => v.vault.clearPins('demo', 'api.example.com', 'not-a-pin'), { code: 'AV_POLICY_DENIED', rule: 'pin_format' })
    assert.equal(v.vault.clearPins('demo', 'api.example.com'), 0)
    assert.deepEqual(v.vault.findCredential('demo').pins, {})
    assert.deepEqual(records(v, 'cred.pins_removed').map(({ host, pins }) => [host, pins]), [['api.example.com', 1], ['api.example.com', 1]])
    v.vault.lock()
    assert.equal(code(() => v.vault.setPins('demo', 'api.example.com', [PIN_A])).code, 'AV_LOCKED')
    assert.equal(code(() => v.vault.clearPins('demo', 'api.example.com')).code, 'AV_LOCKED')
  } finally { v.done() }
})

test('a backup carries pins, and a restore puts them back under the same rules', async () => {
  const v = fresh('av-store-pins-backup-')
  const t = target()
  try {
    v.vault.setPins('demo', 'api.example.com', [PIN_A, PIN_B])
    const { bundle } = await exportBackup(v.vault, { recoveryPassphrase: RECOVERY })
    const seen = await inspectBackup(bundle, { recoveryPassphrase: RECOVERY })
    assert.deepEqual(seen.credentials.map((c) => [c.slug, c.has_pins]), [['demo', true], ['other', false]])
    const out = await restoreBackup(t.vault, bundle, { recoveryPassphrase: RECOVERY })
    assert.deepEqual(out.restored.sort(), ['demo', 'other'])
    const demo = t.vault.findCredential('demo')
    assert.deepEqual(demo.pins, { 'api.example.com': [PIN_A, PIN_B] })
    assert.deepEqual(onDisk(t).credentials[demo.id].pins, { 'api.example.com': [PIN_A, PIN_B] })
    assert.deepEqual(records(t, 'cred.pins_set').map(({ credential_slug, host, pins }) => [credential_slug, host, pins]), [['demo', 'api.example.com', 2]])
    // The restored value still works, pinned.
    assert.equal(t.vault.allSecrets().some((s) => s.secret === SECRET), true)
  } finally { v.done(); t.done() }
})

test('a restore refuses pins it could not store, whole, and records only the refusal', async () => {
  const t = target()
  try {
    const cred = { slug: 'demo', kind: 'http', connector: { host: 'api.example.com' }, created_at: 'x', fields: [{ name: 'token', value: SECRET, sites: [] }], scrub_patterns: [], expires_at: null }
    for (const [pins, rule] of [
      [{ 'api.example.com': ['sha256/short='] }, 'pin_format'],
      [{ 'api.example.com': [PIN_A, PIN_B, PIN_C, `sha256/${'D'.repeat(43)}=`, `sha256/${'E'.repeat(43)}=`] }, 'pin_format'],
      [{ 'evil.example': [PIN_A] }, 'pin_host'],
      [{ 'api.example.com': 'x' }, 'backup_format'],
      [[PIN_A], 'backup_format'],
    ]) {
      const b = await sealedBundle({ credentials: [{ ...cred, pins }], templates: [] })
      await refusedCleanlyAsync(t, () => restoreBackup(t.vault, b, { recoveryPassphrase: RECOVERY }), { code: 'AV_POLICY_DENIED', rule }, { audited: 1 })
      assert.equal(records(t, 'backup.refused').at(-1).reason, rule)
    }
    // An empty list is no pins, and two spellings of one host are one entry.
    const ok = await sealedBundle({ credentials: [{ ...cred, pins: { 'API.example.com.': [PIN_A], 'other.example': [] } }], templates: [] })
    await restoreBackup(t.vault, ok, { recoveryPassphrase: RECOVERY })
    assert.deepEqual(t.vault.findCredential('demo').pins, { 'api.example.com': [PIN_A] })
  } finally { t.done() }
})

test('a pinned, quarantined credential comes back both pinned and quarantined (C13)', async () => {
  const v = fresh('av-store-pins-q-')
  const t = target()
  try {
    v.vault.setPins('demo', 'api.example.com', [PIN_A])
    v.vault.setQuarantine('demo', { by: 'control', reason: 'leaked' })
    const { bundle } = await exportBackup(v.vault, { recoveryPassphrase: RECOVERY })
    await restoreBackup(t.vault, bundle, { recoveryPassphrase: RECOVERY })
    const demo = t.vault.findCredential('demo')
    assert.deepEqual(demo.pins, { 'api.example.com': [PIN_A] })
    assert.equal(demo.quarantine.by, 'control')
    assert.equal(code(() => t.vault.revealField(demo.id, 'token')).code, 'AV_QUARANTINED')
  } finally { v.done(); t.done() }
})
