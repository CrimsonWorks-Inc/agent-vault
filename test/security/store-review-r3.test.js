// A restore never releases a quarantine (round 3 of the wave-2 store review).
//
// A bundle left quarantine out, so restoring a quarantined credential (under
// `rename`, say) brought back a released copy: a widening no human chose.
//
//   (a) A bundle carries each credential's quarantine record, as stored.
//   (b) Restore puts it back.
//   (c) A credential this vault holds quarantined, under the bundle's slug or
//       a renamed copy of it, keeps the restored copy quarantined, whatever
//       the bundle says.
//   (d) A bundle from before (a), with no quarantine field, restores as not
//       quarantined from the bundle, and (c) still applies.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import * as crypt from '../../src/store/crypto.js'
import { exportBackup, inspectBackup, restoreBackup, BACKUP_FORMAT, BACKUP_VERSION, BACKUP_KDF } from '../../src/store/backup.js'
import { fresh, code, codeAsync, records, SECRET, OTHER_SECRET, POLICY } from './store-helpers.js'

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

async function opened(bundle) {
  const key = await crypt.scryptAsync(RECOVERY, Buffer.from(bundle.kdf.salt, 'base64'), KDF)
  return JSON.parse(crypt.openBytes(key, { ct: bundle.ct, nonce: bundle.nonce }, aad(bundle)).toString('utf8'))
}

/** A bundle entry as written before (a): no quarantine field at all. */
const oldEntry = (slug, value) => ({
  slug, kind: 'http', connector: { host: 'api.example.com', scheme: 'https' }, created_at: new Date().toISOString(),
  fields: [{ name: 'token', value, sites: ['header:authorization:Bearer'] }], scrub_patterns: [], pins: {}, expires_at: null,
})

const restore = (v, bundle, onConflict) => restoreBackup(v.vault, bundle, { recoveryPassphrase: RECOVERY, onConflict })
const quarantineOf = (v, slug) => v.vault.publicCredential(v.vault.findCredential(slug)).quarantine
const reveal = (v, slug) => code(() => v.vault.revealField(v.vault.findCredential(slug).id, 'token'))
const QUARANTINED = { code: 'AV_QUARANTINED', rule: 'quarantine' }

/** A vault with nothing in it but the factor, so a restore has no conflict. */
function empty(prefix) {
  const t = fresh(prefix)
  t.vault.deleteCredential('demo')
  t.vault.deleteCredential('other')
  return t
}

// ------------------------------------------------------------------ (a)

test('(a) a bundle carries each credential\'s quarantine record exactly as stored', async () => {
  const v = fresh('av-r3-carry-')
  try {
    const stored = v.vault.setQuarantine('demo', { by: 'tripwire', rule_id: 'many-404s', reason: 'probing /admin' })
    const { bundle } = await exportBackup(v.vault, { recoveryPassphrase: RECOVERY })
    const plain = await opened(bundle)
    const bySlug = Object.fromEntries(plain.credentials.map((c) => [c.slug, c]))
    assert.deepEqual(bySlug.demo.quarantine, stored)
    assert.deepEqual(Object.keys(bySlug.demo.quarantine).sort(), ['by', 'reason_untrusted', 'rule_id', 'since'])
    assert.equal(bySlug.other.quarantine, null)
    // Shown before a restore, so the human knows it comes back stopped.
    const seen = await inspectBackup(bundle, { recoveryPassphrase: RECOVERY })
    assert.deepEqual(seen.credentials.map((c) => [c.slug, c.quarantined]), [['demo', true], ['other', false]])
  } finally { v.done() }
})

// ------------------------------------------------------------------ (b)

test('(b) a credential quarantined at backup time is quarantined after restore, until a human releases it', async () => {
  const v = fresh('av-r3-reapply-src-')
  const t = empty('av-r3-reapply-dst-')
  try {
    const stored = v.vault.setQuarantine('demo', { by: 'tripwire', rule_id: 'many-404s', reason: 'probing /admin' })
    const { bundle } = await exportBackup(v.vault, { recoveryPassphrase: RECOVERY })
    const seq = t.vault.audit.seq
    assert.deepEqual((await restore(t, bundle)).restored, ['demo', 'other'])
    assert.deepEqual(quarantineOf(t, 'demo'), stored)
    assert.deepEqual(reveal(t, 'demo'), QUARANTINED)
    assert.deepEqual(code(() => {
      const { session } = t.vault.createSession({ label: 'after restore' })
      t.vault.createGrant({ sessionId: session.id, credentialId: t.vault.findCredential('demo').id, fields: ['token'], policy: POLICY })
    }), QUARANTINED)
    // On disk too, not just in memory.
    const disk = JSON.parse(readFileSync(join(t.dir, 'vault.json'), 'utf8'))
    assert.deepEqual(Object.values(disk.credentials).find((c) => c.slug === 'demo').quarantine, stored)
    // Recorded, so the log alone says the restored credential is stopped.
    const recs = records(t, 'cred.quarantined').filter((r) => r.seq > seq)
    assert.deepEqual(recs.map((r) => [r.credential_slug, r.by, r.rule_id, r.reason_untrusted, r.since, r.restored]),
      [['demo', 'tripwire', 'many-404s', 'probing /admin', stored.since, true]])
    // The other credential is not touched by it.
    assert.equal(quarantineOf(t, 'other'), null)
    assert.equal(t.vault.revealField(t.vault.findCredential('other').id, 'token'), OTHER_SECRET)
    // Releasing is the human's act, and the value came back whole.
    assert.equal(t.vault.clearQuarantine('demo'), true)
    assert.equal(t.vault.revealField(t.vault.findCredential('demo').id, 'token'), SECRET)
  } finally { v.done(); t.done() }
})

// ------------------------------------------------------------------ (c)

test('(c) a credential quarantined in this vault keeps its restored copy quarantined, whatever the bundle says', async () => {
  const v = fresh('av-r3-held-')
  try {
    // Backed up before anything was quarantined: the bundle says released.
    const { bundle: clean } = await exportBackup(v.vault, { recoveryPassphrase: RECOVERY })
    const live = v.vault.setQuarantine('demo', { by: 'control', reason: 'leaked in a log' })

    // The same slug, renamed on restore.
    const once = await restore(v, clean, 'rename')
    assert.deepEqual(once.renamed.map((r) => r.to), ['demo-restored', 'other-restored'])
    assert.deepEqual(quarantineOf(v, 'demo-restored'), live)
    assert.deepEqual(reveal(v, 'demo-restored'), QUARANTINED)
    assert.equal(quarantineOf(v, 'other-restored'), null, 'a quarantine spread to a credential it was not on')

    // A renamed copy is held too: with the original released, its quarantined copy still holds the next one.
    v.vault.clearQuarantine('demo')
    await restore(v, clean, 'rename')
    assert.deepEqual(quarantineOf(v, 'demo-restored-2'), live)
    // And with the original gone, the bundle's slug is free and restores as itself: still quarantined.
    v.vault.deleteCredential('demo')
    const back = await restore(v, clean, 'rename')
    assert.ok(back.restored.includes('demo'))
    assert.deepEqual(quarantineOf(v, 'demo'), live)
    assert.deepEqual(reveal(v, 'demo'), QUARANTINED)

    // A bundle that is itself quarantined keeps its own record.
    const t = fresh('av-r3-held-both-')
    try {
      const own = t.vault.setQuarantine('demo', { by: 'tripwire', rule_id: 'burst' })
      const { bundle } = await exportBackup(t.vault, { recoveryPassphrase: RECOVERY })
      await restore(t, bundle, 'rename')
      assert.deepEqual(quarantineOf(t, 'demo-restored'), own)
    } finally { t.done() }
  } finally { v.done() }
})

test('(c) only the same credential holds a restore: an unrelated quarantine or a look-alike slug does not', async () => {
  const v = fresh('av-r3-held-ctl-')
  try {
    const { bundle } = await exportBackup(v.vault, { recoveryPassphrase: RECOVERY })
    v.vault.setQuarantine('other', { by: 'control' })
    v.vault.addCredential({ slug: 'demo-x', kind: 'http', connector: { host: 'api.example.com', scheme: 'https' }, fields: { token: 'tok_DEMOXLOOKALIKE00112233445566' } })
    v.vault.setQuarantine('demo-x', { by: 'control' })
    await restore(v, bundle, 'rename')
    assert.equal(quarantineOf(v, 'demo-restored'), null)
    assert.equal(v.vault.revealField(v.vault.findCredential('demo-restored').id, 'token'), SECRET)
    assert.deepEqual(quarantineOf(v, 'other-restored'), quarantineOf(v, 'other'))
  } finally { v.done() }
})

// ------------------------------------------------------------------ (d)

test('(d) a bundle with no quarantine field restores as not quarantined, and (c) still holds', async () => {
  const v = fresh('av-r3-old-')
  try {
    const old = await sealedBundle({ credentials: [oldEntry('demo', 'ghp_OLDBUNDLEDEMO0011223344556677889900'), oldEntry('third', 'ghp_OLDBUNDLETHIRD011223344556677889900')], templates: [] })
    v.vault.setQuarantine('demo', { by: 'control', reason: 'rotating' })
    const out = await restore(v, old, 'rename')
    assert.deepEqual([out.restored, out.renamed], [['demo-restored', 'third'], [{ from: 'demo', to: 'demo-restored' }]])
    assert.equal(quarantineOf(v, 'third'), null)
    assert.equal(v.vault.revealField(v.vault.findCredential('third').id, 'token'), 'ghp_OLDBUNDLETHIRD011223344556677889900')
    assert.deepEqual(quarantineOf(v, 'demo-restored'), quarantineOf(v, 'demo'))
    assert.deepEqual(reveal(v, 'demo-restored'), QUARANTINED)
  } finally { v.done() }
})

// ------------------------------------------------------------- controls

test('an ordinary restore of credentials never quarantined stores no quarantine and records none', async () => {
  const v = fresh('av-r3-plain-src-')
  const t = empty('av-r3-plain-dst-')
  try {
    const { bundle } = await exportBackup(v.vault, { recoveryPassphrase: RECOVERY })
    const seq = t.vault.audit.seq
    assert.deepEqual((await restore(t, bundle)).restored, ['demo', 'other'])
    for (const slug of ['demo', 'other']) assert.equal(quarantineOf(t, slug), null)
    assert.deepEqual(records(t, 'cred.quarantined').filter((r) => r.seq > seq), [])
    const { session } = t.vault.createSession({ label: 'restored' })
    const grant = t.vault.createGrant({ sessionId: session.id, credentialId: t.vault.findCredential('demo').id, fields: ['token'], policy: POLICY })
    const { row } = t.vault.issuePlaceholder({ grantId: grant.id })
    assert.equal(t.vault.consumePlaceholder(row.id).uses, 1)
    assert.equal(t.vault.revealField(t.vault.findCredential('demo').id, 'token'), SECRET)
  } finally { v.done(); t.done() }
})

test('a quarantine record that cannot be read refuses the whole restore rather than being dropped', async () => {
  const v = fresh('av-r3-malformed-')
  try {
    const since = new Date().toISOString()
    const bad = [
      'yes', [], {}, { since, by: 'agent' }, { since: 'not a date', by: 'control' },
      { since, by: 'control', rule_id: 'NOT A RULE' }, { since, by: 'control', reason_untrusted: 'x'.repeat(201) },
      { since, by: 'control', released: true },
    ]
    for (const quarantine of bad) {
      const before = { mem: JSON.stringify(v.vault.db), disk: readFileSync(join(v.dir, 'vault.json')), seq: v.vault.audit.seq }
      const bundle = await sealedBundle({ credentials: [{ ...oldEntry('third', 'ghp_MALFORMEDQ00112233445566778899aa'), quarantine }], templates: [] })
      assert.deepEqual(await codeAsync(() => restore(v, bundle)), { code: 'AV_POLICY_DENIED', rule: 'backup_format' }, JSON.stringify(quarantine))
      assert.equal(JSON.stringify(v.vault.db), before.mem)
      assert.ok(readFileSync(join(v.dir, 'vault.json')).equals(before.disk))
      assert.deepEqual(v.vault.audit.read({ limit: 100000 }).filter((r) => r.seq > before.seq).map((r) => [r.kind, r.reason]), [['backup.refused', 'backup_format']])
    }
    // The same entry with a readable record, or none, restores.
    const ok = await sealedBundle({ credentials: [{ ...oldEntry('third', 'ghp_MALFORMEDQ00112233445566778899aa'), quarantine: { since, by: 'control', rule_id: null, reason_untrusted: null } }], templates: [] })
    assert.deepEqual((await restore(v, ok)).restored, ['third'])
    assert.equal(quarantineOf(v, 'third').by, 'control')
  } finally { v.done() }
})
