// F8, store side: encrypted backup and controlled restore. The bundle holds
// every secret under a recovery passphrase, so it must never carry one in the
// clear, never be logged except by digest, never give back a session, and
// never be partly applied.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Vault } from '../../src/store/vault.js'
import * as crypt from '../../src/store/crypto.js'
import { exportBackup, inspectBackup, restoreBackup, bundleDigest, BACKUP_FORMAT, BACKUP_VERSION, BACKUP_KDF } from '../../src/store/backup.js'
import { fresh, codeAsync, records, auditText, refusedCleanlyAsync, SECRET, OTHER_SECRET, POLICY } from './store-helpers.js'

const RECOVERY = 'correct horse battery staple'
const KDF = { ...BACKUP_KDF, keylen: 32, maxmem: 256 * 1024 * 1024 }
const aad = (b) => `${b.format}|${b.version}|${b.created_at}`

async function plaintextOf(bundle, pass = RECOVERY) {
  const key = await crypt.scryptAsync(pass, Buffer.from(bundle.kdf.salt, 'base64'), KDF)
  return JSON.parse(crypt.open(key, { ct: bundle.ct, nonce: bundle.nonce }, aad(bundle)))
}

/** A correctly encrypted bundle around any plaintext: what a hand-made bundle looks like. */
async function sealedBundle(plain, pass = RECOVERY) {
  const salt = crypt.randomKey().subarray(0, 16)
  const head = { format: BACKUP_FORMAT, version: BACKUP_VERSION, created_at: new Date().toISOString() }
  const key = await crypt.scryptAsync(pass, salt, KDF)
  const sealed = crypt.seal(key, JSON.stringify(plain), aad(head))
  return { ...head, kdf: { ...BACKUP_KDF, salt: salt.toString('base64') }, cipher: 'chacha20-poly1305', nonce: sealed.nonce, ct: sealed.ct }
}

function target(prefix = 'av-store-restore-') {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  const vault = Vault.create(dir, { factor: 'none' })
  return { dir, vault, done: () => rmSync(dir, { recursive: true, force: true }) }
}

function populated() {
  const v = fresh('av-store-backup-')
  v.vault.addScrubPattern('demo', 'acme_[A-Za-z0-9]{20,40}')
  v.vault.setCredentialExpiry('demo', '2031-01-01')
  v.vault.saveTemplate('gh-read', { cred: 'demo', methods: ['GET'], spend_usd: 0.5 })
  const { session, token } = v.vault.createSession({ label: 'live' })
  const grant = v.vault.createGrant({ sessionId: session.id, credentialId: v.cred.id, fields: ['token'], policy: POLICY })
  v.vault.issuePlaceholder({ grantId: grant.id })
  return { ...v, token }
}

test('an export seals everything, holds no secret in the clear, and is logged by digest only', async () => {
  const v = populated()
  try {
    const { bundle, summary, bundle_sha256 } = await exportBackup(v.vault, { recoveryPassphrase: RECOVERY })
    assert.deepEqual(Object.keys(bundle).sort(), ['cipher', 'created_at', 'ct', 'format', 'kdf', 'nonce', 'version'])
    assert.deepEqual(bundle.kdf, { name: 'scrypt', N: 131072, r: 8, p: 1, salt: bundle.kdf.salt })
    assert.equal(Buffer.from(bundle.kdf.salt, 'base64').length, 16)
    assert.equal(bundle.cipher, 'chacha20-poly1305')
    assert.deepEqual([summary.credentials, summary.templates, summary.created_at], [2, 1, bundle.created_at])
    assert.equal(bundle_sha256, bundleDigest(bundle))

    const text = JSON.stringify(bundle)
    for (const s of [SECRET, OTHER_SECRET]) {
      for (const enc of [s, Buffer.from(s).toString('base64'), Buffer.from(s).toString('hex'), Buffer.from(s).toString('base64url')]) {
        assert.ok(!text.includes(enc), 'a secret reached the bundle unsealed')
      }
    }
    const [rec] = records(v, 'backup.exported')
    assert.deepEqual([rec.credentials, rec.templates, rec.bundle_sha256], [2, 1, bundle_sha256])
    assert.ok(!auditText(v).includes(bundle.ct.slice(0, 32)), 'the bundle reached the audit log')
  } finally { v.done() }
})

test('the plaintext is credentials and templates only: no session, grant, placeholder, factor or retired value', async () => {
  const v = populated()
  try {
    v.vault.rotateCredential('demo', { value: 'ghp_ROTATEDBACKUP00112233445566778899aa' })
    const { bundle } = await exportBackup(v.vault, { recoveryPassphrase: RECOVERY })
    const plain = await plaintextOf(bundle)
    assert.deepEqual(Object.keys(plain).sort(), ['credentials', 'templates'])
    const demo = plain.credentials.find((c) => c.slug === 'demo')
    // quarantine travels with the credential, so a restore cannot release it (round 3).
    assert.deepEqual(Object.keys(demo).sort(), ['connector', 'created_at', 'expires_at', 'fields', 'kind', 'pins', 'quarantine', 'scrub_patterns', 'slug'])
    assert.deepEqual(demo.fields.map((f) => f.value), ['ghp_ROTATEDBACKUP00112233445566778899aa'])
    assert.ok(!JSON.stringify(plain).includes(SECRET), 'a retired value was exported')
    assert.deepEqual(plain.templates, [{ name: 'gh-read', spec: { cred: 'demo', methods: ['GET'], spend_usd: 0.5 } }])
  } finally { v.done() }
})

test('inspect lists what a bundle holds without a single value', async () => {
  const v = populated()
  try {
    const { bundle } = await exportBackup(v.vault, { recoveryPassphrase: RECOVERY })
    const seq = v.vault.audit.seq
    const out = await inspectBackup(bundle, { recoveryPassphrase: RECOVERY })
    assert.equal(out.created_at, bundle.created_at)
    assert.deepEqual(out.credentials.find((c) => c.slug === 'demo'), {
      slug: 'demo', kind: 'http', host: 'api.example.com', fields: ['token'],
      has_scrub_patterns: true, has_pins: false, expires_at: '2031-01-01T00:00:00.000Z', quarantined: false,
    })
    assert.deepEqual(out.templates, ['gh-read'])
    assert.ok(!JSON.stringify(out).includes(SECRET))
    assert.equal(v.vault.audit.seq, seq, 'inspect touches no vault')
  } finally { v.done() }
})

test('a restore brings back credentials, patterns, expiry and templates, and no session', async () => {
  const v = populated()
  const t = target()
  try {
    const { bundle } = await exportBackup(v.vault, { recoveryPassphrase: RECOVERY })
    const wraps = t.vault.db.kv.vmk_wraps
    const out = await restoreBackup(t.vault, bundle, { recoveryPassphrase: RECOVERY })
    assert.deepEqual(out, { restored: ['demo', 'other'], skipped: [], renamed: [], templates: { restored: ['gh-read'], skipped: [] } })
    const demo = t.vault.findCredential('demo')
    assert.equal(t.vault.revealField(demo.id, 'token'), SECRET)
    assert.equal(t.vault.revealField(t.vault.findCredential('other').id, 'token'), OTHER_SECRET)
    assert.deepEqual(demo.fields[0].sites, ['header:authorization:Bearer'])
    assert.deepEqual(demo.scrub_patterns.map((p) => p.source), ['acme_[A-Za-z0-9]{20,40}'])
    assert.equal(demo.expires_at, '2031-01-01T00:00:00.000Z')
    assert.equal(t.vault.getTemplate('gh-read').hash, v.vault.getTemplate('gh-read').hash)

    for (const k of ['sessions', 'grants', 'placeholders']) assert.deepEqual(t.vault.db[k], {}, `${k} came back`)
    assert.equal(t.vault.sessionByToken(v.token), null, 'an old session token works against the restored vault')
    assert.equal(t.vault.db.kv.vmk_wraps, wraps, 'a restore touched the factors')
    const [rec] = records(t, 'backup.restored')
    assert.deepEqual([rec.restored, rec.skipped, rec.renamed, rec.bundle_sha256], [['demo', 'other'], [], [], bundleDigest(bundle)])
    assert.ok(!auditText(t).includes(SECRET))
  } finally { v.done(); t.done() }
})

test('conflicts: skip by default, rename to -restored and -restored-2 within 24 characters, and fail writes nothing', async () => {
  const v = populated()
  try {
    v.vault.addCredential({ slug: 'a-very-long-slug-of-24ch', kind: 'http', connector: { host: 'long.example' }, fields: { token: 'tok_LONGSLUG0011223344556677' } })
    const { bundle } = await exportBackup(v.vault, { recoveryPassphrase: RECOVERY })
    const skip = await restoreBackup(v.vault, bundle, { recoveryPassphrase: RECOVERY })
    assert.deepEqual(skip.restored, [])
    assert.deepEqual(skip.skipped, ['demo', 'other', 'a-very-long-slug-of-24ch'])
    assert.deepEqual(skip.templates.skipped, ['gh-read'])

    const once = await restoreBackup(v.vault, bundle, { recoveryPassphrase: RECOVERY, onConflict: 'rename' })
    assert.deepEqual(once.renamed, [
      { from: 'demo', to: 'demo-restored' }, { from: 'other', to: 'other-restored' },
      { from: 'a-very-long-slug-of-24ch', to: 'a-very-long-slu-restored' },
    ])
    const twice = await restoreBackup(v.vault, bundle, { recoveryPassphrase: RECOVERY, onConflict: 'rename' })
    assert.equal(twice.renamed[0].to, 'demo-restored-2')
    assert.equal(v.vault.revealField(v.vault.findCredential('demo-restored-2').id, 'token'), SECRET)

    await refusedCleanlyAsync(v, () => restoreBackup(v.vault, bundle, { recoveryPassphrase: RECOVERY, onConflict: 'fail' }),
      { code: 'AV_POLICY_DENIED', rule: 'backup_conflict' }, { audited: 1 })
    assert.equal(records(v, 'backup.refused').at(-1).reason, 'backup_conflict')
    await refusedCleanlyAsync(v, () => restoreBackup(v.vault, bundle, { recoveryPassphrase: RECOVERY, onConflict: 'merge' }),
      { code: 'AV_POLICY_DENIED', rule: 'backup_conflict' })
  } finally { v.done() }
})

test('a wrong passphrase or an altered bundle is one answer, and a restore writes nothing but the refusal', async () => {
  const v = populated()
  const t = target()
  try {
    const { bundle } = await exportBackup(v.vault, { recoveryPassphrase: RECOVERY })
    const flip = (s) => { const b = Buffer.from(s, 'base64'); b[3] ^= 1; return b.toString('base64') }
    for (const [label, b, pass] of [
      ['wrong passphrase', bundle, 'not the right passphrase'],
      ['altered ciphertext', { ...bundle, ct: flip(bundle.ct) }, RECOVERY],
      ['altered created_at (the AAD)', { ...bundle, created_at: new Date(0).toISOString() }, RECOVERY],
      ['altered salt', { ...bundle, kdf: { ...bundle.kdf, salt: flip(bundle.kdf.salt) } }, RECOVERY],
    ]) {
      assert.deepEqual(await codeAsync(() => inspectBackup(b, { recoveryPassphrase: pass })), { code: 'AV_PRESENCE_DENIED', rule: 'backup_auth' }, label)
      await refusedCleanlyAsync(t, () => restoreBackup(t.vault, b, { recoveryPassphrase: pass }), { code: 'AV_PRESENCE_DENIED', rule: 'backup_auth' }, { audited: 1 })
    }
    assert.deepEqual(records(t, 'backup.refused').map((r) => r.reason), ['backup_auth', 'backup_auth', 'backup_auth', 'backup_auth'])
  } finally { v.done(); t.done() }
})

test('an envelope that is not this format is refused before any key is derived', async () => {
  const v = populated()
  const t = target()
  try {
    const { bundle } = await exportBackup(v.vault, { recoveryPassphrase: RECOVERY })
    for (const b of [
      null, [], 'bundle', { ...bundle, format: 'other' }, { ...bundle, version: 2 },
      { ...bundle, kdf: { ...bundle.kdf, N: 1 << 20 } }, { ...bundle, kdf: { ...bundle.kdf, p: 64 } }, { ...bundle, kdf: { ...bundle.kdf, name: 'pbkdf2' } },
      { ...bundle, kdf: { ...bundle.kdf, salt: 'c2hvcnQ=' } }, { ...bundle, cipher: 'aes-256-gcm' }, { ...bundle, nonce: 'AAAA' },
      { ...bundle, ct: 'x'.repeat(16 * 1024 * 1024 + 1) },
    ]) {
      const started = Date.now()
      assert.deepEqual(await codeAsync(() => inspectBackup(b, { recoveryPassphrase: RECOVERY })), { code: 'AV_POLICY_DENIED', rule: 'backup_format' })
      assert.ok(Date.now() - started < 1000, 'a malformed envelope cost a key derivation')
      await refusedCleanlyAsync(t, () => restoreBackup(t.vault, b, { recoveryPassphrase: RECOVERY }), { code: 'AV_POLICY_DENIED', rule: 'backup_format' }, { audited: 1 })
    }
    for (const pass of ['short', '', undefined, 42]) {
      assert.deepEqual(await codeAsync(() => exportBackup(v.vault, { recoveryPassphrase: pass })), { code: 'AV_POLICY_DENIED', rule: 'recovery_passphrase' })
      assert.deepEqual(await codeAsync(() => inspectBackup(bundle, { recoveryPassphrase: pass })), { code: 'AV_POLICY_DENIED', rule: 'recovery_passphrase' })
    }
  } finally { v.done(); t.done() }
})

test('a correctly sealed bundle that carries anything outside the list is refused whole', async () => {
  const t = target()
  try {
    const cred = { slug: 'demo', kind: 'http', connector: { host: 'api.example.com' }, created_at: 'x', fields: [{ name: 'token', value: SECRET, sites: [] }], scrub_patterns: [], pins: {}, expires_at: null }
    const good = await sealedBundle({ credentials: [cred], templates: [] })
    for (const plain of [
      { credentials: [cred], templates: [], sessions: { s: { token_hash: 'x' } } },
      { credentials: [cred], templates: [], kv: { vmk_wraps: [{ class: 'none' }] } },
      { credentials: [{ ...cred, vmk_wraps: [] }], templates: [] },
      { credentials: [{ ...cred, fields: [{ name: 'token', value: SECRET, sites: [], retired: [] }] }], templates: [] },
      { credentials: [{ ...cred, slug: 'Not A Slug' }], templates: [] },
      { credentials: [{ ...cred, fields: [] }], templates: [] },
      { credentials: [{ ...cred, expires_at: 'garbage' }], templates: [] },
      { credentials: [cred], templates: [{ name: 'Bad Name', spec: {} }] },
      { credentials: [cred], templates: [{ name: 'ok', spec: { presence: { passphrase: 'x' } } }] },
      { credentials: [cred] },
    ]) {
      const b = await sealedBundle(plain)
      await refusedCleanlyAsync(t, () => restoreBackup(t.vault, b, { recoveryPassphrase: RECOVERY }), { code: 'AV_POLICY_DENIED', rule: 'backup_format' }, { audited: 1 })
    }
    // Pins are restored now that the vault stores them (F11); store-pins.test.js
    // covers that, and the pins a restore refuses.
    // The same bundle without the extra is restored.
    assert.deepEqual((await restoreBackup(t.vault, good, { recoveryPassphrase: RECOVERY })).restored, ['demo'])
  } finally { t.done() }
})

test('a scrub pattern in a bundle that would carry a secret into this vault is refused', async () => {
  const t = target()
  try {
    const cred = { slug: 'demo', kind: 'http', connector: { host: 'api.example.com' }, fields: [{ name: 'token', value: SECRET, sites: [] }], scrub_patterns: [{ source: `x${SECRET}` }] }
    const b = await sealedBundle({ credentials: [cred], templates: [] })
    // The rule addScrubPattern gives the same pattern: one set of rules, wherever it arrives.
    await refusedCleanlyAsync(t, () => restoreBackup(t.vault, b, { recoveryPassphrase: RECOVERY }), { code: 'AV_POLICY_DENIED', rule: 'scrub_pattern' }, { audited: 1 })
    assert.equal(records(t, 'backup.refused').at(-1).reason, 'scrub_pattern')
  } finally { t.done() }
})

test('a locked vault neither exports nor restores', async () => {
  const v = populated()
  try {
    const { bundle } = await exportBackup(v.vault, { recoveryPassphrase: RECOVERY })
    v.vault.lock()
    assert.equal((await codeAsync(() => exportBackup(v.vault, { recoveryPassphrase: RECOVERY }))).code, 'AV_LOCKED')
    assert.equal((await codeAsync(() => restoreBackup(v.vault, bundle, { recoveryPassphrase: RECOVERY }))).code, 'AV_LOCKED')
  } finally { v.done() }
})

test('a vault that locks while the key is derived hands nothing out', async () => {
  const v = populated()
  try {
    const pending = exportBackup(v.vault, { recoveryPassphrase: RECOVERY })
    v.vault.lock()
    assert.equal((await codeAsync(() => pending)).code, 'AV_LOCKED')
  } finally { v.done() }
})

test('the key derivation does not block the event loop', async () => {
  const v = populated()
  try {
    let ticks = 0
    let worst = 0
    let last = Date.now()
    const timer = setInterval(() => { const now = Date.now(); worst = Math.max(worst, now - last); last = now; ticks++ }, 5)
    const started = Date.now()
    await exportBackup(v.vault, { recoveryPassphrase: RECOVERY })
    clearInterval(timer)
    const took = Date.now() - started
    assert.ok(ticks >= 3, `the event loop ran ${ticks} times during a ${took} ms export`)
    assert.ok(worst < Math.max(100, took / 2), `the event loop stalled for ${worst} ms of a ${took} ms export`)
  } finally { v.done() }
})
