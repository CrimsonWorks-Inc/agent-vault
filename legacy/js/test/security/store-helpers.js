// Shared fixtures for the store-*.test.js files: a throwaway vault with two
// credentials, a clock override, and the check that a refusal changed nothing
// in memory, on disk or in the audit log.

import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, readFileSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Vault } from '../../src/store/vault.js'

export const SECRET = 'ghp_STOREHELPER00112233445566778899aabb'
export const OTHER_SECRET = 'tok_OTHERHELPER00112233445566778899'
export const HOUR = 3_600_000
export const DAY = 24 * HOUR
export const POLICY = { hosts: ['api.example.com'], methods: ['GET'], paths: ['/**'], budget: { unit: 'requests', limit: 100 }, approval: 'on-write' }

export function fresh(prefix = 'av-store-', { factor = 'none', passphrase = null } = {}) {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  const vault = Vault.create(dir, { factor, passphrase })
  const cred = vault.addCredential({
    slug: 'demo', kind: 'http', connector: { host: 'api.example.com', scheme: 'https' },
    fields: { token: SECRET }, sites: { token: ['header:authorization:Bearer'] },
  })
  const other = vault.addCredential({
    slug: 'other', kind: 'http', connector: { host: 'api.other.example', scheme: 'https' },
    fields: { token: OTHER_SECRET }, sites: { token: ['header:authorization:Bearer'] },
  })
  return { dir, vault, cred, other, done: () => rmSync(dir, { recursive: true, force: true }) }
}

/** Run `fn` with the clock at `ms`. Every expiry check reads Date.now. */
export function at(ms, fn) {
  const real = Date.now
  Date.now = () => ms
  try { return fn() } finally { Date.now = real }
}

export function code(fn) {
  try { fn() } catch (e) { return { code: e.code, rule: e.rule } }
  return { code: 'none' }
}

export async function codeAsync(fn) {
  try { await fn() } catch (e) { return { code: e.code, rule: e.rule } }
  return { code: 'none' }
}

export const records = (v, kind) => v.vault.audit.read({ limit: 100000, kind }).filter((r) => r.kind === kind)
export const onDisk = (v) => JSON.parse(readFileSync(join(v.dir, 'vault.json'), 'utf8'))
export const auditText = (v) => (existsSync(join(v.dir, 'audit.jsonl')) ? readFileSync(join(v.dir, 'audit.jsonl'), 'utf8') : '')

function snapshot(v) {
  return { mem: JSON.stringify(v.vault.db), disk: JSON.stringify(onDisk(v)), seq: v.vault.audit?.seq ?? null }
}

function same(v, before) {
  const after = snapshot(v)
  assert.equal(after.mem, before.mem, 'a refusal changed the vault in memory')
  assert.equal(after.disk, before.disk, 'a refusal changed the vault on disk')
  assert.equal(after.seq, before.seq, 'a refusal wrote to the audit log')
}

/** Asserts `fn` is refused with `expected`, and changed nothing anywhere. */
export function refusedCleanly(v, fn, expected) {
  const before = snapshot(v)
  assert.deepEqual(code(fn), expected)
  same(v, before)
}

export async function refusedCleanlyAsync(v, fn, expected, { audited = 0 } = {}) {
  const before = snapshot(v)
  assert.deepEqual(await codeAsync(fn), expected)
  if (audited) {
    // The refusal itself is recorded, and nothing else changed.
    const after = snapshot(v)
    assert.equal(after.mem, before.mem, 'a refusal changed the vault in memory')
    assert.equal(after.disk, before.disk, 'a refusal changed the vault on disk')
    assert.equal(after.seq, before.seq + audited, 'a refusal wrote more than its own record')
  } else {
    same(v, before)
  }
}
