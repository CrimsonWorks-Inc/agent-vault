// What the daemon answers while the vault is locked.
//
// A locked vault is a normal, expected state — it is where a machine comes up
// after a restart when the only unlock factors are a passphrase or Touch ID.
// Every read the human reaches for at that moment must say "locked", not fall
// over, because an internal error here reads like a broken vault at exactly
// the moment someone is worried about their credentials.

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { request as unixRequest } from 'node:http'
import { Vault } from '../../src/store/vault.js'
import { Daemon } from '../../src/daemon/server.js'

let dir, vault, daemon, sock

const control = (method, path, body) => new Promise((resolve, reject) => {
  const req = unixRequest({ socketPath: sock, path, method, headers: { 'content-type': 'application/json' } }, (res) => {
    const chunks = []
    res.on('data', (c) => chunks.push(c))
    res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(chunks).toString() || '{}') }))
  })
  req.on('error', reject)
  req.end(body ? JSON.stringify(body) : undefined)
})

before(async () => {
  dir = mkdtempSync(join(tmpdir(), 'av-locked-'))
  vault = Vault.create(dir, { factor: 'none' })
  vault.addCredential({
    slug: 'demo', kind: 'http', connector: { host: 'api.example.com', scheme: 'https' },
    fields: { token: 'ghp_LOCKEDTEST00112233445566778899aa' }, sites: { token: ['header:authorization:Bearer'] },
  })
  sock = join(dir, 'c.sock')
  daemon = await new Daemon(vault, { port: 0, socketPath: sock }).start()
  vault.lock()
})

after(async () => {
  if (daemon) await daemon.stop()
  rmSync(dir, { recursive: true, force: true })
})

test('reading the audit log says the vault is locked, not that something broke', async () => {
  // The log is keyed from the vault master key, so the handle is genuinely
  // gone. Dereferencing it produced "Cannot read properties of null".
  const res = await control('GET', '/v1/audit?limit=10')
  assert.equal(res.status, 423)
  assert.equal(res.body.code, 'AV_LOCKED')
  assert.match(res.body.detail, /unlock/i, 'the answer should say what to do about it')
  assert.notEqual(res.body.code, 'AV_INTERNAL')
})

test('verifying the audit chain says the same', async () => {
  const res = await control('GET', '/v1/audit/verify')
  assert.equal(res.status, 423)
  assert.equal(res.body.code, 'AV_LOCKED')
})

test('a locked vault says its record count is unknown, not zero', async () => {
  // Reporting 0 reads as "your audit trail was wiped", which is precisely the
  // wrong thing to tell someone who has just found their vault locked. The
  // count is unknowable while locked, and null says so.
  const { body } = await control('GET', '/v1/status')
  assert.equal(body.locked, true)
  assert.equal(body.audit_records, null)
  assert.notEqual(body.audit_records, 0)
  // The counts that do not need the audit key are still real.
  assert.equal(body.credentials, 1)
})

test('the reads the unlock screen depends on still work', async () => {
  // status and lockstate drive the page that offers to unlock. If they fail
  // while locked, there is no way back in through the UI.
  for (const path of ['/v1/status', '/v1/lockstate']) {
    const res = await control('GET', path)
    assert.equal(res.status, 200, `${path} answered ${res.status}`)
  }
  const { body: state } = await control('GET', '/v1/lockstate')
  assert.equal(state.locked, true)
})

test('unlocking restores the audit log', async () => {
  vault.unlockWith({})
  const res = await control('GET', '/v1/audit?limit=10')
  assert.equal(res.status, 200)
  assert.ok(Array.isArray(res.body))
  assert.ok(res.body.some((r) => r.kind === 'vault.lock'), 'the lock itself should be in the log')
})
