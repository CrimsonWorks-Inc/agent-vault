// Breaking glass.
//
// Every other control in this system decides what an agent may do next. These
// are the ones you reach for when it is already doing something you want
// stopped, which makes them the controls that must not fail quietly. A gate
// that silently stops gating is bad; a revocation that silently does not
// revoke is worse, because you walk away believing it worked.
//
// Each test does the same shape: prove the capability works, revoke it one
// way, prove it stopped, and prove the upstream saw nothing after the cut.

import { test, before, after, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { request as unixRequest, createServer } from 'node:http'
import { Vault } from '../../src/store/vault.js'
import { Daemon } from '../../src/daemon/server.js'

const SECRET = 'ghp_REVOKE00112233445566778899aabb'
let dir, vault, daemon, upstream, upPort, seen

const gw = (path, headers) => new Promise((resolve) => {
  const req = unixRequest({ host: '127.0.0.1', port: daemon.gatewayPort, path, headers }, (res) => {
    const c = []
    res.on('data', (x) => c.push(x))
    res.on('end', () => resolve({ status: res.statusCode, text: Buffer.concat(c).toString() }))
  })
  req.on('error', (e) => resolve({ status: 0, text: e.message }))
  req.end()
})

const codeOf = (r) => { try { return JSON.parse(r.text).code } catch { return null } }

/** A fresh credential, session, grant and placeholder. */
function freshCapability(label) {
  const cred = vault.addCredential({
    slug: label, kind: 'http', connector: { host: `127.0.0.1:${upPort}`, scheme: 'http' },
    fields: { token: SECRET }, sites: { token: ['header:authorization:Bearer'] },
  })
  const made = vault.createSession({ label })
  const grant = vault.createGrant({
    sessionId: made.session.id, credentialId: cred.id, fields: ['token'],
    policy: {
      hosts: ['127.0.0.1'], methods: ['GET'], paths: ['/**'],
      budget: { unit: 'requests', limit: 50 }, approval: 'auto',
    },
  })
  const placeholder = vault.issuePlaceholder({ grantId: grant.id, field: 'token' }).placeholder
  return { cred, session: made.session, token: made.token, grant, placeholder }
}

before(async () => {
  dir = mkdtempSync(join(tmpdir(), 'av-revoke-'))
  seen = []
  upstream = createServer((req, res) => { seen.push(req.url); res.end('{}') })
  await new Promise((r) => upstream.listen(0, '127.0.0.1', r))
  upPort = upstream.address().port
  vault = Vault.create(dir, { factor: 'none' })
  daemon = await new Daemon(vault, { port: 0, socketPath: join(dir, 'c.sock') }).start()
})

after(async () => {
  if (daemon) await daemon.stop()
  if (upstream) upstream.close()
  rmSync(dir, { recursive: true, force: true })
})

beforeEach(() => { seen = [] })

test('revoking a session kills every placeholder it ever issued', async () => {
  const a = freshCapability('rev-session')
  // Two placeholders from the same session, to be sure it is not just the one
  // we happen to hold that stops.
  const second = vault.issuePlaceholder({
    grantId: a.grant.id, field: 'token',
  }).placeholder

  assert.equal((await gw(`/p/${a.cred.slug}/x`, { authorization: `Bearer ${a.placeholder}` })).status, 200)
  assert.equal((await gw(`/p/${a.cred.slug}/x`, { authorization: `Bearer ${second}` })).status, 200)
  seen = []

  vault.revokeSession(a.session.id, 'test')

  for (const p of [a.placeholder, second]) {
    const res = await gw(`/p/${a.cred.slug}/x`, { authorization: `Bearer ${p}` })
    assert.notEqual(res.status, 200, 'a placeholder outlived its session')
    assert.match(String(codeOf(res)), /AV_SESSION_REVOKED|AV_SESSION_REQUIRED|AV_PH_/)
  }
  // The session token itself is dead too.
  const viaToken = await gw(`/p/${a.cred.slug}/x`, { authorization: `Bearer ${a.token}` })
  assert.notEqual(viaToken.status, 200)
  assert.deepEqual(seen, [], 'nothing may reach the upstream after a revoke')
})

test('revoking one grant does not disturb another session', async () => {
  // Revocation has to be precise, or nobody will use it in anger.
  const a = freshCapability('rev-grant-a')
  const b = freshCapability('rev-grant-b')
  assert.equal((await gw(`/p/${a.cred.slug}/x`, { authorization: `Bearer ${a.placeholder}` })).status, 200)
  assert.equal((await gw(`/p/${b.cred.slug}/x`, { authorization: `Bearer ${b.placeholder}` })).status, 200)

  vault.revokeGrant(a.grant.id, 'test')

  assert.notEqual((await gw(`/p/${a.cred.slug}/x`, { authorization: `Bearer ${a.placeholder}` })).status, 200)
  assert.equal((await gw(`/p/${b.cred.slug}/x`, { authorization: `Bearer ${b.placeholder}` })).status, 200,
    'the other session must be untouched')
})

test('deleting a credential stops every grant that used it', async () => {
  const a = freshCapability('rev-cred')
  assert.equal((await gw(`/p/${a.cred.slug}/x`, { authorization: `Bearer ${a.placeholder}` })).status, 200)
  seen = []

  vault.deleteCredential(a.cred.slug)

  const res = await gw(`/p/${a.cred.slug}/x`, { authorization: `Bearer ${a.placeholder}` })
  assert.notEqual(res.status, 200, 'a deleted credential was still usable')
  assert.deepEqual(seen, [])
})

test('locking the vault refuses everything, and unlocking restores it', async () => {
  // The big red button. It has to work while requests are in flight, and it
  // has to be reversible without re-issuing anything.
  const a = freshCapability('rev-lock')
  assert.equal((await gw(`/p/${a.cred.slug}/x`, { authorization: `Bearer ${a.placeholder}` })).status, 200)
  seen = []

  vault.lock()
  const locked = await gw(`/p/${a.cred.slug}/x`, { authorization: `Bearer ${a.placeholder}` })
  assert.notEqual(locked.status, 200, 'a locked vault served a credential')
  assert.deepEqual(seen, [], 'nothing may reach the upstream while locked')

  vault.unlockWith({})
  assert.equal((await gw(`/p/${a.cred.slug}/x`, { authorization: `Bearer ${a.placeholder}` })).status, 200,
    'unlocking should restore the same capability, not require a new one')
})

test('an expired session is refused even with a live placeholder', async () => {
  const a = freshCapability('rev-expiry')
  assert.equal((await gw(`/p/${a.cred.slug}/x`, { authorization: `Bearer ${a.placeholder}` })).status, 200)
  seen = []

  // Wind the clock forward the only way a test can.
  vault.db.sessions[a.session.id].expires_at = new Date(Date.now() - 1000).toISOString()

  const res = await gw(`/p/${a.cred.slug}/x`, { authorization: `Bearer ${a.placeholder}` })
  assert.notEqual(res.status, 200, 'an expired session still worked')
  assert.deepEqual(seen, [])
})

test('a revoked placeholder coming back is treated as hostile, not as a mistake', async () => {
  // Reuse of a dead placeholder is the signal that something is replaying, so
  // it has to be distinguishable in the log from an honest stale one.
  const a = freshCapability('rev-replay')
  const oneShot = vault.issuePlaceholder({ grantId: a.grant.id, field: 'token', uses: 1 }).placeholder

  assert.equal((await gw(`/p/${a.cred.slug}/x`, { authorization: `Bearer ${oneShot}` })).status, 200)
  seen = []
  const again = await gw(`/p/${a.cred.slug}/x`, { authorization: `Bearer ${oneShot}` })
  assert.notEqual(again.status, 200, 'a one-use placeholder worked twice')
  assert.match(String(codeOf(again)), /AV_PH_/)
  assert.deepEqual(seen, [], 'the second use must not reach the upstream')

  const kinds = vault.audit.read({ limit: 60 }).map((r) => r.kind)
  assert.ok(kinds.some((k) => /placeholder\.(exhausted|replay|stale)/.test(k)),
    `the reuse should be recorded distinctly: ${[...new Set(kinds)].join(', ')}`)
})
